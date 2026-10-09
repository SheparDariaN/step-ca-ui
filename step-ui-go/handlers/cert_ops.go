package handlers

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	appdb "step-ui/db"
	"step-ui/models"
	"step-ui/security"
)

type IssuePolicy struct {
	Template string
	Duration string
	KeyType  string
	// Purpose передаётся в step-ca как template data переменная x509Purpose
	// и определяет extKeyUsage выпущенного сертификата.
	Purpose string
}

// Допустимые значения x509Purpose. Шаблон провизионера (см. provisioner.sh)
// разворачивает их в extKeyUsage: server -> serverAuth, client -> clientAuth,
// internal -> serverAuth + clientAuth.
const (
	purposeServer   = "server"
	purposeClient   = "client"
	purposeInternal = "internal"
)

var issueTemplates = map[string]IssuePolicy{
	"server":   {Template: "server", Duration: "8760h", KeyType: "EC:P-256", Purpose: purposeServer},
	"internal": {Template: "internal", Duration: "87600h", KeyType: "EC:P-256", Purpose: purposeInternal},
	"wildcard": {Template: "wildcard", Duration: "8760h", KeyType: "EC:P-256", Purpose: purposeServer},
	"client":   {Template: "client", Duration: "8760h", KeyType: "EC:P-256", Purpose: purposeClient},
}

var allowedIssueDurations = map[string]bool{
	"720h": true, "4380h": true, "8760h": true, "87600h": true,
}

var allowedIssueKeyTypes = map[string]bool{
	"EC:P-256": true, "EC:P-384": true, "RSA:2048": true, "RSA:4096": true,
}

func normalizeIssuePolicy(template, duration, keyType, domain string) (IssuePolicy, error) {
	template = strings.TrimSpace(strings.ToLower(template))
	if template == "" {
		template = "server"
	}
	policy, ok := issueTemplates[template]
	if !ok {
		return IssuePolicy{}, fmt.Errorf("unknown certificate template: %s", template)
	}
	if allowedIssueDurations[duration] {
		policy.Duration = duration
	}
	if allowedIssueKeyTypes[keyType] {
		policy.KeyType = keyType
	}
	if policy.Template == "wildcard" && !strings.HasPrefix(strings.TrimSpace(domain), "*.") {
		return IssuePolicy{}, fmt.Errorf("wildcard template requires domain like *.example.com")
	}
	return policy, nil
}

func decryptProvisionerPassword(encrypted, secretKey string) (string, error) {
	return security.DecryptSecret(encrypted, secretKey)
}

func durationExceedsMax(requested, maxDur string) bool {
	return appdb.DurationExceedsMax(requested, maxDur)
}

func (h *Handler) issueCert(domain, certPath, keyPath, duration, keyType, purpose, provisioner, passwordFile string) error {
	ca := h.CA()
	if !ca.Configured {
		return fmt.Errorf("Step-CA не настроен. Настройте подключение в разделе Админ -> Настройки CA (/admin/ca)")
	}
	if provisioner == "" {
		provisioner = ca.Provisioner
	}
	if passwordFile == "" {
		passwordFile = ca.PasswordFile
	}
	args := stepCertificateArgs(ca.URL, ca.RootCert, provisioner, passwordFile, duration, keyType, purpose, domain, certPath, keyPath)
	log.Printf("[step-cli] step %s", strings.Join(args, " "))
	cmd := exec.Command("step", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

func stepCertificateArgs(caURL, rootCert, provisioner, passwordFile, duration, keyType, purpose, domain, certPath, keyPath string) []string {
	args := []string{
		"ca", "certificate",
		"--ca-url", caURL,
		"--root", rootCert,
		"--provisioner", provisioner,
		"--provisioner-password-file", passwordFile,
		"--not-after", duration,
		"--force",
	}
	if purpose != "" {
		args = append(args, "--set", "x509Purpose="+purpose)
	}
	if strings.HasPrefix(keyType, "EC:") {
		args = append(args, "--kty", "EC", "--curve", strings.TrimPrefix(keyType, "EC:"))
	} else if strings.HasPrefix(keyType, "RSA:") {
		args = append(args, "--kty", "RSA", "--size", strings.TrimPrefix(keyType, "RSA:"))
	}
	return append(args, domain, certPath, keyPath)
}

func (h *Handler) issueWithRegisteredProvisioner(domain, certPath, keyPath, duration, keyType, purpose, provisionerName string) error {
	ca := h.CA()
	if provisionerName == "" {
		provisionerName = ca.Provisioner
	}
	prov, err := appdb.GetCAProvisioner(h.db, provisionerName)
	if err != nil {
		return err
	}
	if prov == nil {
		return fmt.Errorf("провизионер %s не зарегистрирован в UI", provisionerName)
	}
	if durationExceedsMax(duration, prov.MaxDuration) {
		return fmt.Errorf("срок %s превышает max провизионера %s (%s)", duration, prov.Name, prov.MaxDuration)
	}
	passwordFile, cleanup, err := h.provisionerPasswordFile(prov.Name)
	if err != nil {
		return err
	}
	defer cleanup()
	return h.issueCert(domain, certPath, keyPath, duration, keyType, purpose, prov.Name, passwordFile)
}

func (h *Handler) provisionerPasswordFile(provisionerName string) (string, func(), error) {
	cleanup := func() {}
	ca := h.CA()
	if provisionerName == "" {
		provisionerName = ca.Provisioner
	}
	prov, err := appdb.GetCAProvisioner(h.db, provisionerName)
	if err != nil {
		return "", cleanup, err
	}
	if prov == nil {
		return "", cleanup, fmt.Errorf("провизионер %s не зарегистрирован в UI", provisionerName)
	}
	if prov.EncryptedPassword != "" {
		plain, decErr := decryptProvisionerPassword(prov.EncryptedPassword, h.cfg.SecretKey)
		if decErr != nil {
			return "", cleanup, fmt.Errorf("не удалось расшифровать пароль провизионера")
		}
		tmp, writeErr := os.CreateTemp("/opt/step-ui/data", "prov-*.pw")
		if writeErr != nil {
			tmp, writeErr = os.CreateTemp("", "prov-*.pw")
		}
		if writeErr != nil {
			return "", cleanup, writeErr
		}
		path := tmp.Name()
		remove := func() { os.Remove(path) }
		if _, err := tmp.WriteString(plain); err != nil {
			tmp.Close()
			remove()
			return "", cleanup, err
		}
		if err := tmp.Chmod(0600); err != nil {
			tmp.Close()
			remove()
			return "", cleanup, err
		}
		if err := tmp.Close(); err != nil {
			remove()
			return "", cleanup, err
		}
		return path, remove, nil
	}
	if !prov.IsSystem && provisionerName != ca.Provisioner {
		return "", cleanup, fmt.Errorf("для провизионера %s не задан пароль", provisionerName)
	}
	return ca.PasswordFile, cleanup, nil
}

// certPurposeFromFile определяет x509Purpose по extKeyUsage существующего
// сертификата, чтобы перевыпуск сохранял исходное назначение.
func certPurposeFromFile(certPath string) string {
	cert, err := readPEMCert(certPath)
	if err != nil {
		return purposeServer
	}
	server, client := false, false
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			server = true
		case x509.ExtKeyUsageClientAuth:
			client = true
		}
	}
	switch {
	case server && client:
		return purposeInternal
	case client:
		return purposeClient
	default:
		return purposeServer
	}
}

func (h *Handler) revokeBySerial(serial, provisionerName string) error {
	ca := h.CA()
	if !ca.Configured {
		return fmt.Errorf("Step-CA не настроен. Настройте подключение в разделе Админ -> Настройки CA (/admin/ca)")
	}
	if !safeRevokeSerial(serial) {
		return fmt.Errorf("пустой серийный номер")
	}
	if provisionerName == "" {
		provisionerName = ca.Provisioner
	}
	passwordFile, cleanup, err := h.provisionerPasswordFile(provisionerName)
	if err != nil {
		return err
	}
	defer cleanup()
	if passwordFile == "" {
		return fmt.Errorf("для провизионера %s не задан пароль", provisionerName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tokenCmd := exec.CommandContext(ctx, "step", revokeTokenArgs(ca.URL, ca.RootCert, provisionerName, passwordFile, serial)...)
	tokenOut, err := tokenCmd.CombinedOutput()
	if err != nil {
		return stepCLIError(err, tokenOut)
	}
	token, err := parseStepToken(string(tokenOut))
	if err != nil {
		return err
	}
	log.Printf("[step-cli] step ca revoke %s provisioner=%s", serial, provisionerName)
	revokeCmd := exec.CommandContext(ctx, "step", revokeWithTokenArgs(ca.URL, ca.RootCert, token, serial)...)
	out, err := revokeCmd.CombinedOutput()
	if err != nil {
		return stepCLIError(err, out)
	}
	return nil
}

func alreadyRevoked(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already revoked") || strings.Contains(msg, "already been revoked")
}

func certStorageDir(certsDir, name, serial string) string {
	return filepath.Join(certsDir, sanitizeName(name), serial)
}

func newIssueTemp(certsDir string) (string, error) {
	base := filepath.Join(certsDir, ".tmp")
	if err := os.MkdirAll(base, 0755); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, "issue-")
}

// commitIssuedFiles переносит временный каталог в CertsDir/<имя>/<serial>/.
// Существующий каталог этого serial не перезаписывается.
func commitIssuedFiles(certsDir, name, tempDir string) (certPath, keyPath, serial string, err error) {
	srcCert := filepath.Join(tempDir, "certificate.crt")
	_, _, serial, err = parseCertDates(srcCert)
	if err != nil || !safeRevokeSerial(serial) {
		return "", "", "", fmt.Errorf("не удалось прочитать сертификат")
	}
	dest := certStorageDir(certsDir, name, serial)
	if _, statErr := os.Stat(dest); statErr == nil {
		return "", "", "", fmt.Errorf("каталог сертификата уже существует")
	} else if !os.IsNotExist(statErr) {
		return "", "", "", statErr
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return "", "", "", err
	}
	if err = os.Rename(tempDir, dest); err != nil {
		return "", "", "", err
	}
	certPath = filepath.Join(dest, "certificate.crt")
	keyPath = filepath.Join(dest, "private.key")
	if _, statErr := os.Stat(keyPath); statErr != nil {
		keyPath = ""
	}
	return certPath, keyPath, serial, nil
}

func (h *Handler) issueIntoFreshDir(name, domain, duration, keyType, purpose, provisionerName string) (certPath, keyPath, serial string, err error) {
	tempDir, err := newIssueTemp(h.cfg.CertsDir)
	if err != nil {
		return "", "", "", err
	}
	certPath = filepath.Join(tempDir, "certificate.crt")
	keyPath = filepath.Join(tempDir, "private.key")
	if err = h.issueWithRegisteredProvisioner(domain, certPath, keyPath, duration, keyType, purpose, provisionerName); err != nil {
		os.RemoveAll(tempDir)
		return "", "", "", err
	}
	return commitIssuedFiles(h.cfg.CertsDir, name, tempDir)
}

func revokeTokenArgs(caURL, rootCert, provisioner, passwordFile, serial string) []string {
	return []string{
		"ca", "token",
		"--revoke",
		"--provisioner", provisioner,
		"--provisioner-password-file", passwordFile,
		"--ca-url", caURL,
		"--root", rootCert,
		serial,
	}
}

func revokeWithTokenArgs(caURL, rootCert, token, serial string) []string {
	return []string{
		"ca", "revoke",
		"--token", token,
		"--ca-url", caURL,
		"--root", rootCert,
		serial,
	}
}

func parseStepToken(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Count(line, ".") == 2 && !strings.ContainsAny(line, " \t") {
			return line, nil
		}
	}
	return "", fmt.Errorf("step ca token: пустой ответ")
}

func stepCLIError(err error, out []byte) error {
	msg := strings.TrimSpace(scrubToken(string(out)))
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("%s", msg)
}

func scrubToken(s string) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		if strings.Count(f, ".") == 2 && len(f) > 20 {
			fields[i] = "[token]"
		}
	}
	return strings.Join(fields, " ")
}

func safeRevokeSerial(serial string) bool {
	if serial == "" || len(serial) > 100 {
		return false
	}
	for _, r := range serial {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseCertDates(certPath string) (issued, expires *time.Time, serial string, err error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		err = fmt.Errorf("no PEM block found")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	i := cert.NotBefore
	e := cert.NotAfter
	issued = &i
	expires = &e
	serial = cert.SerialNumber.String()
	return
}

func getCertKeyType(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		return "EC"
	case x509.RSA:
		return "RSA"
	default:
		return "Unknown"
	}
}

func scanExistingCerts(certsDir string, d *sql.DB) []map[string]string {
	var found []map[string]string
	filepath.WalkDir(certsDir, func(path string, de os.DirEntry, err error) error {
		if err != nil || de == nil {
			return nil
		}
		if de.IsDir() {
			if de.Name() == ".tmp" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "certificate.crt") {
			dir := filepath.Dir(path)
			name := filepath.Base(dir)
			if safeRevokeSerial(name) {
				parent := filepath.Base(filepath.Dir(dir))
				if parent != "" && parent != "." {
					name = parent
				}
			}
			keyPath := filepath.Join(dir, "private.key")
			if _, e := os.Stat(keyPath); e != nil {
				keyPath = ""
			}
			// Проверяем не в базе ли уже
			_, _, serial, e := parseCertDates(path)
			if e != nil || serial == "" {
				return nil
			}
			c, _ := appdb.GetCertBySerial(d, serial)
			if c == nil {
				found = append(found, map[string]string{
					"name": name, "cert_path": path, "key_path": keyPath,
				})
			}
		}
		return nil
	})
	return found
}

func sanitizeName(name string) string {
	replacer := strings.NewReplacer(
		" ", "_", "/", "_", "\\", "_",
		"..", "_", "<", "_", ">", "_",
	)
	return replacer.Replace(name)
}

func saveUploadedFile(file multipart.File, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, file)
	return err
}

func trimStr(s string) string {
	return strings.TrimSpace(s)
}

func daysLeftVal(t *time.Time) int {
	if t == nil {
		return 999
	}
	return int(time.Until(*t).Hours() / 24)
}

// GetCertBySerial wrapper needed in db
var _ = (*models.Certificate)(nil)
