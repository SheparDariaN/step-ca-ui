package casync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v2"
	"step-ui/models"
)

func TestSyncFromBadgerPreservesKeyPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dbDir := filepath.Join(root, "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "config", "ca.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	rawCfg, err := json.Marshal(map[string]any{
		"db": map[string]string{"type": "badgerv2", "dataSource": dbDir},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, rawCfg, 0644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	active := mustCert(t, "proxmox", "proxmox.example", big.NewInt(1001), now.Add(-time.Hour), now.Add(24*time.Hour), false)
	revoked := mustCert(t, "old-host", "old.example", big.NewInt(1002), now.Add(-48*time.Hour), now.Add(24*time.Hour), false)
	expired := mustCert(t, "gone", "gone.example", big.NewInt(1003), now.Add(-48*time.Hour), now.Add(-time.Hour), false)
	caCert := mustCert(t, "Home CA", "ca.internal", big.NewInt(1), now.Add(-time.Hour), now.Add(365*24*time.Hour), true)
	writeDB(t, dbDir, []stored{
		{bucketCerts, active.SerialNumber.String(), active.Raw},
		{bucketData, active.SerialNumber.String(), meta("acme", "ACME")},
		{bucketCerts, revoked.SerialNumber.String(), revoked.Raw},
		{bucketData, revoked.SerialNumber.String(), meta("acme", "ACME")},
		{bucketRevoked, revoked.SerialNumber.String(), []byte(`{}`)},
		{bucketCerts, expired.SerialNumber.String(), expired.Raw},
		{bucketCerts, caCert.SerialNumber.String(), caCert.Raw},
		{"acme_accounts", "acct-1", []byte("secret-account-key")},
	})

	store := newMemStore()
	certsDir := filepath.Join(root, "certs")
	res, err := Sync(cfgPath, certsDir, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unavailable || res.Added != 3 || res.Updated != 0 {
		t.Fatalf("first sync: %+v", res)
	}
	got := store.certs[active.SerialNumber.String()]
	if got == nil || got.KeyPath != "" || got.Name != "proxmox" || got.Domain != "proxmox.example" || got.Provisioner != "acme" || got.Status != "active" || got.KeyType != "EC:P-256" {
		t.Fatalf("active leaf: %+v", got)
	}
	if !historyHas(store.history, "Импорт из базы step-ca, провизионер: acme (ACME)") {
		t.Fatalf("history: %v", store.history)
	}
	if store.certs[revoked.SerialNumber.String()].Status != "revoked" {
		t.Fatal("revoked leaf must stay revoked")
	}
	if store.certs[expired.SerialNumber.String()].Status != "expired" {
		t.Fatal("expired leaf must be expired")
	}
	if _, ok := store.certs[caCert.SerialNumber.String()]; ok {
		t.Fatal("CA certificate must not be imported")
	}
	pemPath := filepath.Join(certsDir, "_synced", active.SerialNumber.String()+".crt")
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(pemBytes) == "" || containsSecret(pemBytes) {
		t.Fatal("synced PEM missing or leaked account material")
	}
	for _, rec := range store.certs {
		if containsSecret([]byte(rec.Name + rec.Domain + rec.Provisioner + rec.CertPath)) {
			t.Fatal("account bucket leaked into inventory")
		}
	}

	got.KeyPath = "/opt/step-ui/certs/proxmox/private.key"
	got.Name = "custom-name"
	got.CertPath = "/opt/step-ui/certs/proxmox/certificate.crt"

	res, err = Sync(cfgPath, certsDir, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 0 || res.Updated != 3 {
		t.Fatalf("second sync: %+v", res)
	}
	again := store.certs[active.SerialNumber.String()]
	if again.KeyPath != "/opt/step-ui/certs/proxmox/private.key" || again.Name != "custom-name" || again.CertPath != "/opt/step-ui/certs/proxmox/certificate.crt" {
		t.Fatalf("existing paths were overwritten: %+v", again)
	}
	if len(store.history) != 3 {
		t.Fatalf("history must be written only on insert, got %d", len(store.history))
	}
}

func TestResolveDB(t *testing.T) {
	t.Parallel()
	_, skip, err := resolveDB(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || !skip {
		t.Fatalf("missing config: skip=%v err=%v", skip, err)
	}

	root := t.TempDir()
	cfgPath := filepath.Join(root, "config", "ca.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`{"db":{"type":"mysql","dataSource":"dsn"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveDB(cfgPath); err == nil {
		t.Fatal("mysql must be rejected")
	}
	if err := os.WriteFile(cfgPath, []byte(`{"db":{"type":"badgerv2","dataSource":"db"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, skip, err := resolveDB(cfgPath); err != nil || !skip {
		t.Fatalf("missing dir: skip=%v err=%v", skip, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	loc, skip, err := resolveDB(cfgPath)
	if err != nil || skip {
		t.Fatalf("ready dir: skip=%v err=%v", skip, err)
	}
	if loc.Dir != filepath.Join(root, "db") {
		t.Fatalf("dir: %s", loc.Dir)
	}

	if err := os.WriteFile(cfgPath, []byte(`{"db":{"type":"badgerv2","dataSource":"/etc/step-ca/db"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	loc, skip, err = resolveDB(cfgPath)
	if err != nil || skip {
		t.Fatalf("host path fallback: skip=%v err=%v", skip, err)
	}
	if loc.Dir != filepath.Join(root, "db") {
		t.Fatalf("fallback dir: %s", loc.Dir)
	}
}

type stored struct {
	bucket string
	key    string
	val    []byte
}

func writeDB(t *testing.T, dir string, rows []stored) {
	t.Helper()
	opts := badger.DefaultOptions(dir).WithLogger(discardLog{})
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(txn *badger.Txn) error {
		for _, row := range rows {
			bk, err := toBadgerKey([]byte(row.bucket), []byte(row.key))
			if err != nil {
				return err
			}
			if err := txn.Set(bk, row.val); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func meta(name, typ string) []byte {
	raw, err := json.Marshal(map[string]any{
		"provisioner": map[string]string{"id": "id-" + name, "name": name, "type": typ},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func mustCert(t *testing.T, cn, dns string, serial *big.Int, notBefore, notAfter time.Time, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{dns},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         isCA,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func historyHas(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsSecret(b []byte) bool {
	return len(b) > 0 && bytesContains(b, []byte("secret-account-key"))
}

func bytesContains(b, sub []byte) bool {
	return len(sub) == 0 || (len(b) >= len(sub) && indexOf(b, sub) >= 0)
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

type memStore struct {
	certs   map[string]*models.Certificate
	history []string
}

func newMemStore() *memStore {
	return &memStore{certs: map[string]*models.Certificate{}}
}

func (m *memStore) GetCertBySerial(serial string) (*models.Certificate, error) {
	c, ok := m.certs[serial]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (m *memStore) InsertSyncedCert(c *models.Certificate, historyDetails string) error {
	cp := *c
	cp.KeyPath = ""
	m.certs[c.Serial] = &cp
	m.history = append(m.history, historyDetails)
	return nil
}

func (m *memStore) UpdateSyncedCert(serial string, issued, expires *time.Time, status, provisioner, keyType, certPathIfEmpty string) error {
	c := m.certs[serial]
	c.IssuedAt = issued
	c.ExpiresAt = expires
	c.Status = status
	if provisioner != "" {
		c.Provisioner = provisioner
	}
	if c.KeyType == "" {
		c.KeyType = keyType
	}
	if c.CertPath == "" && certPathIfEmpty != "" {
		c.CertPath = certPathIfEmpty
	}
	return nil
}
