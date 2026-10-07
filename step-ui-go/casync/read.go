package casync

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	badger "github.com/dgraph-io/badger/v2"
)

const (
	DefaultCAConfig = "/home/step/config/ca.json"

	bucketCerts   = "x509_certs"
	bucketData    = "x509_certs_data"
	bucketRevoked = "revoked_x509_certs"
)

// Leaf — публичный сертификат из базы step-ca. Приватного ключа в ней нет.
type Leaf struct {
	Serial      string
	Name        string
	Domain      string
	NotBefore   time.Time
	NotAfter    time.Time
	KeyType     string
	Provisioner string
	ProvType    string
	PEM         []byte
	Revoked     bool
}

type dbLocation struct {
	Dir      string
	ValueDir string
}

type caFile struct {
	DB struct {
		Type       string `json:"type"`
		DataSource string `json:"dataSource"`
		ValueDir   string `json:"valueDir"`
	} `json:"db"`
}

type certMeta struct {
	Provisioner *struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"provisioner"`
}

type discardLog struct{}

func (discardLog) Errorf(string, ...interface{})   {}
func (discardLog) Warningf(string, ...interface{}) {}
func (discardLog) Infof(string, ...interface{})    {}
func (discardLog) Debugf(string, ...interface{})   {}

// resolveDB читает db.dataSource из ca.json.
// skip=true, если конфигурации или каталога нет: это внешний CA без монтирования.
func resolveDB(configPath string) (dbLocation, bool, error) {
	if configPath == "" {
		configPath = DefaultCAConfig
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return dbLocation{}, true, nil
		}
		return dbLocation{}, false, err
	}
	var cfg caFile
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return dbLocation{}, false, fmt.Errorf("ca.json: %w", err)
	}
	stepPath := filepath.Dir(filepath.Dir(configPath))
	kind := strings.ToLower(strings.TrimSpace(cfg.DB.Type))
	switch kind {
	case "", "badger", "badgerv2":
	default:
		return dbLocation{}, false, fmt.Errorf("неподдерживаемый тип базы step-ca: %s", kind)
	}
	dir := strings.TrimSpace(cfg.DB.DataSource)
	if dir == "" {
		dir = filepath.Join(stepPath, "db")
	} else if !filepath.IsAbs(dir) {
		dir = filepath.Join(stepPath, dir)
	}
	// ca.json внешнего CA хранит путь хоста (/etc/step-ca/db). В контейнере тот же
	// каталог смонтирован в STEPPATH (/home/step/db).
	if !dirExists(dir) {
		fallback := filepath.Join(stepPath, "db")
		if fallback != dir && dirExists(fallback) {
			dir = fallback
		}
	}
	if !dirExists(dir) {
		return dbLocation{}, true, nil
	}
	valueDir := strings.TrimSpace(cfg.DB.ValueDir)
	if valueDir != "" && !filepath.IsAbs(valueDir) {
		valueDir = filepath.Join(stepPath, valueDir)
	}
	if valueDir != "" && !dirExists(valueDir) {
		valueDir = ""
	}
	return dbLocation{Dir: dir, ValueDir: valueDir}, false, nil
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// openSnapshot открывает копию базы. Truncate нужен, потому что живой step-ca
// не закрывает value log, и ReadOnly такой файл не читает. Исходный каталог не открывается.
func openSnapshot(dir string) (*badger.DB, error) {
	opts := badger.DefaultOptions(dir).
		WithTruncate(true).
		WithBypassLockGuard(true).
		WithLogger(discardLog{})
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("открытие базы step-ca: %w", err)
	}
	return db, nil
}

func snapshotDB(src string) (string, error) {
	dst, err := os.MkdirTemp("", "casync-db-*")
	if err != nil {
		return "", err
	}
	if err := copyRegularFiles(src, dst); err != nil {
		os.RemoveAll(dst)
		return "", err
	}
	return dst, nil
}

func copyRegularFiles(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "LOCK" {
			continue
		}
		if err := copyFile(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func readLeafs(loc dbLocation) ([]Leaf, int, error) {
	snap, err := snapshotDB(loc.Dir)
	if err != nil {
		return nil, 0, err
	}
	if loc.ValueDir != "" && loc.ValueDir != loc.Dir {
		if err := copyRegularFiles(loc.ValueDir, snap); err != nil {
			os.RemoveAll(snap)
			return nil, 0, err
		}
	}
	defer os.RemoveAll(snap)

	db, err := openSnapshot(snap)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()

	certs, skipped, err := listBucket(db, bucketCerts)
	if err != nil {
		return nil, skipped, err
	}
	metaRows, metaSkipped, err := listBucket(db, bucketData)
	if err != nil {
		return nil, skipped + metaSkipped, err
	}
	revokedRows, revSkipped, err := listBucket(db, bucketRevoked)
	if err != nil {
		return nil, skipped + metaSkipped + revSkipped, err
	}
	skipped += metaSkipped + revSkipped

	meta := map[string]certMeta{}
	for serial, raw := range metaRows {
		var m certMeta
		if err := json.Unmarshal(raw, &m); err != nil {
			skipped++
			continue
		}
		meta[serial] = m
	}
	revoked := map[string]bool{}
	for serial := range revokedRows {
		revoked[serial] = true
	}

	var leafs []Leaf
	for serial, der := range certs {
		leaf, ok := parseLeaf(serial, der, meta[serial], revoked[serial])
		if !ok {
			skipped++
			continue
		}
		leafs = append(leafs, leaf)
	}
	return leafs, skipped, nil
}

func listBucket(db *badger.DB, bucket string) (map[string][]byte, int, error) {
	prefix, err := encodeSection([]byte(bucket))
	if err != nil {
		return nil, 0, err
	}
	out := map[string][]byte{}
	skipped := 0
	err = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.PrefetchSize = 64
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			rawKey := item.KeyCopy(nil)
			if isTableKey(rawKey) {
				continue
			}
			gotBucket, key, err := fromBadgerKey(rawKey)
			if err != nil || !bytes.Equal(gotBucket, []byte(bucket)) {
				skipped++
				continue
			}
			val, err := item.ValueCopy(nil)
			if err != nil {
				skipped++
				continue
			}
			copied := make([]byte, len(val))
			copy(copied, val)
			out[string(key)] = copied
		}
		return nil
	})
	return out, skipped, err
}

func parseLeaf(serial string, der []byte, meta certMeta, revoked bool) (Leaf, bool) {
	if !safeSerial(serial) {
		return Leaf{}, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.IsCA {
		return Leaf{}, false
	}
	if cert.SerialNumber == nil || cert.SerialNumber.String() != serial {
		return Leaf{}, false
	}
	name, domain := certIdentity(cert)
	leaf := Leaf{
		Serial:    serial,
		Name:      clipRunes(name, 255),
		Domain:    clipRunes(domain, 255),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		KeyType:   keyTypeOf(cert),
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		Revoked:   revoked,
	}
	if meta.Provisioner != nil {
		leaf.Provisioner = clipRunes(strings.TrimSpace(meta.Provisioner.Name), 255)
		leaf.ProvType = strings.TrimSpace(meta.Provisioner.Type)
	}
	if len(leaf.PEM) == 0 {
		return Leaf{}, false
	}
	return leaf, true
}

func certIdentity(cert *x509.Certificate) (name, domain string) {
	cn := strings.TrimSpace(cert.Subject.CommonName)
	dns := ""
	if len(cert.DNSNames) > 0 {
		dns = strings.TrimSpace(cert.DNSNames[0])
	}
	switch {
	case cn != "":
		name = cn
	case dns != "":
		name = dns
	default:
		name = cert.SerialNumber.String()
	}
	switch {
	case dns != "":
		domain = dns
	case cn != "":
		domain = cn
	default:
		domain = name
	}
	return name, domain
}

func keyTypeOf(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		if ec, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && ec.Curve != nil && ec.Curve.Params() != nil {
			switch ec.Curve.Params().BitSize {
			case 256:
				return "EC:P-256"
			case 384:
				return "EC:P-384"
			case 521:
				return "EC:P-521"
			}
		}
		return "EC"
	case x509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok && pub.N != nil && pub.N.BitLen() > 0 {
			return fmt.Sprintf("RSA:%d", pub.N.BitLen())
		}
		return "RSA"
	default:
		return "Unknown"
	}
}

func safeSerial(serial string) bool {
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

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
