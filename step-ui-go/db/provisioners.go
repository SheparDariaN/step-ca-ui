package db

import (
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"step-ui/models"
	"step-ui/security"
)

var AllowedProvisionerDurations = map[string]bool{
	"720h": true, "4380h": true, "8760h": true, "87600h": true,
}

var provisionerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,62}$`)

func InitCAProvisionerSchema(d *sql.DB) error {
	_, err := d.Exec(`
		CREATE TABLE IF NOT EXISTS ca_provisioners (
			name               TEXT PRIMARY KEY,
			type               TEXT NOT NULL DEFAULT 'JWK',
			default_duration   TEXT NOT NULL DEFAULT '8760h',
			max_duration       TEXT NOT NULL DEFAULT '87600h',
			encrypted_password TEXT NOT NULL DEFAULT '',
			is_system          BOOLEAN NOT NULL DEFAULT FALSE,
			created_at         TIMESTAMPTZ DEFAULT NOW()
		)
	`)
	if err != nil {
		return err
	}
	_, err = d.Exec(`ALTER TABLE certificates ADD COLUMN IF NOT EXISTS provisioner VARCHAR(255) DEFAULT ''`)
	return err
}

func ParseTLSDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

func DurationExceedsMax(requested, maxDur string) bool {
	rd, err1 := ParseTLSDuration(requested)
	md, err2 := ParseTLSDuration(maxDur)
	if err1 != nil || err2 != nil {
		return true
	}
	return rd > md
}

func ValidateProvisionerRegistration(name, typ, defDur, maxDur, systemName string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("provisioner name is required")
	}
	if !provisionerNameRe.MatchString(name) {
		return fmt.Errorf("invalid provisioner name")
	}
	if strings.EqualFold(name, "admin") || (strings.TrimSpace(systemName) != "" && strings.EqualFold(name, systemName)) {
		return fmt.Errorf("cannot register system provisioner %q via CLI", name)
	}
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if typ != "JWK" {
		return fmt.Errorf("unsupported provisioner type %q (v1 supports JWK only)", typ)
	}
	if !AllowedProvisionerDurations[defDur] || !AllowedProvisionerDurations[maxDur] {
		return fmt.Errorf("duration must be one of 720h, 4380h, 8760h, 87600h")
	}
	if DurationExceedsMax(defDur, maxDur) {
		return fmt.Errorf("default duration exceeds max duration")
	}
	return nil
}

func ListCAProvisioners(d *sql.DB) ([]*models.CAProvisioner, error) {
	rows, err := d.Query(`SELECT name,type,default_duration,max_duration,encrypted_password,is_system,created_at
		FROM ca_provisioners ORDER BY is_system DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*models.CAProvisioner
	for rows.Next() {
		p := &models.CAProvisioner{}
		if err := rows.Scan(&p.Name, &p.Type, &p.DefaultDuration, &p.MaxDuration, &p.EncryptedPassword, &p.IsSystem, &p.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func GetCAProvisioner(d *sql.DB, name string) (*models.CAProvisioner, error) {
	p := &models.CAProvisioner{}
	err := d.QueryRow(`SELECT name,type,default_duration,max_duration,encrypted_password,is_system,created_at
		FROM ca_provisioners WHERE name=$1`, name).
		Scan(&p.Name, &p.Type, &p.DefaultDuration, &p.MaxDuration, &p.EncryptedPassword, &p.IsSystem, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

func UpsertCAProvisioner(d *sql.DB, name, typ, defDur, maxDur, encryptedPassword string, isSystem bool) error {
	_, err := d.Exec(`INSERT INTO ca_provisioners (name,type,default_duration,max_duration,encrypted_password,is_system)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (name) DO UPDATE SET
			type=EXCLUDED.type,
			default_duration=EXCLUDED.default_duration,
			max_duration=EXCLUDED.max_duration,
			encrypted_password=EXCLUDED.encrypted_password`,
		name, typ, defDur, maxDur, encryptedPassword, isSystem)
	return err
}

func RegisterCAProvisioner(d *sql.DB, name, typ, defDur, maxDur, plaintext, secretKey, systemName string) error {
	if err := ValidateProvisionerRegistration(name, typ, defDur, maxDur, systemName); err != nil {
		return err
	}
	existing, err := GetCAProvisioner(d, name)
	if err != nil {
		return err
	}
	if existing != nil && existing.IsSystem {
		return fmt.Errorf("cannot register system provisioner %q via CLI", name)
	}
	enc, err := security.EncryptSecret(plaintext, secretKey)
	if err != nil {
		return err
	}
	return UpsertCAProvisioner(d, name, "JWK", defDur, maxDur, enc, false)
}

func UpdateCAProvisioner(d *sql.DB, name, defDur, maxDur, plaintext, secretKey, systemName string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("provisioner name is required")
	}
	if !provisionerNameRe.MatchString(name) {
		return fmt.Errorf("invalid provisioner name")
	}
	if strings.EqualFold(name, "admin") || (strings.TrimSpace(systemName) != "" && strings.EqualFold(name, systemName)) {
		return fmt.Errorf("cannot update system provisioner %q via CLI", name)
	}
	if !AllowedProvisionerDurations[defDur] || !AllowedProvisionerDurations[maxDur] {
		return fmt.Errorf("duration must be one of 720h, 4380h, 8760h, 87600h")
	}
	if DurationExceedsMax(defDur, maxDur) {
		return fmt.Errorf("default duration exceeds max duration")
	}
	existing, err := GetCAProvisioner(d, name)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("provisioner %q is not registered in UI", name)
	}
	if existing.IsSystem {
		return fmt.Errorf("cannot update system provisioner %q via CLI", name)
	}
	if strings.TrimSpace(plaintext) != "" {
		enc, err := security.EncryptSecret(plaintext, secretKey)
		if err != nil {
			return err
		}
		_, err = d.Exec(`UPDATE ca_provisioners SET default_duration=$1, max_duration=$2, encrypted_password=$3 WHERE name=$4`,
			defDur, maxDur, enc, name)
		return err
	}
	_, err = d.Exec(`UPDATE ca_provisioners SET default_duration=$1, max_duration=$2 WHERE name=$3`,
		defDur, maxDur, name)
	return err
}

func EnsureSystemProvisioner(d *sql.DB, name, plaintext, secretKey string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "admin"
	}
	var count int
	if err := d.QueryRow(`SELECT COUNT(*) FROM ca_provisioners`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	enc := ""
	if strings.TrimSpace(plaintext) != "" && strings.TrimSpace(secretKey) != "" {
		var err error
		enc, err = security.EncryptSecret(plaintext, secretKey)
		if err != nil {
			return err
		}
	}
	return UpsertCAProvisioner(d, name, "JWK", "8760h", "87600h", enc, true)
}

func ReadProvisionerPasswordFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
