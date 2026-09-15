package db

import (
	"database/sql"
	"time"

	"step-ui/models"
)

func InitCASchema(d *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS ca_settings (
		id                     INT PRIMARY KEY DEFAULT 1,
		ca_url                 TEXT DEFAULT '',
		provisioner            TEXT DEFAULT '',
		encrypted_password     TEXT DEFAULT '',
		root_cert_pem          TEXT DEFAULT '',
		intermediate_pem       TEXT DEFAULT '',
		root_fingerprint       TEXT DEFAULT '',
		intermediate_subject   TEXT DEFAULT '',
		enable_hsts            BOOLEAN DEFAULT FALSE,
		updated_at             TIMESTAMPTZ DEFAULT NOW()
	);
	INSERT INTO ca_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
	`
	if _, err := d.Exec(schema); err != nil {
		return err
	}
	return nil
}

func GetCASettings(d *sql.DB) (*models.CASettings, error) {
	s := &models.CASettings{}
	err := d.QueryRow(`
		SELECT id, ca_url, provisioner, encrypted_password, root_cert_pem,
		       intermediate_pem, root_fingerprint, intermediate_subject,
		       enable_hsts, updated_at
		FROM ca_settings WHERE id=1
	`).Scan(
		&s.ID, &s.CAURL, &s.Provisioner, &s.EncryptedPassword, &s.RootCertPEM,
		&s.IntermediatePEM, &s.RootFingerprint, &s.IntermediateSubject,
		&s.EnableHSTS, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func SaveCASettings(d *sql.DB, s *models.CASettings) error {
	now := time.Now()
	_, err := d.Exec(`
		INSERT INTO ca_settings (id, ca_url, provisioner, encrypted_password, root_cert_pem,
		                         intermediate_pem, root_fingerprint, intermediate_subject,
		                         enable_hsts, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			ca_url               = EXCLUDED.ca_url,
			provisioner          = EXCLUDED.provisioner,
			encrypted_password   = EXCLUDED.encrypted_password,
			root_cert_pem        = EXCLUDED.root_cert_pem,
			intermediate_pem     = EXCLUDED.intermediate_pem,
			root_fingerprint     = EXCLUDED.root_fingerprint,
			intermediate_subject = EXCLUDED.intermediate_subject,
			enable_hsts          = EXCLUDED.enable_hsts,
			updated_at           = EXCLUDED.updated_at
	`, s.CAURL, s.Provisioner, s.EncryptedPassword, s.RootCertPEM,
		s.IntermediatePEM, s.RootFingerprint, s.IntermediateSubject,
		s.EnableHSTS, now)
	return err
}
