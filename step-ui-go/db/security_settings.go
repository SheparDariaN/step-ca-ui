package db

import (
	"database/sql"
	"time"

	"step-ui/models"
)

func InitSecuritySettingsSchema(d *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS security_settings (
		id             INT PRIMARY KEY DEFAULT 1,
		force_2fa_role VARCHAR(20) DEFAULT '',
		updated_at     TIMESTAMPTZ DEFAULT NOW()
	);
	INSERT INTO security_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
	`
	_, err := d.Exec(schema)
	return err
}

func GetSecuritySettings(d *sql.DB) (*models.SecuritySettings, error) {
	s := &models.SecuritySettings{}
	err := d.QueryRow(`SELECT COALESCE(force_2fa_role,''), updated_at FROM security_settings WHERE id=1`).
		Scan(&s.Force2FARole, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return &models.SecuritySettings{}, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func SaveSecuritySettings(d *sql.DB, s *models.SecuritySettings) error {
	_, err := d.Exec(`
		INSERT INTO security_settings (id, force_2fa_role, updated_at)
		VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE SET
			force_2fa_role = EXCLUDED.force_2fa_role,
			updated_at     = EXCLUDED.updated_at
	`, s.Force2FARole, time.Now())
	return err
}
