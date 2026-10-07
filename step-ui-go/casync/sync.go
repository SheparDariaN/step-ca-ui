package casync

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"step-ui/models"
)

// Store — запись инвентаря. Insert только для нового serial.
// Update не получает key_path и name: их нельзя затирать у сертификатов, выпущенных UI.
type Store interface {
	GetCertBySerial(serial string) (*models.Certificate, error)
	InsertSyncedCert(c *models.Certificate, historyDetails string) error
	UpdateSyncedCert(serial string, issued, expires *time.Time, status, provisioner, keyType, certPathIfEmpty string) error
}

type Result struct {
	Added       int
	Updated     int
	Skipped     int
	Unavailable bool
}

// Sync читает листовые сертификаты step-ca и добавляет их в инвентарь UI.
func Sync(configPath, certsDir string, store Store, now time.Time) (Result, error) {
	loc, skip, err := resolveDB(configPath)
	if err != nil {
		return Result{}, err
	}
	if skip {
		return Result{Unavailable: true}, nil
	}
	leafs, skipped, err := readLeafs(loc)
	if err != nil {
		return Result{Skipped: skipped}, err
	}
	res, err := apply(leafs, certsDir, store, now)
	res.Skipped += skipped
	return res, err
}

func apply(leafs []Leaf, certsDir string, store Store, now time.Time) (Result, error) {
	var res Result
	if len(leafs) == 0 {
		return res, nil
	}
	dir := filepath.Join(certsDir, "_synced")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return res, err
	}
	for _, leaf := range leafs {
		existing, err := store.GetCertBySerial(leaf.Serial)
		if err != nil {
			return res, err
		}
		issued := leaf.NotBefore
		expires := leaf.NotAfter
		status := leafStatus(leaf, now)
		path := filepath.Join(dir, leaf.Serial+".crt")
		if existing == nil {
			if err := os.WriteFile(path, leaf.PEM, 0644); err != nil {
				res.Skipped++
				continue
			}
			rec := &models.Certificate{
				Name:        leaf.Name,
				Domain:      leaf.Domain,
				CertPath:    path,
				IssuedAt:    &issued,
				ExpiresAt:   &expires,
				Serial:      leaf.Serial,
				Status:      status,
				KeyType:     leaf.KeyType,
				Provisioner: leaf.Provisioner,
			}
			if err := store.InsertSyncedCert(rec, historyDetails(leaf)); err != nil {
				again, gerr := store.GetCertBySerial(leaf.Serial)
				if gerr != nil || again == nil {
					return res, err
				}
				existing = again
			} else {
				res.Added++
				continue
			}
		}
		certPath := ""
		if existing.CertPath == "" {
			if err := os.WriteFile(path, leaf.PEM, 0644); err != nil {
				res.Skipped++
				continue
			}
			certPath = path
		}
		if err := store.UpdateSyncedCert(leaf.Serial, &issued, &expires, status, leaf.Provisioner, leaf.KeyType, certPath); err != nil {
			return res, err
		}
		res.Updated++
	}
	return res, nil
}

func leafStatus(leaf Leaf, now time.Time) string {
	if leaf.Revoked {
		return "revoked"
	}
	if !leaf.NotAfter.After(now) {
		return "expired"
	}
	return "active"
}

func historyDetails(leaf Leaf) string {
	if leaf.Provisioner == "" && leaf.ProvType == "" {
		return "Импорт из базы step-ca"
	}
	return fmt.Sprintf("Импорт из базы step-ca, провизионер: %s (%s)", leaf.Provisioner, leaf.ProvType)
}
