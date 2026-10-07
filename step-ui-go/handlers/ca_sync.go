package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"step-ui/casync"
	appdb "step-ui/db"
	"step-ui/models"
)

type caCertStore struct {
	db *sql.DB
}

func (s caCertStore) GetCertBySerial(serial string) (*models.Certificate, error) {
	return appdb.GetCertBySerial(s.db, serial)
}

func (s caCertStore) InsertSyncedCert(c *models.Certificate, historyDetails string) error {
	return appdb.InsertSyncedCert(s.db, c, historyDetails)
}

func (s caCertStore) UpdateSyncedCert(serial string, issued, expires *time.Time, status, provisioner, keyType, certPathIfEmpty string) error {
	return appdb.UpdateSyncedCert(s.db, serial, issued, expires, status, provisioner, keyType, certPathIfEmpty)
}

func (h *Handler) SyncFromCA() (casync.Result, error) {
	return casync.Sync(casync.DefaultCAConfig, h.cfg.CertsDir, caCertStore{db: h.db}, time.Now())
}

func (h *Handler) StartCASync() {
	go func() {
		h.runCASync()
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			h.runCASync()
		}
	}()
}

func (h *Handler) runCASync() {
	res, err := h.SyncFromCA()
	if err != nil {
		log.Printf("[casync] %v", err)
		return
	}
	if res.Unavailable {
		return
	}
	if res.Added > 0 || res.Updated > 0 || res.Skipped > 0 {
		log.Printf("[casync] added=%d updated=%d skipped=%d", res.Added, res.Updated, res.Skipped)
	}
}

func (h *Handler) SyncCertificatesPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/certificates") {
		return
	}
	res, err := h.SyncFromCA()
	if err != nil {
		h.flash(w, r, "err", "Ошибка: "+err.Error())
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
		return
	}
	if res.Unavailable {
		h.flash(w, r, "err", "База сертификатов step-ca недоступна")
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
		return
	}
	h.auditSecurity(r, fmt.Sprintf("certificate.sync added=%d updated=%d skipped=%d", res.Added, res.Updated, res.Skipped))
	h.flash(w, r, "ok", fmt.Sprintf("Синхронизировано: добавлено %d, обновлено %d", res.Added, res.Updated))
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}
