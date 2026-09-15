package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	appdb "step-ui/db"
	"step-ui/models"
	"step-ui/security"
)

type CAResolver struct {
	mu      sync.RWMutex
	current models.CARuntime
	handler *Handler
}

func NewCAResolver(h *Handler) (*CAResolver, error) {
	r := &CAResolver{handler: h}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CAResolver) Runtime() models.CARuntime {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

func (r *CAResolver) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg := r.handler.cfg
	db := r.handler.db

	mode := strings.ToLower(strings.TrimSpace(cfg.CAMode))
	if mode != "external" {
		mode = "bundled"
	}

	rt := models.CARuntime{
		Mode:             mode,
		URL:              cfg.CAURL,
		RootCert:         cfg.RootCert,
		IntermediateCert: filepath.Join(filepath.Dir(cfg.RootCert), "intermediate_ca.crt"),
		Provisioner:      cfg.Provisioner,
		PasswordFile:     cfg.PasswordFile,
		EnableHSTS:       cfg.EnableHSTS,
		Configured:       true,
	}

	// Calculate fingerprint if root cert exists
	if fp, err := calcCertFingerprint(rt.RootCert); err == nil {
		rt.RootFingerprint = fp
	}
	if subj, err := getCertSubject(rt.IntermediateCert); err == nil {
		rt.IntermediateSubject = subj
	}

	if mode == "bundled" {
		r.current = rt
		return nil
	}

	// External mode: load from DB ca_settings if DB connection is available
	var s *models.CASettings
	if db != nil {
		var err error
		s, err = appdb.GetCASettings(db)
		if err != nil {
			log.Printf("[ca-resolver] warning: could not load ca_settings: %v", err)
		}
	}

	if s != nil {
		if s.EnableHSTS {
			rt.EnableHSTS = true
		}
		if strings.TrimSpace(s.CAURL) != "" {
			rt.URL = strings.TrimSpace(s.CAURL)
		}
		if strings.TrimSpace(s.Provisioner) != "" {
			rt.Provisioner = strings.TrimSpace(s.Provisioner)
		}
	}

	// Check if host path bind mount is active at /home/step/certs/root_ca.crt
	if _, err := os.Stat("/home/step/certs/root_ca.crt"); err == nil {
		rt.HostPathMounted = true
		rt.RootCert = "/home/step/certs/root_ca.crt"
		rt.IntermediateCert = "/home/step/certs/intermediate_ca.crt"
		if fp, err := calcCertFingerprint(rt.RootCert); err == nil {
			rt.RootFingerprint = fp
		}
		if subj, err := getCertSubject(rt.IntermediateCert); err == nil {
			rt.IntermediateSubject = subj
		}
	} else {
		// Stored in step-ui-data/ca/
		dataDir := "/opt/step-ui/data/ca"
		os.MkdirAll(dataDir, 0700)
		rootPath := filepath.Join(dataDir, "root_ca.crt")
		intermediatePath := filepath.Join(dataDir, "intermediate_ca.crt")

		// If DB has PEM stored, ensure files on disk match
		if s != nil && strings.TrimSpace(s.RootCertPEM) != "" {
			_ = os.WriteFile(rootPath, []byte(s.RootCertPEM), 0644)
			rt.RootCert = rootPath
			rt.RootFingerprint = s.RootFingerprint
		} else if _, err := os.Stat(rootPath); err == nil {
			rt.RootCert = rootPath
			if fp, err := calcCertFingerprint(rootPath); err == nil {
				rt.RootFingerprint = fp
			}
		}

		if s != nil && strings.TrimSpace(s.IntermediatePEM) != "" {
			_ = os.WriteFile(intermediatePath, []byte(s.IntermediatePEM), 0644)
			rt.IntermediateCert = intermediatePath
			rt.IntermediateSubject = s.IntermediateSubject
		} else if _, err := os.Stat(intermediatePath); err == nil {
			rt.IntermediateCert = intermediatePath
			if subj, err := getCertSubject(intermediatePath); err == nil {
				rt.IntermediateSubject = subj
			}
		}
	}

	// Decrypt provisioner password and write to password file if set in DB
	if s != nil && s.EncryptedPassword != "" {
		plain, err := security.DecryptSecret(s.EncryptedPassword, cfg.SecretKey)
		if err == nil && plain != "" {
			os.MkdirAll(filepath.Dir(rt.PasswordFile), 0700)
			if err := os.WriteFile(rt.PasswordFile, []byte(plain), 0600); err != nil {
				log.Printf("[ca-resolver] failed to write password file: %v", err)
			}
		} else if err != nil {
			log.Printf("[ca-resolver] warning: could not decrypt provisioner password: %v", err)
		}
	}

	// Check if external mode is configured enough to operate
	hasURL := strings.HasPrefix(rt.URL, "https://")
	hasRoot := fileExists(rt.RootCert)
	hasProv := strings.TrimSpace(rt.Provisioner) != ""
	hasPass := fileExists(rt.PasswordFile)

	rt.Configured = hasURL && hasRoot && hasProv && hasPass

	r.current = rt
	return nil
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func calcCertFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func getCertSubject(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return cert.Subject.String(), nil
}
