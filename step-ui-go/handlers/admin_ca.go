package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appdb "step-ui/db"
	"step-ui/models"
	"step-ui/security"
)

func (h *Handler) AdminCAGet(w http.ResponseWriter, r *http.Request) {
	ca := h.CA()
	settings, _ := appdb.GetCASettings(h.db)

	data := h.base(w, r, "admin_ca")
	data["CARuntime"] = ca
	data["Settings"] = settings
	h.render(w, "admin_ca", data)
}

func (h *Handler) AdminCAPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/admin/ca") {
		return
	}

	ca := h.CA()
	settings, err := appdb.GetCASettings(h.db)
	if err != nil || settings == nil {
		settings = &models.CASettings{}
	}

	// Общая настройка HSTS (доступна в обоих режимах)
	enableHSTS := r.FormValue("enable_hsts") == "on" || r.FormValue("enable_hsts") == "true"
	settings.EnableHSTS = enableHSTS

	if ca.Mode == "bundled" {
		// В bundled режиме реквизиты CA берутся только из env/docker
		if err := appdb.SaveCASettings(h.db, settings); err != nil {
			h.flash(w, r, "err", "Ошибка сохранения настроек: "+err.Error())
		} else {
			_ = h.resolver.Reload()
			h.auditSecurity(r, fmt.Sprintf("ca.settings.save mode=bundled hsts=%t", enableHSTS))
			h.flash(w, r, "ok", "Настройки сохранены")
		}
		http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
		return
	}

	// External mode
	caURL := strings.TrimSpace(r.FormValue("ca_url"))
	provisioner := strings.TrimSpace(r.FormValue("provisioner"))
	password := strings.TrimSpace(r.FormValue("password"))

	if caURL != "" {
		parsed, parseErr := url.Parse(caURL)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" {
			h.flash(w, r, "err", "Некорректный CA URL: должен начинаться с https:// и содержать хост")
			http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
			return
		}
		settings.CAURL = caURL
	}

	if provisioner != "" {
		settings.Provisioner = provisioner
	}

	if password != "" {
		enc, encErr := security.EncryptSecret(password, h.cfg.SecretKey)
		if encErr != nil {
			h.flash(w, r, "err", "Ошибка шифрования пароля: "+encErr.Error())
			http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
			return
		}
		settings.EncryptedPassword = enc
	}

	// Обработка загрузки PEM файлов (если нет bind-mount)
	if !ca.HostPathMounted {
		rootFile, _, err := r.FormFile("root_cert_file")
		if err == nil && rootFile != nil {
			defer rootFile.Close()
			bytes, readErr := io.ReadAll(rootFile)
			if readErr == nil && len(bytes) > 0 {
				cert, parseErr := validateUploadedCACert(bytes)
				if parseErr != nil {
					h.flash(w, r, "err", "Root CA файл некорректен: "+parseErr.Error())
					http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
					return
				}
				settings.RootCertPEM = string(bytes)
				sha := x509SHA256(cert.Raw)
				settings.RootFingerprint = colonHex(sha[:])
			}
		}

		interFile, _, err := r.FormFile("intermediate_cert_file")
		if err == nil && interFile != nil {
			defer interFile.Close()
			bytes, readErr := io.ReadAll(interFile)
			if readErr == nil && len(bytes) > 0 {
				cert, parseErr := validateUploadedCACert(bytes)
				if parseErr != nil {
					h.flash(w, r, "err", "Intermediate CA файл некорректен: "+parseErr.Error())
					http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
					return
				}
				settings.IntermediatePEM = string(bytes)
				if cert.Subject.CommonName != "" {
					settings.IntermediateSubject = cert.Subject.CommonName
				} else {
					settings.IntermediateSubject = cert.Subject.String()
				}
			}
		}
	}

	if err := appdb.SaveCASettings(h.db, settings); err != nil {
		h.flash(w, r, "err", "Ошибка сохранения в БД: "+err.Error())
		http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
		return
	}

	_ = h.resolver.Reload()
	h.auditSecurity(r, fmt.Sprintf("ca.settings.save mode=external ca_url=%s provisioner=%s hsts=%t pw_updated=%t",
		settings.CAURL, settings.Provisioner, enableHSTS, password != ""))
	h.flash(w, r, "ok", "Настройки CA успешно сохранены")
	http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
}

func (h *Handler) AdminCATestPost(w http.ResponseWriter, r *http.Request) {
	if !h.requireCSRF(w, r, "/admin/ca") {
		return
	}

	ca := h.CA()
	if !ca.Configured {
		h.flash(w, r, "err", "CA ещё не сконфигурирован. Заполните URL, provisioner, пароль и сертификаты.")
		http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	out, err := runCheck(ctx, 5*time.Second, "step", "ca", "health", "--ca-url", ca.URL, "--root", ca.RootCert)
	if err != nil {
		h.auditSecurity(r, fmt.Sprintf("ca.test status=fail error=%q", cleanCheckOutput(out, err)))
		h.flash(w, r, "err", "Проверка доступности step-ca health завершилась ошибкой: "+cleanCheckOutput(out, err))
		http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
		return
	}

	// Проверим также чтение списка provisioners
	provOut, provErr := runCheck(ctx, 5*time.Second, "step", "ca", "provisioner", "list", "--ca-url", ca.URL, "--root", ca.RootCert)
	if provErr != nil {
		h.auditSecurity(r, fmt.Sprintf("ca.test status=partial provisioner_err=%q", cleanCheckOutput(provOut, provErr)))
		h.flash(w, r, "warn", "CA health доступен, но не удалось получить provisioners: "+cleanCheckOutput(provOut, provErr))
		http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
		return
	}

	h.auditSecurity(r, "ca.test status=ok")
	h.flash(w, r, "ok", fmt.Sprintf("Подключение к CA успешно! URL: %s, ответ health: OK", ca.URL))
	http.Redirect(w, r, "/admin/ca", http.StatusSeeOther)
}

func validateUploadedCACert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM блок не найден")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ожидался тип CERTIFICATE, получен %s", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("невалидный X.509 сертификат: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("сертификат не помечен как CA (BasicConstraints: IsCA=false)")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("срок действия сертификата истёк или ещё не наступил (%s — %s)",
			cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	}
	return cert, nil
}
