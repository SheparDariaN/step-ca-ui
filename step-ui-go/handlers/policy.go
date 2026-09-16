package handlers

import (
	"net/http"
	"strings"

	appdb "step-ui/db"
)

var roleLevels = map[string]int{"viewer": 1, "manager": 2, "admin": 3}

func roleAtLeast(role, minRole string) bool {
	return roleLevels[role] >= roleLevels[minRole]
}

// force2FARole возвращает минимальную роль, для которой TOTP обязателен.
// Пустая строка означает, что политика выключена.
func (h *Handler) force2FARole() string {
	settings, err := appdb.GetSecuritySettings(h.db)
	if err != nil || settings == nil {
		return ""
	}
	role := strings.TrimSpace(settings.Force2FARole)
	if _, ok := roleLevels[role]; !ok {
		return ""
	}
	return role
}

// requires2FA сообщает, обязателен ли TOTP для указанной роли.
func (h *Handler) requires2FA(role string) bool {
	minRole := h.force2FARole()
	if minRole == "" {
		return false
	}
	return roleAtLeast(role, minRole)
}

// twoFAPolicyExemptPaths — маршруты, доступные без выполненной политики 2FA,
// иначе пользователь не смог бы включить TOTP или выйти из системы.
var twoFAPolicyExemptPaths = []string{
	"/logout",
	"/profile/2fa",
	"/profile/2fa/start",
	"/profile/2fa/qr",
	"/profile/2fa/confirm",
	"/profile/2fa/disable",
}

// Enforce2FAPolicy перенаправляет пользователей, для которых TOTP обязателен
// по политике, но ещё не включён, на страницу настройки 2FA.
func (h *Handler) Enforce2FAPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range twoFAPolicyExemptPaths {
			if r.URL.Path == p {
				next.ServeHTTP(w, r)
				return
			}
		}

		si := h.sessionInfo(r)
		if si.UserID == 0 || !h.requires2FA(si.Role) {
			next.ServeHTTP(w, r)
			return
		}
		u, err := appdb.GetUserByID(h.db, si.UserID)
		if err != nil || u == nil || u.TOTPEnabled {
			next.ServeHTTP(w, r)
			return
		}

		h.flash(w, r, "warn", "Политика безопасности требует включить 2FA для вашей роли.")
		http.Redirect(w, r, "/profile/2fa", http.StatusFound)
	})
}
