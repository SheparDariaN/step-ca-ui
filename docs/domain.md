# Domain Concepts and Invariants

This document defines business rules, PKI lifecycle semantics, and canonical text strings for Step-CA UI.

## Roles and Privileges

| Role | Permissions |
|---|---|
| `viewer` | Read-only access to dashboard, certificates, details, history, provisioners, and personal profile. |
| `manager` | All `viewer` permissions + certificate issuance, renewal, import, key downloads, and Let's Encrypt management. |
| `admin` | All `manager` permissions + user management, temporary user creation, CA root key downloads, certificate revocation, system console, backup bundle export, notifications, and integrity diagnostics. |

### Temporary Users
- Temporary users can hold any role (`viewer`, `manager`, `admin`).
- Have a non-null `expires_at` timestamp.
- A background goroutine checks accounts every minute. Once `expires_at <= NOW()`, the account is automatically locked (`is_active = FALSE`).

## Certificate Templates

Pre-configured profiles in `step-ui-go/handlers/cert_ops.go`:
- **`server`**: Default TLS server cert, 1 year validity (`8760h`), `EC:P-256`.
- **`internal`**: Long-lived internal service cert, 10 years validity (`87600h`), `EC:P-256`.
- **`wildcard`**: Server certificate requiring domain prefix `*.` (e.g. `*.domain.local`), 1 year validity (`8760h`), `EC:P-256`.
- **`client`**: Client mTLS identity certificate, 1 year validity (`8760h`), `EC:P-256`.

Allowed durations: `720h` (30 days), `4380h` (6 months), `8760h` (1 year), `87600h` (10 years).
Allowed key types: `EC:P-256`, `EC:P-384`, `RSA:2048`, `RSA:4096`.

UI templates are form presets. They do not select a step-ca provisioner. Issue/renew uses a **registered JWK** from `ca_provisioners` (seeded `admin` plus playbook-created classes). The requested `--not-after` must not exceed that provisioner's `max_duration`. System provisioner `admin` cannot be overwritten via `./provisioner.sh`. `--mode create` writes the JWK on bundled step-ca or a same-host native CA (`CA_HOST_PATH` / `/etc/step-ca`); `register-only` is for an already existing JWK.

## Canonical Russian UI & Error Strings

To maintain system consistency and security guarantees, do not paraphrase these canonical strings:

### Password Validation
- Minimum length: `"Минимум 8 символов"`
- Maximum length: `"Максимум 72 символа"`
- Missing digit: `"Нужна хотя бы одна цифра"`
- Missing letter: `"Нужна хотя бы одна буква"`
- Missing special character: `"Нужен хотя бы один спецсимвол"`

### Session & CSRF
- Invalid CSRF token: `"Ошибка сессии. Обновите страницу."`
- General operation success flash: `"Операция успешно выполнена"`

### Account Recovery & Enumeration Defense
- Forgot password submission message (must be neutral regardless of account presence):
  `"Если аккаунт с таким логином или email существует, мы отправили ссылку для сброса пароля."`
- Invalid or expired token message:
  `"Ссылка для сброса недействительна или устарела. Запросите восстановление повторно."`

### Restricted Admin Console
- Command not allowlisted:
  `"Команда не входит в allowlist."`
- Execution timeout:
  `"Команда прервана по таймауту"`

## Backup and Restore Rules

- **Content**: Backup archive (`.tgz`) contains PostgreSQL dump (`postgres-stepui.sql`), CA secrets (`step-ca-data.tgz`), application credentials (`step-ui-data.tgz`), certificates (`step-ui-certs.tgz`), and SHA-256 `manifest.json`.
- **Confidentiality**: The archive contains CA private keys and must be handled with top-level secrecy.
- **Manual Restore Only**: Restore operations are strictly manual via the host CLI as documented in `BACKUP_RESTORE.md`. Under no circumstances should automated restore be added to the Web UI, as an accidental trigger or CSRF could destroy CA keys.
