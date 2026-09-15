# API & Route Contracts

All routes are registered in `step-ui-go/main.go` using the `chi/v5` router.

## Session & Authentication Model

- **Session Storage**: `gorilla/sessions` encrypted cookie (`step-ui`).
- **Sliding Timeout**: 8 hours (`SessionTimeout = 8 * time.Hour`). Inactive sessions expire automatically.
- **CSRF Token**: Stored in session (`csrf_token`). Required on all POST requests.
- **Role Hierarchy**: `viewer` (1) < `manager` (2) < `admin` (3).

## Routes Reference Table

### Public Routes

| Method | Path | Min Role | CSRF | Handler | Description |
|---|---|---|---|---|---|
| `GET` | `/login` | Public | No | `h.LoginGet` | Render login form |
| `POST` | `/login` | Public | Yes | `h.LoginPost` | Authenticate user (rate limited) |
| `GET` | `/forgot-password` | Public | No | `h.ForgotPasswordGet` | Password recovery request form |
| `POST` | `/forgot-password` | Public | Yes | `h.ForgotPasswordPost` | Send reset link (neutral response) |
| `GET` | `/reset-password` | Public | No | `h.ResetPasswordGet` | Reset password form (token-validated) |
| `POST` | `/reset-password` | Public | Yes | `h.ResetPasswordPost` | Set new password |
| `GET` | `/logout` | Public | No | `h.Logout` | Terminate session |

### Authenticated Routes (Viewer Role & Above)

| Method | Path | Min Role | CSRF | Handler | Description |
|---|---|---|---|---|---|
| `GET` | `/` | `viewer` | No | `h.Home` | Home status and quick statistics |
| `GET` | `/dashboard` | `viewer` | No | `h.Dashboard` | Certificate overview metrics |
| `GET` | `/api/status` | `viewer` | No | `h.APIStatus` | JSON health endpoint |
| `GET` | `/certificates` | `viewer` | No | `h.Certificates` | Certificate list and filters |
| `GET` | `/certificates/{id}` | `viewer` | No | `h.CertificateDetails` | Detailed certificate inspection |
| `GET` | `/history` | `viewer` | No | `h.History` | Certificate operations history |
| `GET` | `/provisioners` | `viewer` | No | `h.Provisioners` | CA provisioners list |
| `GET` | `/profile` | `viewer` | No | `h.ProfileGet` | User profile page |
| `POST` | `/profile` | `viewer` | Yes | `h.ProfilePost` | Update display name / theme / password |
| `GET` | `/profile/2fa` | `viewer` | No | `h.Profile2FAGet` | 2FA configuration page |
| `POST` | `/profile/2fa/start` | `viewer` | Yes | `h.Profile2FAStart` | Initiate TOTP enrollment |
| `GET` | `/profile/2fa/qr` | `viewer` | No | `h.Profile2FAQR` | Generate QR code PNG |
| `POST` | `/profile/2fa/confirm` | `viewer` | Yes | `h.Profile2FAConfirm` | Verify code and enable 2FA |
| `POST` | `/profile/2fa/disable` | `viewer` | Yes | `h.Profile2FADisable` | Disable 2FA |

### Manager Routes (Manager Role & Above)

| Method | Path | Min Role | CSRF | Handler | Description |
|---|---|---|---|---|---|
| `GET` | `/issue` | `manager` | No | `h.IssueGet` | Form to issue certificate |
| `POST` | `/issue` | `manager` | Yes | `h.IssuePost` | Issue certificate via step CLI |
| `GET` | `/renew/{id}` | `manager` | No | `h.Renew` | Renew active certificate |
| `GET` | `/import` | `manager` | No | `h.ImportGet` | Certificate import page |
| `POST` | `/import` | `manager` | Yes | `h.ImportPost` | Import existing certificate |
| `GET` | `/download/cert/{id}` | `manager` | No | `h.DownloadCert` | Download public certificate file |
| `GET` | `/download/key/{id}` | `manager` | No | `h.DownloadKey` | Download private key file |
| `GET` | `/le` | `manager` | No | `h.LEDashboard` | Let's Encrypt dashboard |
| `GET` | `/le/issue` | `manager` | No | `h.LEIssueGet` | Let's Encrypt issue form |
| `POST` | `/le/issue` | `manager` | Yes | `h.LEIssuePost` | Request Let's Encrypt certificate |
| `POST` | `/le/{id}/renew` | `manager` | Yes | `h.LERenew` | Trigger LE manual renew |
| `POST` | `/le/{id}/delete` | `manager` | Yes | `h.LEDelete` | Remove LE certificate record |
| `POST` | `/le/{id}/autorenew` | `manager` | Yes | `h.LEToggleAutoRenew`| Toggle auto-renewal flag |
| `GET` | `/le/download/cert/{id}` | `manager` | No | `h.LEDownloadCert` | Download LE certificate |
| `GET` | `/le/download/key/{id}` | `manager` | No | `h.LEDownloadKey` | Download LE private key |
| `GET` | `/le/settings` | `manager` | No | `h.LESettingsGet` | DNS provider & ACME settings |
| `POST` | `/le/settings` | `manager` | Yes | `h.LESettingsPost` | Save LE settings |
| `GET` | `/le/logs` | `manager` | No | `h.LELogs` | View LE renewal logs |

### Admin Routes (Admin Role Only)

| Method | Path | Min Role | CSRF | Handler | Description |
|---|---|---|---|---|---|
| `GET` | `/download/ca` | `admin` | No | `h.DownloadCA` | Download CA root certificate |
| `GET` | `/download/intermediate-ca` | `admin` | No | `h.DownloadIntermediateCA` | Download intermediate CA |
| `GET` | `/download/full-chain` | `admin` | No | `h.DownloadFullChain` | Download complete CA chain |
| `GET` | `/revoke/{id}` | `admin` | No | `h.Revoke` | Revoke certificate via step CLI |
| `GET` | `/admin` | `admin` | No | `h.AdminGet` | Admin dashboard overview |
| `GET` | `/admin/users` | `admin` | No | `h.Users` | User management table |
| `POST` | `/admin/users` | `admin` | Yes | `h.UsersPost` | Create or update regular user |
| `GET` | `/admin/users/{id}` | `admin` | No | `h.UserProfile` | View/edit specific user profile |
| `GET` | `/admin/users-temp` | `admin` | No | `h.AdminUsersTempGet`| Manage temporary accounts |
| `POST` | `/admin/users-temp` | `admin` | Yes | `h.AdminUsersTempPost`| Create expiring guest user |
| `GET` | `/admin/activity` | `admin` | No | `h.AdminActivityGet` | View administrative audit log |
| `GET` | `/admin/security` | `admin` | No | `h.SecurityLog` | View authentication security log |
| `GET` | `/admin/console` | `admin` | No | `h.AdminConsoleGet` | Restricted web diagnostic console |
| `POST` | `/admin/console` | `admin` | Yes | `h.AdminConsolePost` | Run allowlisted diagnostic command |
| `GET` | `/admin/about` | `admin` | No | `h.AdminAboutGet` | System version and environment info |
| `GET` | `/admin/integrity` | `admin` | No | `h.AdminIntegrityGet`| CA chain and password integrity check |
| `GET` | `/admin/backup` | `admin` | No | `h.AdminBackupGet` | Backup export overview |
| `POST` | `/admin/backup/download` | `admin` | Yes | `h.AdminBackupDownload`| Export encrypted backup archive |
| `GET` | `/admin/notifications` | `admin` | No | `h.AdminNotificationsGet` | Webhook and alert configuration |
| `POST` | `/admin/notifications` | `admin` | Yes | `h.AdminNotificationsPost` | Save notification preferences |
| `POST` | `/admin/notifications/test`| `admin` | Yes | `h.AdminNotificationsTest` | Dispatch test webhook alert |
| `GET` | `/admin/ca` | `admin` | No | `h.AdminCAGet` | Dual CA mode and connection settings |
| `POST` | `/admin/ca` | `admin` | Yes | `h.AdminCAPost` | Save CA settings and upload PEM certs |
| `POST` | `/admin/ca/test` | `admin` | Yes | `h.AdminCATestPost` | Verify connection to configured CA |
