---
name: navigate-project
description: Locate routes, handlers, templates, database queries, and deployment scripts in the Step-CA UI repository. Use when starting a task, finding where a feature is implemented, or exploring the codebase.
---

# Navigating Step-CA UI Codebase

Follow this procedure to locate code rapidly without scanning non-source directories.

## Workflow

1. **Find the Route**:
   - Check `step-ui-go/main.go` for the URL path.
   - Note the chi router group to identify required authentication and role (`viewer`, `manager`, `admin`).
2. **Find the Handler**:
   - Trace the handler method in `step-ui-go/handlers/*.go`:
     - Certificates & PKI: `certs.go`, `cert_ops.go`, `cert_details.go`
     - Auth, Profile & 2FA: `auth.go`, `totp.go`, `password_reset.go`
     - Admin & Operations: `admin.go`, `users.go`, `admin_temp.go`, `admin_console.go`, `backup.go`, `health.go`
     - Let's Encrypt: `le.go`, `le/lego.go`, `le/renewer.go`
     - Notifications & Webhooks: `notifications.go`
3. **Find the Template and Assets**:
   - Check the template name passed to `h.render(w, "name", data)`.
   - Template file is `step-ui-go/templates/<name>.html`.
   - Base wrapper: `templates/admin_base.html` if prefixed with `admin_` or is `"admin"`; otherwise `templates/base.html`.
   - Associated JS/CSS is in `step-ui-go/static/js/` and `step-ui-go/static/css/`.
4. **Find the Database Operations**:
   - Query functions are located in `step-ui-go/db/*.go`.
   - Schema creation and column additions are in `InitSchema`, `InitLESchema`, `InitNotificationSchema`, `InitPasswordResetSchema`.

## Avoid Common Pitfalls

- Do NOT scan `.env`, `credentials.txt`, `ssl/`, or `backups/`.
- Do NOT search for external frontend framework entry points (no React, Vue, or webpack).
- All templates and static files are served directly by Go without precompilation.
