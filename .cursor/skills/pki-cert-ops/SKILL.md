---
name: pki-cert-ops
description: Implement, modify, or debug certificate issuance, renewal, revocation, and inspection via the step CLI. Use when working on PKI operations, certificate templates, or CA integration.
---

# PKI and Certificate Operations Runbook

Step-CA UI invokes the Smallstep `step` CLI binary inside the `step-ui` container to interact with the `step-ca` service over mutual or root-pinned TLS.

## Core Implementation Files

- **CLI invocation wrappers**: `step-ui-go/handlers/cert_ops.go` (`issueCert`, `revokeStep`, `parseCertDates`)
- **Web handlers**: `step-ui-go/handlers/certs.go` (`IssueGet`, `IssuePost`, `Renew`, `Revoke`, `ImportPost`)
- **Certificate inspection**: `step-ui-go/handlers/cert_details.go` (`CertificateDetails`, `validateCertKeyPair`, `validateCertChain`)
- **Database records**: `step-ui-go/db/db.go` (`certificates` and `cert_history` tables)

## Invariants & Policies

1. **Certificate Templates & Presets**:
   - `server`: Default duration `8760h` (1 year), key type `EC:P-256`.
   - `internal`: Default duration `87600h` (10 years), key type `EC:P-256`.
   - `wildcard`: Requires domain starting with `*.` (e.g. `*.example.com`).
   - `client`: Client identity profile, key type `EC:P-256`.
2. **Allowed Durations & Key Types**:
   - Durations: `720h` (30 days), `4380h` (6 months), `8760h` (1 year), `87600h` (10 years).
   - Key types: `EC:P-256`, `EC:P-384`, `RSA:2048`, `RSA:4096`.
3. **Execution Safety**:
   - Always invoke `exec.Command("step", args...)` with explicit arguments array. Never run unescaped shell concatenation.
   - Use provisioner password file via `--provisioner-password-file cfg.PasswordFile`.
   - Point to CA with `--ca-url cfg.CAURL` and `--root cfg.RootCert`.
4. **Storage & DB Synchronization**:
   - Cert files are saved in `/opt/step-ui/certs/<name>.crt` and `.key`.
   - Record actions in `cert_history` (`issue`, `renew`, `revoke`, `import`) with username and role.

## Verification Checklist

- [ ] Command arguments passed safely via slice.
- [ ] Issued cert and private key written with secure permissions.
- [ ] Database record and history entry created.
- [ ] `cd step-ui-go && gofmt -w . && go vet ./...` passed.
