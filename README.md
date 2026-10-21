# TrustVault starter

A security-focused starter API for document sharing. It is **not production-ready** until the deployment checklist and threat tests are completed.

## Requirements
- Python 3.11+
- `pip`

## Run locally
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt

# Set separate random secrets (at least 32 characters each).
# PowerShell:
$env:TRUSTVAULT_JWT_SECRET = "replace-with-a-random-secret-at-least-32-chars"
$env:TRUSTVAULT_AUDIT_SECRET = "use-a-different-random-secret-at-least-32-chars"
$env:TRUSTVAULT_BOOTSTRAP = "1"
# macOS/Linux:
# export TRUSTVAULT_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
# export TRUSTVAULT_AUDIT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
# export TRUSTVAULT_BOOTSTRAP=1

uvicorn app:app --reload
```

Open `http://127.0.0.1:8000/docs`. Call `POST /dev/bootstrap` once to create demo accounts:
- admin / `AdminPass-ChangeMe-2026!`
- owner / `OwnerPass-ChangeMe-2026!`
- viewer / `ViewerPass-ChangeMe-2026!`

These credentials are for local demonstration only. Do not deploy them. Disable the bootstrap route and set strong unique secrets before any public deployment. The demo bootstrap only runs when `TRUSTVAULT_BOOTSTRAP=1` and only while no users exist.

## Run tests
```bash
pytest -q
```

## Key authorisation design
- The owner can read/edit/manage their own document.
- A named user with `read` grant can read/download.
- A named user with `edit` grant can read/download/edit metadata.
- Only the owner can grant/revoke access and delete the document.
- Admin can inspect audit events but has no automatic right to document contents.
- Every download checks the current grant. No public URLs or presigned URLs are issued.
- Non-authorised document access returns 404.

## API permissions
| Endpoint | Allowed caller | Purpose |
|---|---|---|
| `POST /auth/login` | Anyone | Login |
| `GET /me` | Authenticated user | Current identity |
| `POST /documents` | Owner | Upload |
| `GET /documents` | Authenticated user | Search only visible documents (admin search is metadata-wide) |
| `GET /documents/{id}` | Owner or read/edit grantee | Metadata |
| `GET /documents/{id}/download` | Owner or read/edit grantee | Download |
| `PATCH /documents/{id}` | Owner or edit grantee | Update metadata |
| `POST /documents/{id}/grants` | Owner only | Grant read/edit |
| `DELETE /documents/{id}/grants/{username}` | Owner only | Revoke |
| `DELETE /documents/{id}` | Owner only | Delete |
| `GET /admin/audit` | Admin | View audit |
| `GET /admin/audit/verify` | Admin | Verify audit chain |
| `POST /dev/bootstrap` | Disabled unless explicitly enabled | Create local demo accounts |

## Before public deployment
1. Disable/remove `/dev/bootstrap`.
2. Use PostgreSQL or another managed database with backups and migrations.
3. Store files in a private bucket or volume with restrictive IAM; never expose the storage directory via a web server.
4. Use HTTPS, secure proxy settings, rate limits, MFA/SSO and account lifecycle controls.
5. Store audit signing keys in a secret manager and export audit events to independently controlled append-only/WORM storage.
6. Add antivirus/content-disarm scanning, retention/deletion recovery, monitoring, alerting and operational runbooks.
7. Review transaction boundaries, concurrency, upload streaming, token revocation and backup/restore.
8. Run the full threat model and independent security review against the deployed build.

See `THREATS.md` and `PROMPTS.md`.
