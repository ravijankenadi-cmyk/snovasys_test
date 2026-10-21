# TrustVault threat model

This is a starter threat model. Update it after testing the deployed build.

## Controls implemented
- **IDOR / insecure direct object references:** every document metadata, download, edit, grant, revoke and delete route checks owner/grant on the server. Unauthorized document routes return 404 to reduce existence disclosure.
- **Permission inherited accidentally from a folder:** no folder inheritance exists; grants are per document.
- **Revocation with stale links:** the application does not issue public or presigned download URLs. Every download checks the current grant.
- **Malicious filenames / path traversal:** storage uses random opaque keys, not user filenames. Filenames are never used to build storage paths.
- **Oversized uploads:** upload reads at most 10 MiB + 1 byte and rejects oversized files.
- **Extension/MIME spoofing:** extension allowlist and basic file-signature checks are applied. This is not a malware scanner.
- **Password disclosure:** Argon2 password hashes are stored; login errors are generic.
- **Token forgery / long-lived token:** signed JWT with an expiry and a secret supplied through environment variables. Token revocation is not implemented; tokens expire after 20 minutes.
- **Audit editing:** HMAC-signed, hash-chained events make ordinary edits detectable if the secret remains protected. This is not immutable storage; a database administrator with the secret can rewrite history.
- **Unauthorized audit access:** only the admin role can read or verify audit events.
- **Search leaking document names:** non-admin searches are constrained to owner documents or explicitly granted documents before filters are applied.

## Known limitations / accepted risks
- Local SQLite and local disk are for a demonstration, not a high-availability deployment.
- Audit events are stored in the same database as application data. Production should export them to separately administered append-only/WORM storage or a remote audit service.
- No MFA, SSO, account lockout, rate limiting, malware scanning, antivirus/CDR, encryption-at-rest key management, or formal incident alerting.
- Login denial events are recorded, but IP addresses are untrusted request metadata unless reverse-proxy handling is configured safely.
- The starter does not implement content versioning, recovery/retention policy, external sharing, or group grants.
- A user who downloads a file can retain a copy; revocation prevents future server access, not deletion of previously downloaded copies.
- Admins can inspect audit data but are not automatically granted document-content access.
- The audit chain is not a substitute for an independent trusted timestamp or external append-only log.
- The starter uses a synchronous local file write inside an async route; for production use streaming upload handling and robust cleanup/transaction patterns.
- SQLite concurrency and multi-worker behavior need review before production use.

## Attack tests to add before deployment
- Remove the authorization call in `download_document`; `test_other_owner_cannot_read_download_edit_or_delete` must fail.
- Try guessed document IDs against metadata, download, patch, delete, grant and revoke routes.
- Revoke a grant, then reuse the same token and URL; access must fail.
- Try an inactive user, expired token, malformed token and wrong role.
- Try oversized files, mismatched signatures, path-like names and unsupported extensions.
- Modify an old audit event and verify `/admin/audit/verify` detects it.
- Attempt to access admin audit endpoints as owner/viewer.
- Test concurrent grant/revoke and download requests; define the exact revocation linearization point.
