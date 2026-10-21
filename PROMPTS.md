# AI use log

Keep this file updated during the project. The entries below are a template, not evidence of work already completed. Replace each placeholder with the actual date, prompt, output, specific defect found, corrective change, and real commit URL. Do not claim a commit or test that does not exist.

## Entry 1 — YYYY-MM-DD — Authorisation review
- **Prompt:** Ask AI to review every document endpoint for object-level authorisation and list bypass paths.
- **AI output:** [Summarise the actual output.]
- **What was wrong:** [Name a specific missed endpoint, incorrect assumption, or explain the code and tests you checked if no defect was found.]
- **What I changed:** [Describe the fix and the test that proves it.]
- **Commit:** [real commit URL]

## Entry 2 — YYYY-MM-DD — Revocation semantics
- **Prompt:** Ask AI whether revoking a document grant immediately blocks old links and existing tokens.
- **AI output:** [Summarise actual output.]
- **What was wrong:** [For example, identify any proposed presigned/public URL or cached authorization decision, if that occurred.]
- **What I changed:** [Describe actual fix and test.]
- **Commit:** [real commit URL]

## Entry 3 — YYYY-MM-DD — Audit integrity
- **Prompt:** Ask AI to design a tamper-evident audit log and adversarial verification tests.
- **AI output:** [Summarise actual output.]
- **What was wrong:** [Explain the limits of a hash chain if the database and signing secret are both compromised.]
- **What I changed:** [Describe actual fix/test and remaining risk.]
- **Commit:** [real commit URL]

## Entry 4 — YYYY-MM-DD — Upload validation
- **Prompt:** Ask AI to review upload validation for path traversal, content spoofing and resource exhaustion.
- **AI output:** [Summarise actual output.]
- **What was wrong:** [Specific defect found during review.]
- **What I changed:** [Actual fix and test.]
- **Commit:** [real commit URL]

## Entry 5 — YYYY-MM-DD — Cross-user tests
- **Prompt:** Ask AI to propose adversarial tests for IDOR across metadata, download, edit, delete and sharing routes.
- **AI output:** [Summarise actual output.]
- **What was wrong:** [Specific missing case or a test that would pass even if a guard were removed.]
- **What I changed:** [Actual fix and test.]
- **Commit:** [real commit URL]

## Reusable project instruction
Treat every document ID and every client-supplied filename as untrusted. Enforce object-level authorisation on the server for every request. Default deny. Do not issue public/presigned file URLs. Test negative cases by authenticating as a different user. Do not call a log immutable unless it is protected independently from the application and database administrators.
