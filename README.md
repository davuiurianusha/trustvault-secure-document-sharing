# TrustVault — Secure Document Sharing

A starter full-stack Flask website for the Snovasys Fresher Hiring Challenge. It includes registration/login, private uploads, document downloads, user-to-user sharing, access revocation, and a hash-chained audit log.

## Features

- Responsive HTML/CSS interface
- Registration and login with password hashing
- Session-based authentication and CSRF protection
- Private file storage (files are not served as static assets)
- Upload allowlist and 16 MB request limit
- SHA-256 file integrity check on download
- Share with registered users as viewer/editor; revoke access
- Hash-chained audit events and integrity verification page
- SQLite database created automatically

## Run on Windows

1. Install Python 3.11 or newer.
2. Open this folder in VS Code.
3. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt:
   `.venv\Scripts\activate.bat`

4. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

5. Copy `.env.example` to `.env` and replace `SECRET_KEY` with a long random secret. For local development, `FLASK_DEBUG=1` is optional.
6. Start the app:

   ```powershell
   python app.py
   ```

7. Open http://127.0.0.1:5000

## Suggested demo

1. Register User A.
2. Upload a PDF or text file.
3. Register User B in a second browser/incognito session.
4. As User A, share the file with User B's registered email.
5. Log in as User B and download it from Documents.
6. As User A, revoke access and verify User B can no longer download it.
7. Open Audit Trail and run Verify audit chain.

## Important limitations

This is a hackathon prototype, not a production-certified secure document platform. A local SQLite hash chain is tamper-evident for accidental/partial changes, but an administrator able to rewrite the database and recompute every hash may rewrite the entire chain. Production use needs independent signed/checkpointed audit storage, secure secret management, HTTPS, backups, rate limiting, malware scanning, stronger operational controls, and security testing. Only share non-sensitive demo files until the deployment has been reviewed.

The editor role in this starter grants download access and sharing management; it does not allow editing the contents of an uploaded file. The website does not send email notifications.
