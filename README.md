# Notesly

Notesly is a full-stack student notes community. Accounts, notes, moderation, likes, saves, follows, comments, and notifications are stored in SQLite. Note files are kept on the server's data directory and become viewable to signed-in users after approval.

## Run locally

Requires Python 3.10 or newer. The app has no third-party packages.

```powershell
$env:NOTESLY_ADMIN_EMAIL = "admin@example.com"
$env:NOTESLY_ADMIN_PASSWORD = Read-Host "Choose a strong admin password"
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Students create accounts from the sign-in page. Use the configured admin account to open **Review desk**, check suggested title duplicates, and publish or decline submissions. For a new admin account after first startup, stop the server, set the environment variables, and start it again.

By default, SQLite and uploaded files are stored under `data/`. Set `NOTESLY_DATA_DIR` to use another persistent directory, `PORT` to change the port, and `NOTESLY_COOKIE_SECURE=1` when serving through HTTPS. `NOTESLY_HOST` defaults to `127.0.0.1` for local use.

## Included workflows

- Create an account, sign in, and sign out. Passwords are stored as PBKDF2 hashes; sessions use HTTP-only cookies.
- Submit a note by class, subject, and topic, with a description and optional JPG, PNG, WebP, GIF, or PDF attachment (10 MB maximum).
- Review submissions in an admin-only queue. Similar titles in the same class and subject are flagged for review. Approvals publish to the feed; declined submissions stay out of the feed.
- Search and filter published notes; sort by newest or popularity; like, save, comment on, and follow student contributors.
- Receive notifications when a note is approved or declined, or when another student comments on your note.

## Before public deployment

This is a working single-server MVP, not yet a hardened multi-server production service. Use HTTPS, set a strong admin password, back up the SQLite database and `uploads` directory together, and put the app behind a production WSGI/ASGI server and reverse proxy before exposing it publicly. Add email verification, password reset, rate limiting, and an explicit privacy/moderation policy before opening registration broadly. `python server.py` is intended for local development.
