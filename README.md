# Notesly

Notesly is a student notes-sharing community concept. It includes a responsive study feed, class and subject discovery, search, likes, saved notes, a note submission flow, and a lightweight review desk that flags likely title duplicates before an admin publishes a submission.

## Run locally

Open `index.html` in a modern browser. No build step or dependencies are required.

## Prototype notes

- Feed content and moderation actions are demonstration data stored in the browser. Saved notes and pending review submissions use `localStorage` on the current device.
- The upload picker validates file size and type in the browser, but uploaded file bytes are not sent or retained. Production deployment needs accounts, secure file storage, a database, and server-side duplicate detection and moderation.
- The review desk is a front-end prototype, not an authenticated administrator system.
