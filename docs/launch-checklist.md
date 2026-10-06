# Launch checklist (free public release)

Goal: anyone can download the macOS app from the website and use SVX for
free. No payments, no premium plans. Written 2026-10-05.

Legend: `[ ]` open, `[x]` done.

## Where things stand

- [x] Website built (`website/`) and live on a Cloudflare `workers.dev` address
- [x] Azure server created (Ubuntu 24.04, B2ats_v2, Central India's allowed region), <server-ip>
- [x] Server hardened: key-only SSH, no root login, firewall (SSH only), swap, updates, rebooted
- [x] PostgreSQL 16 on the server (local only), role and database `svx`
- [x] `svx-server` and `svx` built for Linux and installed; keys created on the server
- [x] Service runs under systemd (restarts on failure, starts at boot) on `127.0.0.1:8443`
- [x] Key backup copied to the Mac (`~/.svx-service-backup/`)
- [x] Domain `getsvx.me` registered (Namecheap, free for 1 year via the GitHub Student Pack)
- [x] Domain added to Cloudflare (Free plan), nameservers changed at Namecheap
- [x] Cloudflare shows the domain **Active** (2026-10-05); no GitHub Pages records left
- [x] Service public at `https://api.getsvx.me:8443` (Cloudflare proxy, SSL mode Full), direct IP access blocked
- [x] Two-factor sign-in on Namecheap and Azure
- [ ] Two-factor sign-in on Cloudflare (needs the password reset first)

Fingerprints built into the app (not secret):
- registry key: `7e37ca3363edce95a7f823e9df8454bb0fa9af93b531ccdf8bae98cbf56948a0`
- release key (`SVX_RELEASE_KEY`): `2aff61166fa62af77e7f89d8b349cf1a9ee5fd1179619b1a93dd8f59c04b8bf6`

## A. Make the service public

No card needed: we skipped Cloudflare Tunnel (Zero Trust wants a card) and use the proxy on port 8443 instead. Public address: `https://api.getsvx.me:8443` (Cloudflare proxies 8443 on the free plan, not plain 443).

| | Step |
|---|---|
| [x] | ~~A1. Delete the GitHub Pages `A` records and the `www` `CNAME` (checked: none left)~~ |
| [x] | ~~A2. Domain shows **Active** in Cloudflare~~ |
| [x] | ~~A3. Public hostname: `api` A record (proxied) → server, SSL mode Full, service listens on `0.0.0.0:8443`, server firewall (ufw) allows 8443 only from Cloudflare's ranges, Azure inbound rule `cloudflare-8443`~~ |
| [ ] | A4. SSH (port 22) closed to the internet or limited to your IP (keep a recovery path: Azure serial console). Optional for the beta: key-only login is already enforced |
| [x] | ~~A5. Gmail account `<notification-mailbox>` with an app password in `/etc/svx/smtp.env` (set by a command you ran; never in chat). Test code email arrived (2026-10-06); first mails may land in spam, so the app and the docs say "check Spam, mark Not spam"~~ |
| [ ] | A6. Optional: Google OAuth client for Google sign-in (`--personal-idp`). Email sign-up works without it |
| [x] | ~~A7. `https://api.getsvx.me:8443/v1/service` answers `200` from outside the server~~ (optional: open it once on your phone's mobile data) |

## B. Make it safe to open to everyone

| | Step |
|---|---|
| [x] | ~~B1. Abuse limits: per address (requests, codes, new accounts, registrations, registry lookups), per account (files, opens, share requests), daily email budget (450). No file-size cap needed: files never reach the service~~ |
| [x] | ~~B2. `svx-admin` on the server: `stats`, `users --search`, `user`, `suspend`, `unsuspend`, `delete --yes` (see `deploy/service/README.md`)~~ |
| [x] | ~~B3. Nightly encrypted database dump (age, 14 kept, 03:30 IST); `scripts/pull-backup.sh [--drill]` copies it to your Mac; restore drill passed 2026-10-06. Your part: run `scripts/pull-backup.sh` weekly and keep `db-backup-age.key` offline with the other backups~~ |
| [~] | B4. On-server health check every 5 minutes (service, database, disk, memory, backup age) emails `<notification-mailbox>` per problem and when cleared: installed and tested. **Still to do (you): an outside monitor** for when the whole server is down (free UptimeRobot on `https://api.getsvx.me:8443/healthz`, alert to your email) |
| [x] | ~~B2b. Private admin page: `scripts/admin.sh` opens `svx-admin web` through an SSH forward (installed 2026-10-06). **You:** allow that one forward on the server (`deploy/service/README.md`, "Admin page"), then run the script~~ Working (2026-10-06), with Logs and Announcements tabs |
| [ ] | B5. Copy **both** backups to a second, offline place (USB or encrypted cloud folder): `~/.svx-service-backup/` (service keys, `db-backup-age.key` and the database backups) and `~/.svx-release/` (release and updater keys). **Without the service KEM key, every file ever sent is unreadable; without the release keys, installed apps can't be updated.** Practise restoring once |
| [x] | ~~B6. Security re-check (2026-10-05): open ports (22 key-only, 8443 Cloudflare-only, Postgres local), key and config permissions, SCRAM, unattended upgrades, service sandbox tightened (systemd exposure 4.3 → 1.4), SSH forwarding off and 3 auth tries, abuse limits live behind `CF-Connecting-IP`~~ |
| [ ] | B7. Follow-ups from B6: (a) Cloudflare **Full (strict)** with a free Cloudflare Origin certificate (make a CSR on the server, paste it in SSL/TLS → Origin Server, install the certificate; the private key never leaves the server), so the Cloudflare → server hop is authenticated too; (b) once SMTP works, clear the old journal (it holds the sign-up codes logged while email was off): `sudo journalctl --rotate && sudo journalctl --vacuum-time=1s`; (c) re-sync ufw with Cloudflare's IP list every few months |

## C. Build the official app

| | Step |
|---|---|
| [x] | ~~C1. Release key and Tauri updater key: already in `~/.svx-release` (made 2026-10-04, never left the Mac); the updater public key matches `tauri.conf.json`; fingerprint above. Offline backup is part of B5~~ |
| [x] | ~~C2. Version 0.1.0 built for Apple silicon with the official service (`https://api.getsvx.me:8443`), registry fingerprint, release key and update address built in (`scripts/release.sh 0.1.0 --update-url … --service-url … --registry-fingerprint …`); signed manifest verified. Files in `dist-release/` (not in git): `download/SVX-beta-macOS.dmg` (SHA-256 `63b881a20a07e52d2236ddb0ec6b9f25a163ad8b5a756f98b71da2fbbd702302`, local build; a different build gets a different checksum) and `0.1.0/` (update package + manifest, for the server's updates folder)~~ |
| [ ] | C3. First-run check on a clean Mac user account |
| [x] | ~~C4. Update test: the installed app updated itself through 0.1.1 → 0.1.5 (2026-10-06); releases are signed with one certificate (`scripts/make-signing-cert.sh`) so updates keep keychain access~~ |

## D. Your manual tests

- [ ] macOS capture probe: `cargo run -p svx-desktop --example viewer_probe` (decides the "blocks screenshots" claim)
- [ ] View-only for real: PDF, photo and `.docx`; copy, save and print do nothing; the watermark shows
- [ ] Share request: the recipient asks to keep a copy, the sender approves
- [ ] Two real accounts over the internet (phone data): sign up with an emailed code, send, approve, open, revoke
- [ ] The Phase 7 security changes: the main app and the viewer still work after the new per-window permissions
- [ ] Password reset, sign-in on a second device, key backup restore
- [ ] Any bug found goes on the issue list

## E. Website and legal

| | Step |
|---|---|
| [x] | ~~E1. Website on `getsvx.me` and `www.getsvx.me` (workers.dev switched off; account subdomain no longer has your name; checked 2026-10-06)~~ |
| [ ] | E2a. **Upload the site, then run `scripts/check-site.sh`** (tests the pages, `install.sh`, the disk image and its checksum, security.txt and the service as a new user's Mac would). Every line must say ok before anyone is told about the site. After each new app build: `scripts/release.sh …` then `scripts/prepare-download.sh`, upload, check again |
| [x] | ~~E2. Add the download link and SHA-256, set `RELEASE = 'live'` in `website/assets/js/boot.js`, show Windows and Linux as "coming soon"~~ |
| [ ] | E3. Adjust claims to the test results (macOS capture; view-only status wording) |
| [ ] | E4. Fill in Privacy and Terms (operator name or "individual developer", contact, retention) and have someone qualified review them |
| [x] | ~~E5. Email Routing: `support@getsvx.me` and `security@getsvx.me` forward to `<notification-mailbox>`; catch-all off; tested, arrives in the inbox (2026-10-06)~~ |
| [~] | E5b (done in the files, **upload the site to publish it**). **Put the contact addresses on the website**: `support@getsvx.me` and `security@getsvx.me` in the footer of every page, a Contact line on the download and docs pages, "Report a vulnerability" on the security page, the Contact sections of privacy and terms, and a `/.well-known/security.txt` (`Contact: mailto:security@getsvx.me`). Mention them in the app (Settings → About) and in the sign-up emails' footer if wanted |
| [ ] | E6. Delete the temporary `resources/` folder; commit `website/`, `deploy/service/` and the docs |
| [ ] | E7. Decide the licence and whether the GitHub repository is public. The code is Apache-2.0 today, so anyone may run their own service |
| [x] | ~~E8. `workers.dev` address switched off; the account subdomain is now `getsvx`~~ |

## F. Launch

- [ ] Friends beta: 3–5 people for about a week; watch the server log and your inbox; fix what comes up
- [ ] Public release: publish the link
- [ ] Calendar reminders:
  - [ ] about 1 month before **Oct 5, 2027**: the domain's free year ends (renew or move it to Cloudflare) and the Azure credit ends (move or pay for the server)
  - [ ] about 9 months from now: GitHub student status needs re-verifying

## Requested features (later, not started)

Asked for on 2026-10-06; plan first when picked up.

- [x] ~~**Logs page in the admin page:** recent service activity (sign-ups,
      sends, opens, refusals, admin actions) with filters. Never file names
      or contents (the service doesn't have them).~~ Built 2026-10-06 (Logs tab).
- [x] ~~**Announcements from the admin page:** write an email (for example a
      new release and its features) and send it to all users or to chosen
      ones, with optional attachments (files, documents). Needs: the daily
      email budget (Gmail ~500/day: send in batches over several days, or
      move to a bulk email service), an unsubscribe option and a line in
      the privacy policy, attachment size limits, and a preview/test send
      to yourself first.~~ Built 2026-10-06 (Announcements tab, shared
      email counter in `email_sends`, 400/day for announcements, optional
      queue, reply-to-unsubscribe).

## Cost

Now: about ₹0 (student offers). After the free periods: about ₹600–1,500 a
year for the domain, and about $7–8 a month for the server if kept on Azure.

## Known limits to keep stating honestly

- View-only blocks saving, copying and screenshots in the app; it cannot stop a photo of the screen
- Windows screenshot blocking is untested; Linux refuses to show view-only files
- Revocation stops future access; it cannot recall a file already opened
- Installers are unsigned: the first launch shows an "unidentified developer" warning
- The service is trusted to enforce approval, one-time limits and revocation; it cannot decrypt a file alone
- Windows and Linux installers need a build machine (GitHub's automated build) and testing; launch with macOS only
