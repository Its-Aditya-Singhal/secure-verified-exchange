# Personal accounts (Phase 5d)

Anyone can use SVX without company IT: sign in with Google, or create an
account with an email address and a password, send
files to email addresses, and keep control of each file after sending it.
Company setup is still available ("Company or test server setup" on the
welcome screen).

All people and addresses here are fictional (`alice@example.test`,
`bob@example.test`).

## What a person sees

1. **Welcome.** "Continue with Google", or "Create account with email"
   (first name, last name, email, password twice, with a live strength
   meter, then the 6-digit code emailed to that address). The app makes
   this device's keys and keeps them in the system keychain. It then
   suggests saving one encrypted backup, locked with a recovery password.
2. **Send.** Pick a file or folder, type email addresses (each is checked
   in the signed directory), and choose:
   - **Ask me before each open** (on by default);
   - **One-time** (on by default): each person can open it once;
   - an optional expiry.

   The `.svx` file can then travel any way: email, chat, a USB stick.
3. **Open.** Double-click the `.svx` file. The app verifies it, then asks
   the service. If the sender wants to approve, the timeline shows
   "Waiting for alice@example.test to approve" until they do (or the
   recipient stops waiting).
4. **Requests.** The sender sees "bob@example.test wants to open
   report.pdf" in the app (and gets an email without file name or link),
   checks by phone or in person that it's really Bob, and approves or
   declines **in the app**.
5. **History.** Files sent and received, with who, when and what happened.
   A sent file's page shows each recipient's state and lets the sender
   switch approval and one-time on or off, bring the expiry forward, revoke
   one person or everyone, or send a new copy.
6. **Settings.** Account, key IDs, backup, reset keys, sign out, output
   folder, "Confirm it's you" (Touch ID / password, see
   [desktop.md](desktop.md)) and, for email accounts, change password.

## How it works

A personal account is a one-person organization (`orgs.kind = 'personal'`,
ID `u.<16 hex>`). Everything that protects company files protects personal
files too: signed registry records, sender verification, the service's
share of every file key, audit and revocation.

| Piece | Company | Personal |
|-------|---------|----------|
| Who signs in | company IdP, every open | Google, or email + password + emailed code, once per device |
| Recipient's half of the key | the org's key agent | the person's own MLKEM1024-P384 key, in their keychain |
| Who decides | the recipient org's policy | the sender's per-file rules |
| Requests to the service | ID token bound to the open | signed with the device key |

### Sign-up

1. The app generates an SVX-2 signing key (Ed25519 + ML-DSA-87 + SLH-DSA)
   and an MLKEM1024-P384 encryption key.
2. It signs in with Google (browser, PKCE) asking for an ID token
   whose `nonce` is `signup_nonce(signing_public, kem_public)`, so a
   captured token can't register anyone else's keys.
3. `POST /v1/accounts`: the service checks the token, requires a verified
   email, and creates the account bound to the provider's `(issuer, sub)`.
   The email goes into the account's **signed** registry record
   (`account_email`), so "this email has these keys" is signed by the
   registry key every client pins.
4. On another device the same sign-in gets `account_exists`: restore the
   backup (same keys, accepted) or reset (new keys; the old ones retire, so
   files sent to them can't be opened any more). A backup's keys can't be
   registered to a different account.

### Signed requests

After sign-up, the app signs every request with the device key instead of
signing in again:

```
SVX-1 account request\0 ‖ METHOD \n path?query \n hex(SHA-256(body)) \n time \n hex(nonce) \n account \n hex(key_id)
```

Headers `svx-account`, `svx-key-id`, `svx-time`, `svx-nonce`,
`svx-signature`. The service accepts a request only with an active hybrid
signing key of that account, within 60 seconds of its clock, and once per
nonce. Proxies must not rewrite the path (the signature covers it).

### Sending

`svx_client::personal` looks each email up (`GET /v1/directory?email=`),
checks the signed record and that its email matches, and seals the file
(format 1.2) with one recipient envelope per person, all holding the same
recipient half. Before the file is written, it registers the file and its
rules (`POST /v1/me/files`). An unregistered personal file never opens.

File names never leave the device: the service knows file IDs, accounts
and times only. The app keeps names in a local `history.json`.

### Opening

1. Verify the file locally against the sender's signed record.
2. Check it is addressed to this account and sealed to this device's key.
3. `POST /v1/personal/release` with a fresh MLKEM1024-P384 one-time key. The
   service checks, in order: a registered file with this exact header; the
   caller is a named and registered recipient; revocation (file or
   person); expiry (the earlier of the signed and the sender's); one-time
   use; the sender's approval; a single-use transaction.
4. If approval is needed, the answer is `pending`; the app repeats the same
   request (freshly signed) every few seconds. An approval is valid for 24
   hours for that person and file.
5. The service share arrives sealed to the one-time key. The app unseals
   its own half with the keychain key and decrypts locally, as always.
6. A receipt (`POST /v1/personal/opened`) makes a one-time open final at
   once; without it the open becomes final 10 minutes after release (so a
   crash mid-decryption can be retried).

### Email accounts

For people who don't use Google, the service is its own sign-in provider
(issuer `svx:email`; the account is bound to the lower-cased address).
Proving the address is what matters, because the directory sends files to
whoever owns `bob@…`. So every step that binds keys to an account needs a
**fresh code emailed to that address**, and an existing account also needs
its **password**:

| Step | Needs |
|------|-------|
| Create the account | code (`sign_up`), first and last name, a strong password |
| Sign in on a new computer, or reset keys | code (`sign_in`) + password; then the backup, or a key reset |
| Forgot password | code (`reset_password`) + a strong new password; keys are not touched |
| Change password | the signed-in device + current password |

1. `POST /v1/auth/email/code {email, purpose}` → `{challenge, expires_at}`.
   The code is 6 random digits, valid for 10 minutes, at most 5 tries
   (right or wrong), used once. The service keeps only
   `SHA-256("SVX email code\0" ‖ challenge ‖ code)`, never the code, and
   the email holds the code and nothing else (no link). An address gets at
   most 5 codes an hour, 30 seconds apart; the whole service at most 120 a
   minute. The answer is the same whether or not an account exists:
   sign-in and reset codes are only sent to email accounts.
2. `POST /v1/accounts/email {challenge, code, email, password, first_name,
   last_name, signing_public, kem_public, keys}`. The same key checks as
   Google sign-up (SVX-2 kinds, a backup's keys belong to their account,
   `account_exists` for other keys unless `keys: "reset"`).

**Passwords** must be 12–128 characters, score at least 3 of 4 on
[zxcvbn](https://github.com/dropbox/zxcvbn) (which refuses common
passwords, keyboard patterns, dates and the like) and not be built from
the person's own name or email. One check in `svx-protocol`
(`password_strength`) drives the app's live meter and is enforced again by
the service, so bypassing the app doesn't help. The service stores
Argon2id hashes (64 MiB, 3 passes; costs stored with each hash). Ten wrong
passwords in a row lock the account for 15 minutes.

Names are shown to recipients next to the verified email, as
`Alice Example <alice@example.test>`. Only the email is verified; a name
can't contain `@`, `<` or `>`, so it can't pose as another address.

The password doesn't encrypt anything: files are protected by the device
keys, as for Google accounts. It only guards registering keys.

### Backups

`*.svxbackup`: both private keys, encrypted with ChaCha20-Poly1305 under a
key derived from the recovery password with Argon2id (256 MiB, 4 passes; older 64 MiB backups still open).
The file is owner-only and never overwritten. There is no password
recovery.

## View-only files (Phase 7)

A sender can mark a file **view-only**: recipients see it inside the SVX desktop app, in a window that screenshots and recordings can't capture, with no copy, save or print, until the sender allows a copy. The honest limits are below and in the threat model (T29).

**Sending.** In the app, **View only** is a switch on the Send screen (with **Let them ask to keep a copy**); on the command line, `svx send --view-only [--allow-share-requests]`. It works for PDF, images (PNG, JPEG, GIF, WebP), plain text and Office files (Word, Excel, PowerPoint, OpenDocument, RTF). Office files are converted to PDF **on the sender's computer** with LibreOffice (free; the app and CLI say so if it isn't installed) from the sender's own file; the recipient never parses an Office format, and **keep a copy** gives them the original. Folders and other types can't be view-only. The flag is signed into the file (format 1.4), so older apps and the SDKs refuse it instead of saving it.

**Viewing.** Opening a view-only file in the app asks the service as usual (including the sender's approval, if required), then decrypts **only into memory** and draws it in a separate protected window: pages arrive as pictures, each carrying the viewer's email, the time and a short file ID burned in. Nothing is written to disk, so **every view asks the service again**: revoking, expiring or changing a rule takes effect on the next view. A one-time view-only file can be viewed once, and then can't be saved either (the same "used up" applies), so turn one-time off if recipients should be able to ask for a copy later. **Linux can't show view-only files** (it has no way to keep the window out of screenshots), and says so before anything is decrypted. Windows capture blocking is untested.

**Keeping a copy.** In the viewer, **Ask to keep a copy** (or `svx keep FILE`) sends the sender a request, marked as a request to keep a copy, in Requests. They check it's really them and approve or decline; an approval lasts 24 hours, a decline stands for 24 hours, and emails name the requester only. After an approval, **Save a copy** (or `svx open FILE`) writes the sender's original as an ordinary file, and that can't be taken back.

**The sender's controls.** On the file page (History → the file), **View only** can be lifted at any time (with a confirmation: everyone who opens it can then save it) and switched back on only for a file that was sent view-only; **Let them ask to keep a copy** can be switched either way. `svx file ID --view-only on|off --share-requests on|off` does the same. A "view only" badge marks these files in History.

**How it's enforced.**
- The rules `view_only` and `allow_share_requests` live on the service with the other per-file rules. A release asks to `save` or to `view`; the service refuses a `save` of a view-only file (`view_only`, before anything is used up) unless the sender allowed it, and registers a file only with the rule that matches the signed flag.
- Each step is in the audit trail (`share_requested`, `share_granted`, `share_declined`).
- Viewing runs in `svx_client::Client::view_personal`; drawing is `svx-viewer`; the protected window is in the desktop shell. No security decision is made in the web layer.

**What it can't do:** stop a photo of the screen, a modified app (the app is unsigned, so the service can't tell), malware on the recipient's computer, or capture tools that ignore the operating system's flag. Treat view-only as strong friction plus accountability (the watermark), not as a guarantee against a determined recipient. Details and tests: threat model T29.

## Limits

- **One-time stops re-opening, not copying.** The copy a recipient
  decrypted is ordinary data on their computer.
- **Recipients can't be added after sending:** their halves are sealed
  into the file. "Send a new copy" makes a new file.
- **Revocation and expiry stop future opens.** They can't recall plaintext
  already opened.
- **A stolen unlocked device** can open files sent to that account, subject
  to the senders' rules (approval, one-time). Reset the keys from another
  device to stop it.
- **Approving the wrong person** is the main social-engineering risk. The
  app asks the sender to confirm by another channel, and emails never
  contain links.

## Running it locally

```sh
cargo run -p svx-demo -- serve --state-dir /tmp/svx-stack
```

It prints the dev "Google" accounts (alice, bob, carol at `example.test`;
eve has no confirmed email) and the command to start the desktop app
against the stack. Email accounts work with any address: the code emails
are printed by `svx-demo serve` instead of being sent.

```sh
cd apps/desktop
SVX_SERVICE_URL=http://127.0.0.1:PORT SVX_REGISTRY_FINGERPRINT=<hex> SVX_DEV=1 \
  SVX_CONFIG=/tmp/svx-alice/config.toml npm run tauri dev
# a second account, in another terminal while the first window runs:
SVX_SERVICE_URL=http://127.0.0.1:PORT SVX_REGISTRY_FINGERPRINT=<hex> SVX_DEV=1 \
  SVX_CONFIG=/tmp/svx-bob/config.toml ../../target/debug/svx-desktop
```

Each `SVX_CONFIG` folder is a separate account with its own window (the
single-instance hand-over applies only without `SVX_CONFIG`). Approval
emails are printed by `svx-demo serve`.

The CLI shares the account and keychain with the app:

```sh
svx account signup --service http://127.0.0.1:PORT --registry-key <hex> --dev --dev-user alice
svx account signup --service http://127.0.0.1:PORT --registry-key <hex> --dev \
  --email dana@example.test --first-name Dana --last-name Example   # asks for a password and the code
svx account password                     # change it (email accounts)
svx account reset-password dana@example.test --service … --registry-key … --dev
svx send notes.txt --to bob@example.test
svx requests
svx approve <request-id>
svx history
svx file <file-id> --revoke-for bob@example.test
```

## Production setup (later)

- **Google:** a "Desktop app" OAuth client ID (and its non-secret client
  secret): `svx-server --personal-idp issuer=https://accounts.google.com,client_id=…,client_secret=…`.
- **Email (free): Gmail SMTP.** Codes and approval notices need an SMTP
  account; a Gmail address works and costs nothing (about 500 emails a
  day, plenty for a beta):
  1. Use a separate Gmail address for the service, e.g.
     `<notification-mailbox>`, and turn on 2-Step Verification for it.
  2. Google Account → Security → **App passwords**: create one named
     "SVX". Copy the 16 letters (no spaces).
  3. Run the service with
     `--smtp-url "smtps://notification-mailbox%40example.com:<app password>@smtp.gmail.com:465"`
     `--smtp-from "Secure Verified Exchange <<notification-mailbox>>"`
     (`@` in the user name is written `%40`). Prefer the environment
     variables `SVX_SMTP_URL` and `SVX_SMTP_FROM`, so the password isn't
     in the process list or shell history.
  Without SMTP the service only logs emails (development).
- **No Apple sign-in.** It needs a paid Apple Developer account; email
  accounts cover people without Google instead.
- **The official service** is built into release apps with
  `SVX_OFFICIAL_SERVICE_URL` and `SVX_OFFICIAL_REGISTRY_FINGERPRINT`.
