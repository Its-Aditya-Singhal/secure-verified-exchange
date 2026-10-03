# Personal accounts (Phase 5d)

Anyone can use SVX without company IT: sign in with Google or Apple, send
files to email addresses, and keep control of each file after sending it.
Company setup is still available ("Company or test server setup" on the
welcome screen).

All people and addresses here are fictional (`alice@example.test`,
`bob@example.test`).

## What a person sees

1. **Welcome.** "Continue with Google" or "Continue with Apple". The app
   makes this device's keys and keeps them in the system keychain. It then
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
   folder.

## How it works

A personal account is a one-person organization (`orgs.kind = 'personal'`,
ID `u.<16 hex>`). Everything that protects company files protects personal
files too: signed registry records, sender verification, the service's
share of every file key, audit and revocation.

| Piece | Company | Personal |
|-------|---------|----------|
| Who signs in | company IdP, every open | Google or Apple, once per device |
| Recipient's half of the key | the org's key agent | the person's own X-Wing key, in their keychain |
| Who decides | the recipient org's policy | the sender's per-file rules |
| Requests to the service | ID token bound to the open | signed with the device key |

### Sign-up

1. The app generates a hybrid signing key (Ed25519 + ML-DSA-65) and an
   X-Wing encryption key.
2. It signs in with Google or Apple (browser, PKCE) asking for an ID token
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
3. `POST /v1/personal/release` with a fresh X-Wing one-time key. The
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

### Relayed sign-in (Apple)

Apple can't send a desktop app's browser back to `127.0.0.1`, and its
client secret (an ES256 JWT signed with the team's key) must stay on the
service. So for relayed providers:

1. The app picks the ID-token nonce (binding its keys, as always) and a
   random 32-byte secret, and sends `POST /v1/auth/relay/start` with the
   nonce and `SHA-256(secret)`. The service returns the authorization URL
   (its own `state` and PKCE) and the app opens it in the browser.
2. Apple form-posts the code to `/v1/auth/relay/callback`. The service
   exchanges it with its client secret and PKCE verifier and validates the
   ID token, nonce included. The browser only sees "Return to the app".
3. The app collects the token with `POST /v1/auth/relay/poll` and the
   secret, once, then signs up as with Google.

A sign-in lives 10 minutes; the token is handed out once, only for the
secret, and is useless for keys other than those its nonce binds. Apple
"Hide my email" addresses work: the directory finds the account by that
address.

### Backups

`*.svxbackup`: both private keys, encrypted with ChaCha20-Poly1305 under a
key derived from the recovery password with Argon2id (64 MiB, 3 passes).
The file is owner-only and never overwritten. There is no password
recovery.

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
against the stack:

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
svx send notes.txt --to bob@example.test
svx requests
svx approve <request-id>
svx history
svx file <file-id> --revoke-for bob@example.test
```

## Production setup (later)

- **Google:** a "Desktop app" OAuth client ID (and its non-secret client
  secret): `svx-server --personal-idp issuer=https://accounts.google.com,client_id=…,client_secret=…`.
- **Apple:** an Apple Developer account, a Services ID (its ID is the
  `client_id`) with the return URL `https://<service>/v1/auth/relay/callback`
  and the service's domain registered, and a "Sign in with Apple" key
  (`AuthKey_<key_id>.p8`):
  `svx-server --public-url https://<service> --personal-idp issuer=https://appleid.apple.com,client_id=<Services ID> --apple-key team_id=<Team ID>,key_id=<Key ID>,file=AuthKey_<Key ID>.p8`.
  Apple doesn't allow loopback redirects or secrets in apps, so Apple
  sign-in is always **relayed** (below).
- **Email:** an SMTP account: `--smtp-url smtps://user:pass@smtp.example.com --smtp-from "SVX <no-reply@example.com>"`.
- **The official service** is built into release apps with
  `SVX_OFFICIAL_SERVICE_URL` and `SVX_OFFICIAL_REGISTRY_FINGERPRINT`.
