# The SVX client (`svx`)

The `svx` command is the reference client. It is a thin layer over the `svx-client` library, which the language SDKs will wrap too.

## Setup

An administrator gives you three things:
- the service URL;
- the **registry key fingerprint**, which must be obtained out of band, for example from your organization's admin or from a published fingerprint;
- your organization's SVX client ID.

Then run:

```sh
svx init --service https://svx.example --registry-key <64 hex> --org example-corp --client-id svx
```

`init` fetches the service's registry key and accepts it only if its fingerprint matches the one you supplied. It then fetches your organization's registry record and the service record and verifies **both signatures with that key**. A wrong fingerprint fails here, before anything is saved. The registry key is a post-quantum hybrid key (Ed25519 + ML-DSA-65), too long to type, which is why you pin its 64-hex-character fingerprint; the configuration stores both, and every run checks that they still match.

A configuration made before protocol version 3 (when the registry key was Ed25519) is refused with a message to run `svx init` again.

The registry key is the client's only trust anchor. Every other key comes from records signed with it:
- sender signing keys;
- recipient encryption keys;
- the service's key-release key.

The configuration lives at `~/.config/svx/config.toml` (or the platform equivalent). Override the location with `--config` or `$SVX_CONFIG`.

## Opening an artifact

```text
$ svx open incident.svx
Verifying artifact...
Signature valid (sender: acme-security)
Connecting to SVX service...
Authenticating with https://login.example-corp.example...
Checking authorization...
Access approved
Decrypting locally...
Opened:         /home/alice/SVX/evidence.zip
Classification: TLP:AMBER
```

### What happens, in order

The flow fails closed: any failure means nothing is decrypted.

1. **Local verification.** The client checks structure, integrity and the sender's signature, using keys from the verified registry record. A tampered or unknown-sender file is **rejected before you are asked to sign in**.
2. **Local checks.** The artifact must be addressed to your organization, managed by your service, and not expired on your clock. The server checks expiry again with its own clock.
3. **Sign-in.** The client signs you in with your organization's IdP in the browser (OIDC with PKCE and a loopback redirect, RFC 8252).
   - **Every `open` signs in again.** The login's `nonce` is bound to a fresh one-time key generated for this open, and the service and key agent only release key shares to that key.
   - **No reusable tokens.** A cached or intercepted token cannot be used to open anything.
   - **Usually silent.** If you already have an IdP session, the browser step completes without prompting.
4. **Authorization.**
   - The managed service checks the recipient organization's policy, expiry, revocation and replay, then releases its share.
   - Your organization's key agent re-checks your identity with your own IdP, then releases its share.
5. **Decryption.** Decryption happens **locally**. The payload never reaches the server in plaintext.

### Where the plaintext goes

| Option | Destination |
|--------|-------------|
| `-o DIR` | `DIR` |
| `default_output_dir` in the config | that directory |
| neither | `~/SVX`, created with owner-only permissions |

The plaintext is handled as follows:
- **Temporary file first.** Plaintext is written to a private temporary file (`.svx-partial-*`, mode 0600) in that directory.
- **Atomic rename.** It is renamed to the file name in the encrypted manifest only after the entire payload has authenticated. On any failure the temporary file is deleted.
- **Safe names.** File names from the manifest must be a single safe path component. Traversal, separators, control characters and reserved names are rejected.
- **No overwriting.** Existing files are never overwritten unless you pass `--overwrite`.
- **`--stdout`.** This streams the plaintext to a pipe. It is refused if stdout is a terminal.
- **Folders.** A payload marked as a folder (`application/vnd.svx.folder+zip` in the signed, encrypted manifest) is extracted into a new folder named after it. Entry names must be portable relative paths (no `..`, absolute paths, drive letters, backslashes, colons, control characters or device names); only regular files and folders are allowed (no links); entry count, total size and compression ratio are limited on the bytes actually written; files are 0600 and folders 0700; everything is staged privately and an existing folder is never replaced (`--overwrite` is refused for folders). With `--stdout` the zip itself is streamed.

### Limitations, stated plainly

- Once you have opened an artifact, the plaintext is an ordinary file. **Revocation cannot recall it.**
- Deleting a temporary file does not securely erase it from SSDs, copy-on-write filesystems, backups or swap. SVX minimizes how much plaintext persists; it cannot guarantee erasure. For the most sensitive material, use an encrypted home directory and short-lived output directories.
- A compromised endpoint can read whatever an authorized user decrypts (threat model T10).

## Commands

| Command | What it does |
|---------|--------------|
| `svx init …` | Configure the service, pinned registry key and organization |
| `svx open FILE [-o DIR] [--stdout] [--overwrite]` | Verify, authenticate, authorize and decrypt |
| `svx status FILE` | Verify against the registry and show who the artifact is for. Nothing is released and nothing is audited. |
| `svx pack FILE\|FOLDER --recipient ORG --policy P --sign-key KEY [--expires T] [--classification C] [--register]` | Create an artifact. The recipient and service keys come from the verified registry. A folder is zipped and extracted again on open (see below). |
| `svx login` / `svx logout` / `svx whoami` | Admin session (see below) |
| `svx revoke FILE\|ARTIFACT_ID` | Revoke future access. Admins of the sender org or the recipient org only. |
| `svx policy list\|show NAME\|set NAME --file F` | Manage your organization's policies. Admin. |
| `svx audit [--limit N] [--json]` | Your organization's audit log, with hash-chain verification. Admin. |
| `svx organizations show ORG` | A verified registry record |
| `svx keygen`, `svx inspect`, `svx verify [--trust F \| --registry]` | Offline tools |

### Admin sessions

`svx login` signs you in once and caches the ID token in `session.json` next to the config file:
- **Owner-only.** The file is mode 0600. Over-permissive or expired files are discarded.
- **Short-lived.** It lasts until the token expires, which is typically minutes.
- **Admin only.** It is used **only** as a bearer token for administrative calls. It cannot open artifacts; see the sign-in step above.

`svx logout` deletes it.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Security refusal: rejected, not the recipient, expired, revoked, not authorized |
| 2 | Usage, configuration or local error |
| 3 | SVX service unavailable. Nothing was decrypted. |

## File association

Double-clicking a `.svx` file runs `svx open <file>`. The file is passed to the client as data and is **never executed**.

| Platform | How to install |
|----------|----------------|
| Linux | `packaging/linux/install.sh` registers the `application/vnd.svx` MIME type (by extension and magic bytes) and a `.desktop` handler that runs in a terminal. |
| Windows | Import `packaging/windows/svx-file-association.reg` after adjusting the path to `svx.exe`. |
| macOS | `packaging/macos/Info.plist.fragment` holds the UTI declaration; the desktop app bundle declares it. |

The [desktop app](desktop.md) installers register the association themselves and open the file in the app instead of a terminal.

## Development mode

Use `svx init --dev` for local stacks (`docs/running-locally.md`). It allows:
- plain-http loopback URLs;
- `--dev-user NAME`, which signs in headlessly against the development IdP.

Never use dev mode with real data.
