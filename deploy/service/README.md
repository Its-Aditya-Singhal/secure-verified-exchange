# Running the SVX service on a Linux server

How the official service is set up (Ubuntu 24.04, x86_64, 1 GiB RAM). No
secrets are in this folder: they are created on the server.

1. **Base:** key-only SSH, `PermitRootLogin no`, `ufw` allowing only SSH, a
   2 GiB swap file, unattended security upgrades.
2. **PostgreSQL 16** on `127.0.0.1` only (`conf.d/svx.conf`: 64 MB shared
   buffers, 30 connections, SCRAM). Role and database `svx`; the password is
   generated on the server into `/etc/svx/db.env` (`DATABASE_URL=…`, mode 0640
   root:svx).
3. **Binaries**, built on a Mac with
   `cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.39 -p svx-server -p svx-cli`,
   installed to `/usr/local/bin` (`svx-server`, `svx`); `svx-admin` goes to
   `/usr/local/lib/svx/` with the wrapper [`svx-admin`](svx-admin) in
   `/usr/local/bin` (see "Managing accounts").
4. **Keys**, created on the server as the `svx` user in `/etc/svx/keys` (0700):
   `svx keygen --kind sign --owner svx --out registry`, `… --out grant`,
   `svx keygen --kind kem --owner svx --out service-kem`. Back them up offline:
   losing the KEM key makes every file ever sent unreadable; the registry
   key's fingerprint is built into every app.
5. **TLS and the proxy:** a self-signed P-256 certificate in `/etc/svx/tls`; the
   service listens on `0.0.0.0:8443`. Public HTTPS goes through the Cloudflare
   proxy (`api.getsvx.me:8443`, SSL mode Full, which accepts the self-signed
   certificate). ufw allows 8443 only from Cloudflare's published ranges
   (`cloudflare.com/ips-v4`, `ips-v6`), and an Azure inbound rule allows 8443.
   Direct access to the IP is blocked. (A Cloudflare Tunnel would expose no
   port, but Zero Trust asks for a card.) Because only Cloudflare can connect,
   the service trusts its `CF-Connecting-IP` header for the client's address
   (`--client-ip-header`), which the abuse limits count by. Cloudflare's
   ranges change rarely; compare them with `sudo ufw status` now and then.
6. **systemd:** [`svx-server.service`](svx-server.service) (hardened; optional
   `/etc/svx/smtp.env` with `SVX_SMTP_URL`, `SVX_SMTP_FROM`).

## Abuse limits

Built into the service (`crates/svx-server/src/limits.rs`), counted in
memory, reset on restart:

| What | Limit |
|---|---|
| Requests from one address (IPv6: one /64) | 600 a minute |
| Emailed codes asked for from one address | 20 an hour (and 5 an hour per email address) |
| New accounts from one address | 20 a day |
| Company registrations from one address | 5 a day |
| Registry lookups from one address | 120 a minute |
| Files registered by one account | 200 a day |
| Opens and approval polling by one account | 60 a minute |
| Share requests by one account | 20 an hour |
| Emails sent (every kind, last 24 hours, counted in the database) | codes and notices stop at 480 (`--max-emails-per-day`), announcements at 400, under Gmail's ~500 |

Over a limit the service answers HTTP 429 with a reason the app shows
(release requests: a plain "unavailable"). When the email budget is used
up, sign-up codes wait until the next day; approval emails aren't sent,
but the requests still show in the app.

## Managing accounts (`svx-admin`)

Over SSH, on the server:

```sh
sudo svx-admin stats                                  # accounts, files, opens, database size
sudo svx-admin users [--search alice] [--limit 50]    # newest first
sudo svx-admin user alice@example.com                 # one account in detail
sudo svx-admin suspend alice@example.com [--reason "spam reports"]
sudo svx-admin unsuspend alice@example.com
sudo svx-admin delete alice@example.com --yes [--reason "asked to be removed"]   # cannot be undone
```

- **Emails:** suspend, unsuspend and delete each email the account's owner
  (plain text, no links, through the service's Gmail account from
  `/etc/svx/smtp.env`, which the wrapper loads). The reason is included
  only when one is given. The command and the admin page say whether the
  email went out; the action happens either way.
- **Suspend:** the account can't sign in or make requests, nobody can find
  it or send it new files, and files it sent stop opening. Lifting the
  suspension restores everything.
- **Delete:** erases the account, its keys and password, every file it sent
  (they can't be opened any more), its place on other people's files, its
  requests, emails to it and its own activity log. Entries that mention it
  in *other* people's activity logs stay (for example "alice@… asked to
  open your file"): they are the sender's own record. The address can sign
  up again.

## Admin page (`scripts/admin.sh`)

The same commands in a browser page, private to the operator's Mac. Run
`scripts/admin.sh` (or double-click `scripts/SVX Admin.command`, which can be
copied to the Desktop). It:

1. makes a one-time login token with `openssl rand -hex 32`;
2. connects with the SSH key, forwarding a free port on the Mac's 127.0.0.1
   to the server's `127.0.0.1:9790`, and starts `sudo svx-admin web` there,
   sending the token on stdin (never on a command line);
3. opens `http://127.0.0.1:<port>/login?t=<token>` once, which sets a
   session cookie and spends the token.

The page shows the counts and the account list (search, details) and has
Suspend, Unsuspend and Delete (Delete needs the email typed again). It
stops when the Terminal window closes or after 30 minutes without use.
Nothing listens on the internet: `svx-admin web` binds `127.0.0.1` only,
accepts only a loopback `Host`, and changes need the page's own header and
origin (`crates/svx-server/src/admin_web.rs`). Actions are written to the
journal (`journalctl -t svx-admin`); suspend and unsuspend also go to the
account's audit log.

The page has three tabs:

- **Accounts:** counts, the account list, details, suspend, unsuspend,
  delete, and "No announcement emails" for someone who replied
  "unsubscribe".
- **Logs:** every account's activity log and the operator's own actions
  (`admin_log`: account IDs only, never addresses), newest first, with a
  search, an event filter and "problems only". No file names exist on the
  service; files show as short IDs.
- **Announcements:** write a subject, a plain-text message and up to 5
  attachments (10 MB in total), choose people (Select all, then untick),
  send a test to yourself, then Send. The service's worker
  (`crates/svx-server/src/announce.rs`) sends one email per person, a few
  every 15 seconds. Every email ends with an unsubscribe line. The counter
  shows emails of every kind in the last 24 hours against Gmail's ~500:
  announcements stop at 400, so sign-up codes always get through. Without
  "queue the rest", only the people who fit today are added; with it, the
  rest go out over the next days. Suspended and unsubscribed people are
  skipped. Attachments are deleted from the database once it's done or
  stopped.

SSH must allow this one forward and nothing else. In
`/etc/ssh/sshd_config.d/10-svx.conf`, instead of `AllowTcpForwarding no`:

```
AllowTcpForwarding local
PermitOpen 127.0.0.1:9790
PermitListen none
```

then `sudo sshd -t && sudo systemctl reload ssh`.

## Backups and health checks

- **Nightly backup** ([`svx-backup.sh`](svx-backup.sh), `svx-backup.timer`, 03:30 India time): `pg_dump` of the database, encrypted with `age` to the public key in `/etc/svx-backup.pub`, kept as `/var/backups/svx/svx-<time>.dump.age` (newest 14). The private key (`db-backup-age.key`) exists only on the operator's computer, so a stolen server can't read old backups. The dump holds accounts, public keys, file rules and audit logs; it never holds files, file names or private keys.
- **Copy off the server**: `scripts/pull-backup.sh` on the operator's Mac (weekly, or after anything important) copies the encrypted dumps to `~/.svx-service-backup/db/`. `scripts/pull-backup.sh --drill` also restores the newest into a scratch database and prints row counts. Do this after changes to the database layout.
- **What the backups don't cover**: the service keys (`/etc/svx/keys`, backed up once to `~/.svx-service-backup/`) and the release keys (`~/.svx-release`). Keep offline copies of both folders and of `db-backup-age.key`.
- **Health check** ([`svx-check.sh`](svx-check.sh), every 5 minutes): service and PostgreSQL running, the service answering, disk under 85%, memory, a backup less than 30 hours old. One email per problem and one when it clears, to `ALERT_TO` in `/etc/svx/alert.env`, through the service's own Gmail account. It can't tell you when the whole server is down or can't send mail: add an outside monitor for that (a free UptimeRobot or similar check on `https://api.getsvx.me:8443/healthz`).
- **Restore**: stop the service, `age -d -i db-backup-age.key -o dump svx-….dump.age`, then `pg_restore --clean --if-exists --no-owner -d svx dump` as the postgres user, start the service. Practise on a copy first.
