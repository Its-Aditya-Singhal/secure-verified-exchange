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
| Emails sent by the service | 450 a day (`--max-emails-per-day`), under Gmail's ~500 |

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
sudo svx-admin suspend alice@example.com --reason "spam reports"
sudo svx-admin unsuspend alice@example.com
sudo svx-admin delete alice@example.com --yes         # erase on request; cannot be undone
```

- **Suspend:** the account can't sign in or make requests, nobody can find
  it or send it new files, and files it sent stop opening. Lifting the
  suspension restores everything.
- **Delete:** erases the account, its keys and password, every file it sent
  (they can't be opened any more), its place on other people's files, its
  requests, emails to it and its own activity log. Entries that mention it
  in *other* people's activity logs stay (for example "alice@… asked to
  open your file"): they are the sender's own record. The address can sign
  up again.
