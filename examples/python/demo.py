"""The Acme Security -> Example Corp demo, written against the Python SDK.

Start the dev stack first, then point this script at its state directory:

    cargo run -p svx-demo -- serve --state-dir /tmp/svx-stack
    python examples/python/demo.py /tmp/svx-stack

All organizations, people and data are fictional.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

import svx


def main(state_dir: Path) -> int:
    state = json.loads((state_dir / "state.json").read_text())
    orgs = {o["org_id"]: o for o in state["orgs"]}
    work = Path(tempfile.mkdtemp(prefix="svx-py-demo-"))

    def client(org: str, who: str) -> svx.Client:
        # One config directory per person, so admin sessions stay separate.
        d = work / who
        d.mkdir(exist_ok=True)
        shutil.copy(orgs[org]["config"], d / "config.toml")
        return svx.Client(d / "config.toml")

    carol = client("acme-security", "carol")
    alice = client("example-corp", "alice")
    bob = client("example-corp", "bob")
    admin = client("example-corp", "example-admin")

    results = []

    def check(name: str, ok: bool, detail: str) -> None:
        results.append(ok)
        print(f"{'✔' if ok else '✘'} {name}: {detail}")

    # 1. Carol packs a report for Example Corp.
    report = work / "incident-report.txt"
    report.write_text("FICTIONAL incident report: lookalike domain login-examplecorp.invalid\n")
    carol.login(dev_user="carol")
    packed = carol.pack(
        report,
        recipient="example-corp",
        policy=state["policy"],
        signing_key=state["acme_signing_key"],
        expires_at=int(time.time()) + 86400,
        classification="TLP:AMBER",
        register=True,
    )
    check("Carol packs", True, f"{packed.path} ({packed.artifact_id})")

    # 2. Eve has the file but is not Example Corp.
    info = svx.inspect(packed.path)
    check("Eve inspects", "lookalike" not in Path(packed.path).read_text(errors="replace"),
          f"sees only {info.sender_org} -> {info.recipient_org}")
    try:
        carol.open(packed.path, work / "eve", dev_user="carol")
        check("Wrong org opens", False, "opened!")
    except svx.NotRecipientError as e:
        check("Wrong org opens", True, str(e))

    # 3. Alice is authorized.
    r = alice.open(packed.path, work / "alice-out", dev_user="alice",
                   on_step=lambda step, detail: print(f"    {step}" + (f" ({detail})" if detail else "")))
    check("Alice opens", Path(r.path).read_text() == report.read_text(), r.path)

    # 4. Bob is not.
    try:
        bob.open(packed.path, work / "bob-out", dev_user="bob")
        check("Bob opens", False, "opened!")
    except svx.AccessDeniedError as e:
        check("Bob opens", e.deny_reason == "not_authorized", f"denied ({e.deny_reason})")

    # 5. Tampered copy.
    data = bytearray(Path(packed.path).read_bytes())
    data[len(data) // 2] ^= 1
    tampered = work / "tampered.svx"
    tampered.write_bytes(bytes(data))
    try:
        alice.open(tampered, work / "t", dev_user="alice")
        check("Tampered", False, "opened!")
    except svx.RejectedError as e:
        check("Tampered", True, str(e))

    # 6. Expired.
    try:
        alice.open(state["expired_artifact"], work / "x", dev_user="alice")
        check("Expired", False, "opened!")
    except svx.ExpiredError as e:
        check("Expired", True, str(e))

    # 7. Revoked.
    admin.login(dev_user="example-admin")
    admin.revoke(packed.path)
    try:
        alice.open(packed.path, work / "again", dev_user="alice")
        check("Revoked", False, "opened!")
    except svx.AccessDeniedError as e:
        check("Revoked", e.deny_reason == "expired_or_revoked", f"denied ({e.deny_reason})")

    # 8. Audit.
    page = admin.audit(100)
    for e in sorted(page.entries, key=lambda e: e.seq)[-6:]:
        print(f"    #{e.seq} {e.event} {e.subject or '-'}")
    check("Audit chain", page.chain_valid, f"{len(page.entries)} events")

    print(f"\n{sum(results)}/{len(results)} checks as expected. Files in {work}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
