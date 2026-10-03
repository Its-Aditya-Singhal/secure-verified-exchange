"""End-to-end against `svx-demo serve` (needs PostgreSQL)."""

from __future__ import annotations

import os
import shutil
import stat
import sys
import time

import pytest

import svx

EXPECTED_STEPS = [
    "verifying",
    "signature_valid",
    "connecting",
    "authenticating",
    "checking_authorization",
    "access_approved",
    "decrypting",
]


@pytest.fixture
def artifact(stack, tmp_path):
    p = tmp_path / "incident-report.svx"
    shutil.copy(stack["sample_artifact"], p)
    return p


def test_alice_opens(stack, example_cfg, artifact, tmp_path):
    c = svx.Client(example_cfg)
    steps = []
    r = c.open(
        artifact,
        tmp_path / "out",
        dev_user="alice",
        on_step=lambda name, detail: steps.append((name, detail)),
    )
    assert open(r.path).read() == stack["sample_plaintext"]
    assert r.sender_org == "acme-security"
    assert [s for s, _ in steps] == EXPECTED_STEPS
    assert dict(steps)["signature_valid"] == "acme-security"
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(r.path).st_mode) == 0o600
    # No overwrite by default.
    with pytest.raises(svx.OutputExistsError):
        c.open(artifact, tmp_path / "out", dev_user="alice")


def test_open_bytes(stack, example_cfg, artifact):
    r, data = svx.Client(example_cfg).open_bytes(artifact, dev_user="alice")
    assert data.decode() == stack["sample_plaintext"]
    assert r.path is None


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_callback_exception_does_not_break_open(example_cfg, artifact):
    def boom(name, detail):
        raise RuntimeError("callback failure")

    _, data = svx.Client(example_cfg).open_bytes(artifact, dev_user="alice", on_step=boom)
    assert data


def test_bob_denied(example_cfg, artifact, tmp_path):
    out = tmp_path / "bob"
    with pytest.raises(svx.AccessDeniedError) as e:
        svx.Client(example_cfg).open(artifact, out, dev_user="bob")
    assert e.value.deny_reason == "not_authorized"
    assert e.value.exit_code == 1
    assert not out.exists()


def test_tampered_rejected_before_login(example_cfg, artifact, tmp_path):
    b = bytearray(artifact.read_bytes())
    b[len(b) // 2] ^= 1
    bad = tmp_path / "bad.svx"
    bad.write_bytes(bytes(b))
    steps = []
    with pytest.raises(svx.RejectedError):
        svx.Client(example_cfg).open(
            bad, tmp_path / "o", dev_user="alice", on_step=lambda n, d: steps.append(n)
        )
    assert "authenticating" not in steps


def test_wrong_org_refused(stack, acme_cfg, artifact, tmp_path):
    with pytest.raises(svx.NotRecipientError):
        svx.Client(acme_cfg).open(artifact, tmp_path / "o", dev_user="carol")


def test_expired_refused(stack, example_cfg, tmp_path):
    with pytest.raises(svx.ExpiredError):
        svx.Client(example_cfg).open(
            stack["expired_artifact"], tmp_path / "o", dev_user="alice"
        )


def test_unknown_user_login_fails(example_cfg, artifact, tmp_path):
    with pytest.raises(svx.LoginError):
        svx.Client(example_cfg).open(artifact, tmp_path / "o", dev_user="eve")


def test_status(example_cfg, acme_cfg, artifact):
    s = svx.Client(example_cfg).status(artifact)
    assert s.for_you and not s.expired
    assert s.info.recipient_org == "example-corp"
    assert not svx.Client(acme_cfg).status(artifact).for_you


def test_pack_roundtrip_register_and_revoke(stack, acme_cfg, example_cfg, tmp_path):
    acme = svx.Client(acme_cfg)
    acme.login(dev_user="carol")
    src = tmp_path / "findings.txt"
    src.write_text("FICTIONAL findings for the SDK test\n")
    packed = acme.pack(
        src,
        recipient="example-corp",
        policy=stack["policy"],
        signing_key=stack["acme_signing_key"],
        expires_at=int(time.time()) + 3600,
        classification="TLP:GREEN",
        register=True,
    )
    assert packed.registered and packed.path.endswith("findings.svx")
    assert svx.inspect(packed.path).artifact_id == packed.artifact_id

    ex = svx.Client(example_cfg)
    r = ex.open(packed.path, tmp_path / "out", dev_user="alice")
    assert open(r.path).read() == src.read_text()
    assert r.manifest.classification == "TLP:GREEN"

    with pytest.raises(svx.NotLoggedInError):
        ex.revoke(packed.path)
    who = ex.login(dev_user="example-admin")
    assert who.sub == "example-admin" and who.org_id == "example-corp"
    assert ex.whoami().sub == "example-admin"
    assert ex.revoke(packed.path) == packed.artifact_id
    with pytest.raises(svx.AccessDeniedError) as e:
        ex.open(packed.path, tmp_path / "again", dev_user="alice")
    assert e.value.deny_reason == "expired_or_revoked"

    page = ex.audit(100)
    assert page.chain_valid
    events = {e.event for e in page.entries}
    assert {"decryption_authorized", "artifact_revoked", "revoked_artifact_access"} <= events
    assert ex.logout() is True
    assert ex.logout() is False


def test_pack_with_unregistered_key_refused(stack, acme_cfg, tmp_path):
    svx.generate_signing_key(tmp_path / "rogue", "acme-security")
    src = tmp_path / "x.txt"
    src.write_text("x")
    with pytest.raises(svx.ConfigError):
        svx.Client(acme_cfg).pack(
            src,
            recipient="example-corp",
            policy=stack["policy"],
            signing_key=tmp_path / "rogue.sign.key",
        )


def test_policies_admin(example_cfg):
    c = svx.Client(example_cfg)
    c.login(dev_user="example-admin")
    pols = c.policies()
    assert "incident-response" in pols
    saved = c.set_policy("sdk-test", {"allow_groups": ["staff"]})
    assert saved["allow_groups"] == ["staff"]
    assert "sdk-test" in c.policies()


def test_non_dev_config_rejects_plain_http(example_cfg, artifact, tmp_path):
    text = example_cfg.read_text().replace("dev = true", "dev = false")
    prod = tmp_path / "prod.toml"
    prod.write_text(text)
    # A non-dev config with loopback http URLs is invalid on load.
    with pytest.raises(svx.ConfigError):
        svx.Client(prod)


def test_service_down_is_unavailable(stack, example_cfg, artifact, tmp_path):
    text = example_cfg.read_text().replace(stack["service_url"], "http://127.0.0.1:9")
    down = tmp_path / "down.toml"
    down.write_text(text)
    with pytest.raises(svx.UnavailableError) as e:
        svx.Client(down).open(artifact, tmp_path / "o", dev_user="alice")
    assert e.value.exit_code == 3
    assert not (tmp_path / "o").exists()


def test_org_record(example_cfg):
    rec = svx.Client(example_cfg).org_record("acme-security")
    assert rec["org_id"] == "acme-security"
    assert any(k["kind"] == "ed25519" for k in rec["keys"])
