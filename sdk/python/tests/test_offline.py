"""Offline API: no managed service needed."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

import svx
from conftest import VECTORS


def _vector_trust(tmp_path):
    keys = json.loads((VECTORS / "keys.json").read_text())
    acme = keys["acme-security"]
    p = tmp_path / "acme.sign.pub"
    p.write_text(
        json.dumps(
            {
                "svx_key": 1,
                "type": "ed25519-public",
                "owner": "acme-security",
                "key_id": acme["key_id"],
                "key": acme["ed25519_public"],
            }
        )
    )
    return p


def test_version():
    assert svx.__version__


def test_generate_keys(tmp_path):
    kid = svx.generate_signing_key(tmp_path / "acme", "acme-security")
    assert len(kid) == 32
    assert (tmp_path / "acme.sign.pub").exists()
    secret = tmp_path / "acme.sign.key"
    assert secret.exists()
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(secret).st_mode) & 0o077 == 0
    assert len(svx.generate_kem_key(tmp_path / "ex", "example-corp")) == 32


def test_generate_rejects_bad_owner(tmp_path):
    with pytest.raises(svx.ConfigError):
        svx.generate_signing_key(tmp_path / "x", "Not Valid!")


def test_inspect_vector():
    info = svx.inspect(VECTORS / "valid-basic.svx")
    assert info.sender_org == "acme-security"
    assert info.recipient_org == "example-corp"
    assert info.policy_ref == "incident-response"
    assert info.artifact_id == "3a167c54ea43dca97f767134638bec0b"
    assert {e.role for e in info.envelopes} == {"service", "recipient-org"}


def test_verify_vector(tmp_path):
    v = svx.verify(VECTORS / "valid-basic.svx", [_vector_trust(tmp_path)])
    assert v.chunk_count == 3
    assert v.info.sender_org == "acme-security"


@pytest.mark.parametrize(
    "name",
    [
        "invalid-chunk-tampered",
        "invalid-signature-tampered",
        "invalid-policy-tampered",
        "invalid-truncated",
        "invalid-chunks-reordered",
    ],
)
def test_verify_rejects_invalid_vectors(tmp_path, name):
    with pytest.raises(svx.RejectedError) as e:
        svx.verify(VECTORS / f"{name}.svx", [_vector_trust(tmp_path)])
    assert e.value.exit_code == 1
    assert isinstance(e.value, svx.RefusedError)


def test_verify_without_trust_is_rejected():
    with pytest.raises(svx.RejectedError):
        svx.verify(VECTORS / "valid-basic.svx", [])


def test_missing_file_is_local_error():
    with pytest.raises(svx.SvxError) as e:
        svx.inspect("/nonexistent/file.svx")
    assert not isinstance(e.value, svx.RefusedError)
    assert e.value.exit_code == 2


def test_missing_config_is_config_error(tmp_path):
    with pytest.raises(svx.ConfigError):
        svx.Client(tmp_path / "nope.toml")
