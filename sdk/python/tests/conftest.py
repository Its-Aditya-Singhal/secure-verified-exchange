"""Fixtures for the SVX Python SDK tests.

Managed tests start ``svx-demo serve`` (real managed service, key agent and
dev IdPs on loopback) against the PostgreSQL in ``SVX_TEST_DATABASE_URL``,
the same variable the Rust tests use. Without it they are skipped, unless
``SVX_REQUIRE_DB`` is set.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "test-vectors" / "v1"


def _demo_binary() -> Path:
    env = os.environ.get("SVX_DEMO_BIN")
    if env:
        return Path(env)
    exe = "svx-demo.exe" if sys.platform == "win32" else "svx-demo"
    p = REPO / "target" / "debug" / exe
    if not p.exists():
        subprocess.run(
            ["cargo", "build", "-q", "-p", "svx-demo"], cwd=REPO, check=True
        )
    return p


@pytest.fixture(scope="session")
def stack(tmp_path_factory):
    url = os.environ.get("SVX_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("SVX_REQUIRE_DB"):
            pytest.fail("SVX_TEST_DATABASE_URL must be set when SVX_REQUIRE_DB is set")
        pytest.skip("SVX_TEST_DATABASE_URL not set")
    state_dir = tmp_path_factory.mktemp("stack")
    log = open(state_dir / "serve.log", "w+")
    proc = subprocess.Popen(
        [str(_demo_binary()), "--database-url", url, "serve", "--state-dir", str(state_dir)],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if (state_dir / "state.json").exists():
                break
            if proc.poll() is not None:
                log.seek(0)
                pytest.fail("svx-demo serve exited:\n" + log.read())
            time.sleep(0.2)
        else:
            pytest.fail("svx-demo serve did not start")
        state = json.loads((state_dir / "state.json").read_text())
        state["dir"] = state_dir
        yield state
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def _org(stack, org_id):
    return next(o for o in stack["orgs"] if o["org_id"] == org_id)


@pytest.fixture
def example_cfg(stack, tmp_path):
    """A private copy of Example Corp's config (own directory, so its own
    session cache)."""
    (tmp_path / "example").mkdir()
    dst = tmp_path / "example" / "config.toml"
    shutil.copy(_org(stack, "example-corp")["config"], dst)
    return dst


@pytest.fixture
def acme_cfg(stack, tmp_path):
    (tmp_path / "acme").mkdir()
    dst = tmp_path / "acme" / "config.toml"
    shutil.copy(_org(stack, "acme-security")["config"], dst)
    return dst
