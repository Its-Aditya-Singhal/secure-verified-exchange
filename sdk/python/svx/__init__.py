"""SVX secure verified exchange — Python SDK.

A thin, typed layer over the Rust ``svx-client`` library (the same code the
``svx`` CLI runs). Nothing security-relevant is implemented in Python:
verification, login binding, key release and decryption all happen in the
native module.

Quick start::

    import svx

    client = svx.Client()                        # same config as the CLI
    result = client.open("incident.svx", output_dir="~/SVX")
    print(result.path, result.manifest.classification)

Errors are raised as subclasses of :class:`SvxError`; security refusals
(:class:`RefusedError`) are distinct from outages (:class:`UnavailableError`)
and local problems.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from . import _native

__version__: str = _native.__version__

PathLike = Union[str, "os.PathLike[str]"]
StepCallback = Callable[[str, Optional[str]], None]

__all__ = [
    "AccessDeniedError",
    "ArtifactInfo",
    "AuditEntry",
    "AuditPage",
    "Client",
    "ConfigError",
    "Envelope",
    "ExpiredError",
    "FileEntry",
    "LoginError",
    "Manifest",
    "NotLoggedInError",
    "NotRecipientError",
    "OpenResult",
    "OutputExistsError",
    "PackResult",
    "RefusedError",
    "RejectedError",
    "Status",
    "SvxError",
    "UnavailableError",
    "Verified",
    "WhoAmI",
    "generate_kem_key",
    "generate_signing_key",
    "inspect",
    "verify",
]


# --------------------------------------------------------------------------
# Errors


class SvxError(Exception):
    """Base class for all SVX errors.

    Attributes:
        kind: stable machine-readable category (``"denied"``, ``"rejected"``...).
        exit_code: what the ``svx`` CLI would exit with (1 refused,
            2 local error, 3 service unavailable).
        deny_reason: for :class:`AccessDeniedError`, the coarse reason
            reported by the service (``"not_authorized"``,
            ``"expired_or_revoked"``...).
    """

    def __init__(
        self,
        message: str,
        kind: str = "other",
        exit_code: int = 2,
        deny_reason: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.exit_code = exit_code
        self.deny_reason = deny_reason


class RefusedError(SvxError):
    """A security refusal: the artifact was not opened, by design."""


class RejectedError(RefusedError):
    """The artifact failed verification (tampered, untrusted sender...)."""


class NotRecipientError(RefusedError):
    """The artifact is addressed to a different organization."""


class ExpiredError(RefusedError):
    """The artifact has expired (checked locally before any login)."""


class AccessDeniedError(RefusedError):
    """The managed service or key agent refused to release keys."""


class UnavailableError(SvxError):
    """The SVX service could not be reached. Nothing was decrypted."""


class LoginError(SvxError):
    """Signing in to the organization's identity provider failed."""


class NotLoggedInError(LoginError):
    """An admin operation needs ``Client.login()`` first."""


class ConfigError(SvxError):
    """Missing or invalid configuration or arguments."""


class OutputExistsError(SvxError):
    """The output file exists and ``overwrite`` was not requested."""


_ERRORS: Dict[str, type] = {
    "rejected": RejectedError,
    "not_recipient": NotRecipientError,
    "expired": ExpiredError,
    "denied": AccessDeniedError,
    "unavailable": UnavailableError,
    "login": LoginError,
    "not_logged_in": NotLoggedInError,
    "config": ConfigError,
    "output_exists": OutputExistsError,
}


def _translate(e: "_native.NativeError") -> SvxError:
    kind, message, exit_code, deny_reason = e.args
    cls = _ERRORS.get(kind, SvxError)
    return cls(message, kind=kind, exit_code=exit_code, deny_reason=deny_reason)


def _call(f: Callable[..., Any], *args: Any) -> Any:
    try:
        return f(*args)
    except _native.NativeError as e:
        raise _translate(e) from None


def _path(p: Optional[PathLike]) -> Optional[str]:
    if p is None:
        return None
    return os.path.expanduser(os.fspath(p))


# --------------------------------------------------------------------------
# Result types


@dataclass(frozen=True)
class Envelope:
    role: str
    key_id: str


@dataclass(frozen=True)
class ArtifactInfo:
    """Header fields. Unverified when returned by :func:`inspect`."""

    format_version: str
    suite_id: int
    #: Human-readable protection level, e.g. "maximum (...)".
    protection: str
    #: True for the post-quantum suites (SVX-1H 0x0003, SVX-2 0x0004).
    post_quantum: bool
    artifact_id: str
    created_at: int
    expires_at: Optional[int]
    sender_org: str
    sender_key_id: str
    recipient_org: str
    #: Every recipient (several for personal files sent to several people).
    recipients: List[str]
    service_id: str
    policy_ref: str
    chunk_size: int
    envelopes: List[Envelope]
    encrypted_manifest_bytes: int
    unknown_fields: List[int]

    @classmethod
    def _from(cls, d: Mapping[str, Any]) -> "ArtifactInfo":
        d = dict(d)
        d["envelopes"] = [Envelope(**e) for e in d["envelopes"]]
        return cls(**d)


@dataclass(frozen=True)
class Verified:
    info: ArtifactInfo
    chunk_count: int
    expired: bool


@dataclass(frozen=True)
class Status:
    """Result of :meth:`Client.status`: verified against the registry."""

    info: ArtifactInfo
    chunk_count: int
    expired: bool
    for_you: bool
    #: The sender's verified email (personal accounts) or organization name.
    sender_name: str


@dataclass(frozen=True)
class FileEntry:
    name: str
    size: int
    content_type: Optional[str] = None


@dataclass(frozen=True)
class Manifest:
    files: List[FileEntry]
    classification: Optional[str] = None
    description: Optional[str] = None

    @classmethod
    def _from(cls, d: Mapping[str, Any]) -> "Manifest":
        return cls(
            files=[FileEntry(**f) for f in d.get("files", [])],
            classification=d.get("classification"),
            description=d.get("description"),
        )


@dataclass(frozen=True)
class OpenResult:
    """A successful open. ``path`` is ``None`` for :meth:`Client.open_bytes`."""

    path: Optional[str]
    sender_org: str
    artifact_id: str
    manifest: Manifest

    @classmethod
    def _from(cls, d: Mapping[str, Any]) -> "OpenResult":
        return cls(
            path=d.get("path"),
            sender_org=d["sender_org"],
            artifact_id=d["artifact_id"],
            manifest=Manifest._from(d["manifest"]),
        )


@dataclass(frozen=True)
class PackResult:
    path: str
    artifact_id: str
    sender_org: str
    recipient_org: str
    service_id: str
    policy: str
    expires_at: Optional[int]
    signing_key_id: str
    registered: bool
    protection: str


@dataclass(frozen=True)
class WhoAmI:
    sub: str
    org_id: str
    issuer: str
    email: Optional[str]
    groups: List[str]
    acr: Optional[str]
    expires_at: int


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    at: int
    event: str
    subject: Optional[str]
    artifact_id: Optional[str]
    txn: Optional[str]
    reason: Optional[str]
    hash: str


@dataclass(frozen=True)
class AuditPage:
    entries: List[AuditEntry]
    chain_valid: bool


# --------------------------------------------------------------------------
# Offline functions


def inspect(path: PathLike) -> ArtifactInfo:
    """Parse the header WITHOUT verifying it. Never trust the result."""
    return ArtifactInfo._from(json.loads(_call(_native.inspect, _path(path))))


def verify(path: PathLike, trust: List[PathLike]) -> Verified:
    """Verify signature and integrity offline against ``*.sign.pub`` files.

    Raises :class:`RejectedError` if verification fails.
    """
    d = json.loads(_call(_native.verify, _path(path), [_path(t) for t in trust]))
    return Verified(
        info=ArtifactInfo._from(d["info"]),
        chunk_count=d["chunk_count"],
        expired=d["expired"],
    )


def generate_signing_key(prefix: PathLike, owner: str) -> str:
    """Write ``<prefix>.sign.key`` (secret, owner-only) and ``.sign.pub``.

    Returns the key ID (hex).
    """
    return _call(_native.generate_signing_key, _path(prefix), owner)


def generate_kem_key(prefix: PathLike, owner: str) -> str:
    """Write ``<prefix>.kem.key`` (secret, owner-only) and ``.kem.pub``.

    Returns the key ID (hex).
    """
    return _call(_native.generate_kem_key, _path(prefix), owner)


# --------------------------------------------------------------------------
# Managed client


class Client:
    """An SVX client bound to one configuration (see ``svx init``).

    Args:
        config: path to ``config.toml``. Defaults to ``$SVX_CONFIG`` or the
            platform configuration directory, exactly like the CLI. The
            admin session cache lives next to it.

    Opening always signs the user in again, because key release requires a
    login bound to a one-time key generated for that open. ``dev_user`` is
    only accepted with development configurations; otherwise the system
    browser is used (``browser=False`` prints the sign-in URL instead).

    Methods block and release the GIL while waiting on the network.
    """

    def __init__(self, config: Optional[PathLike] = None) -> None:
        self._n = _call(_native.NativeClient, _path(config))

    @property
    def config_path(self) -> str:
        return str(self._n.config_path())

    @property
    def config(self) -> Dict[str, Any]:
        """The loaded configuration (contains no secrets)."""
        return json.loads(self._n.config_json())

    @property
    def org_id(self) -> str:
        return self.config["org_id"]

    def status(self, path: PathLike) -> Status:
        """Verify an artifact against the registry. No login, no key release."""
        d = json.loads(_call(self._n.status, _path(path)))
        return Status(
            info=ArtifactInfo._from(d["info"]),
            chunk_count=d["chunk_count"],
            expired=d["expired"],
            for_you=d["for_you"],
            sender_name=d["sender_name"],
        )

    def open(
        self,
        path: PathLike,
        output_dir: Optional[PathLike] = None,
        *,
        overwrite: bool = False,
        dev_user: Optional[str] = None,
        browser: bool = True,
        on_step: Optional[StepCallback] = None,
    ) -> OpenResult:
        """Verify, sign in, obtain both key shares and decrypt to a file.

        The plaintext is written to ``output_dir`` (default: the configured
        directory or ``~/SVX``) under the file name from the encrypted
        manifest, owner-only, and only after the whole payload authenticated.

        ``on_step(name, detail)`` is called with ``"verifying"``,
        ``"signature_valid"`` (detail: sender), ``"connecting"``,
        ``"authenticating"``, ``"checking_authorization"``,
        ``"awaiting_approval"`` (personal accounts; detail: sender),
        ``"access_approved"`` and ``"decrypting"``.
        """
        d = json.loads(
            _call(
                self._n.open,
                _path(path),
                _path(output_dir),
                overwrite,
                dev_user,
                browser,
                on_step,
            )
        )
        return OpenResult._from(d)

    def open_bytes(
        self,
        path: PathLike,
        *,
        dev_user: Optional[str] = None,
        browser: bool = True,
        on_step: Optional[StepCallback] = None,
    ) -> "tuple[OpenResult, bytes]":
        """Like :meth:`open` but returns the plaintext in memory.

        Python cannot reliably wipe ``bytes``; prefer :meth:`open` for large
        or highly sensitive content.
        """
        j, data = _call(self._n.open_bytes, _path(path), dev_user, browser, on_step)
        return OpenResult._from(json.loads(j)), data

    def pack(
        self,
        input: PathLike,
        output: Optional[PathLike] = None,
        *,
        recipient: str,
        policy: str,
        signing_key: PathLike,
        expires_at: Optional[int] = None,
        classification: Optional[str] = None,
        description: Optional[str] = None,
        name: Optional[str] = None,
        overwrite: bool = False,
        register: bool = False,
    ) -> PackResult:
        """Sign and encrypt ``input`` for ``recipient``.

        The recipient's encryption key and the service key come from the
        signed registry. ``signing_key`` must be an active registered key of
        your organization. ``expires_at`` is Unix seconds. ``register=True``
        records the artifact with the service (needs :meth:`login`).
        """
        d = json.loads(
            _call(
                self._n.pack,
                _path(input),
                _path(output),
                recipient,
                policy,
                _path(signing_key),
                expires_at,
                classification,
                description,
                name,
                overwrite,
                register,
            )
        )
        return PackResult(**d)

    # Administration (uses the cached session from login()).

    def login(self, *, dev_user: Optional[str] = None, browser: bool = True) -> WhoAmI:
        """Sign in and cache a short-lived admin session (owner-only file)."""
        return WhoAmI(**json.loads(_call(self._n.login, dev_user, browser)))

    def logout(self) -> bool:
        """Delete the cached session. Returns ``False`` if there was none."""
        return bool(_call(self._n.logout))

    def whoami(self) -> WhoAmI:
        """Re-validate the cached session with the IdP."""
        return WhoAmI(**json.loads(_call(self._n.whoami)))

    def revoke(self, artifact: Union[PathLike, str]) -> str:
        """Revoke by artifact file or hex ID. Returns the artifact ID."""
        target = artifact if isinstance(artifact, str) else os.fspath(artifact)
        if not (len(target) == 32 and all(c in "0123456789abcdefABCDEF" for c in target)):
            target = os.path.expanduser(target)
        return _call(self._n.revoke, target)

    def policies(self) -> Dict[str, Dict[str, Any]]:
        return json.loads(_call(self._n.policies))

    def set_policy(self, name: str, policy: Mapping[str, Any]) -> Dict[str, Any]:
        return json.loads(_call(self._n.set_policy, name, json.dumps(dict(policy))))

    def audit(self, limit: int = 50) -> AuditPage:
        d = json.loads(_call(self._n.audit, limit))
        return AuditPage(
            entries=[AuditEntry(**e) for e in d["entries"]],
            chain_valid=d["chain_valid"],
        )

    def org_record(self, org: str) -> Dict[str, Any]:
        """The organization's registry record, verified with the pinned key."""
        return json.loads(_call(self._n.org_record, org))
