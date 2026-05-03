"""Public Python API. Each function corresponds to a CLI subcommand.

The functions return parsed schema-v1 dicts. Type hints describe the
shape of the JSON envelope but the runtime type is always a plain
``dict[str, Any]`` so consumers can opt into stricter parsing
(pydantic, attrs, etc.) without paying for it here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Iterable

SCHEMA_VERSION = 1


class SecretgeneratorError(RuntimeError):
    """Raised when the CLI exits non-zero.

    When ``--json`` was set the CLI emits a structured envelope on
    stderr; we expose it as :attr:`envelope` so callers branch on the
    stable ``error.code`` rather than parsing free-form messages.
    """

    def __init__(
        self,
        message: str,
        *,
        returncode: int,
        envelope: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.envelope = envelope

    @property
    def code(self) -> str | None:
        """Stable error code (e.g. ``ENTROPY_TOO_LOW``) when present."""
        if not self.envelope:
            return None
        err = self.envelope.get("error")
        if isinstance(err, dict):
            code = err.get("code")
            return code if isinstance(code, str) else None
        return None


def _binary() -> str:
    path = shutil.which("secretgenerator")
    if path is None:
        raise SecretgeneratorError(
            "secretgenerator is not on PATH. Install it with one of:\n"
            "  npm install -g @secretgenerator/cli\n"
            "  brew install rafaelperoco/tap/secretgenerator\n"
            "  go install github.com/rafaelperoco/secretgenerator/cmd/secretgenerator@latest",
            returncode=127,
        )
    return path


def _run(args: Iterable[str]) -> dict[str, Any]:
    cmd = [_binary(), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        envelope: dict[str, Any] | None = None
        for stream in (proc.stderr, proc.stdout):
            if stream:
                try:
                    envelope = json.loads(stream)
                    break
                except json.JSONDecodeError:
                    continue
        raise SecretgeneratorError(
            (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip(),
            returncode=proc.returncode,
            envelope=envelope,
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SecretgeneratorError(
            f"could not parse JSON from CLI: {exc}",
            returncode=proc.returncode,
        ) from exc


def _common(
    *,
    require_schema_version: int | None,
    show_crack_time: bool,
    audit_log: str | None,
    extra: list[str],
) -> list[str]:
    args = ["--json", *extra]
    if require_schema_version is not None:
        args.append(f"--require-schema-version={require_schema_version}")
    if show_crack_time:
        args.append("--show-crack-time")
    if audit_log:
        args.extend(["--audit-log", audit_log])
    return args


def password(
    *,
    length: int = 20,
    charset: str = "alphanum-v1",
    require_classes: str | None = None,
    exclude: str | None = None,
    min_entropy_bits: float | None = None,
    allow_weak: bool = False,
    show_crack_time: bool = True,
    audit_log: str | None = None,
    require_schema_version: int | None = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Generate a random password."""
    extra: list[str] = ["--length", str(length), "--charset", charset]
    if require_classes:
        extra.extend(["--require-classes", require_classes])
    if exclude:
        extra.extend(["--exclude", exclude])
    if min_entropy_bits is not None:
        extra.extend(["--min-entropy-bits", str(min_entropy_bits)])
    if allow_weak:
        extra.append("--allow-weak")
    args = _common(
        require_schema_version=require_schema_version,
        show_crack_time=show_crack_time,
        audit_log=audit_log,
        extra=extra,
    )
    return _run(["password", *args])


def passphrase(
    *,
    words: int = 8,
    separator: str = "-",
    capitalize: bool = False,
    digit_suffix: bool = False,
    min_entropy_bits: float | None = None,
    allow_weak: bool = False,
    show_crack_time: bool = True,
    audit_log: str | None = None,
    require_schema_version: int | None = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Generate an EFF Large Wordlist diceware passphrase."""
    extra: list[str] = ["--words", str(words), "--separator", separator]
    if capitalize:
        extra.append("--capitalize")
    if digit_suffix:
        extra.append("--digit-suffix")
    if min_entropy_bits is not None:
        extra.extend(["--min-entropy-bits", str(min_entropy_bits)])
    if allow_weak:
        extra.append("--allow-weak")
    args = _common(
        require_schema_version=require_schema_version,
        show_crack_time=show_crack_time,
        audit_log=audit_log,
        extra=extra,
    )
    return _run(["passphrase", *args])


def secret(
    *,
    bytes_: int = 32,
    prefix: str | None = None,
    min_entropy_bits: float | None = None,
    allow_weak: bool = False,
    show_crack_time: bool = True,
    audit_log: str | None = None,
    require_schema_version: int | None = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Generate raw CSPRNG bytes encoded as URL-safe base64."""
    extra: list[str] = ["--bytes", str(bytes_)]
    if prefix:
        extra.extend(["--prefix", prefix])
    if min_entropy_bits is not None:
        extra.extend(["--min-entropy-bits", str(min_entropy_bits)])
    if allow_weak:
        extra.append("--allow-weak")
    args = _common(
        require_schema_version=require_schema_version,
        show_crack_time=show_crack_time,
        audit_log=audit_log,
        extra=extra,
    )
    return _run(["secret", *args])


def api_key(
    *,
    length: int = 32,
    prefix: str = "sk",
    separator: str = "_",
    min_entropy_bits: float | None = None,
    allow_weak: bool = False,
    show_crack_time: bool = True,
    audit_log: str | None = None,
    require_schema_version: int | None = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Generate a Stripe-style ``prefix_random`` token."""
    extra: list[str] = [
        "--length", str(length),
        "--prefix", prefix,
        "--separator", separator,
    ]
    if min_entropy_bits is not None:
        extra.extend(["--min-entropy-bits", str(min_entropy_bits)])
    if allow_weak:
        extra.append("--allow-weak")
    args = _common(
        require_schema_version=require_schema_version,
        show_crack_time=show_crack_time,
        audit_log=audit_log,
        extra=extra,
    )
    return _run(["api-key", *args])


def pin(
    *,
    digits: int = 6,
    acknowledge_low_entropy: bool = True,
    allow_weak_pattern: bool = False,
    show_crack_time: bool = False,
    audit_log: str | None = None,
    require_schema_version: int | None = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Generate a numeric PIN with the weak-pattern blocklist enforced.

    PINs are intrinsically low-entropy (a 6-digit PIN carries ~19.9 bits)
    and thus require an explicit acknowledgement. Set
    ``acknowledge_low_entropy=False`` only if you have already shown the
    user that warning elsewhere; the CLI will refuse otherwise.
    """
    extra: list[str] = ["--digits", str(digits)]
    if acknowledge_low_entropy:
        extra.append("--acknowledge-low-entropy")
    if allow_weak_pattern:
        extra.append("--allow-weak-pattern")
    args = _common(
        require_schema_version=require_schema_version,
        show_crack_time=show_crack_time,
        audit_log=audit_log,
        extra=extra,
    )
    return _run(["pin", *args])


def entropy(
    candidate: str,
    *,
    show_crack_time: bool = True,
    require_schema_version: int | None = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Estimate the entropy and crack time of an existing string.

    The candidate is piped on stdin; it never appears on the command
    line, so it does not leak into ``ps``, shell history, or the
    process-list inspection surface.
    """
    cmd = [_binary(), "entropy", "--json"]
    if require_schema_version is not None:
        cmd.append(f"--require-schema-version={require_schema_version}")
    if show_crack_time:
        cmd.append("--show-crack-time")
    proc = subprocess.run(cmd, input=candidate, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SecretgeneratorError(
            (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip(),
            returncode=proc.returncode,
        )
    return json.loads(proc.stdout)


def estimate_crack_time(candidate: str) -> list[dict[str, Any]]:
    """Return crack-time estimates for an existing string.

    Convenience wrapper that calls :func:`entropy` with
    ``show_crack_time=True`` and returns the ``crack_time_estimates``
    list directly.
    """
    payload = entropy(candidate, show_crack_time=True)
    estimates = payload.get("crack_time_estimates")
    if not isinstance(estimates, list):
        return []
    return estimates
