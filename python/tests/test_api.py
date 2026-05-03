"""Smoke tests for the Python wrapper.

These tests assume a working ``secretgenerator`` binary on PATH. CI
provisions it via the composite action; locally, install via brew or
``go install``.
"""

from __future__ import annotations

import pytest

import secretgenerator_py as sg


def test_password_returns_schema_v1() -> None:
    out = sg.password(length=24, charset="alphanum-symbols-v1")
    assert out["schema_version"] == 1
    assert len(out["password"]) == 24
    assert out["entropy_bits"] > 100
    assert out["subcommand"] == "password"
    assert out["request_id"]


def test_password_required_classes_guarantee() -> None:
    out = sg.password(
        length=20,
        charset="alphanum-symbols-v1",
        require_classes="lower,upper,digit,symbol",
    )
    pw = out["password"]
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_passphrase_word_count() -> None:
    out = sg.passphrase(words=8, separator=" ")
    assert len(out["password"].split(" ")) == 8


def test_secret_default_length() -> None:
    out = sg.secret(bytes_=32)
    # 32 bytes -> 43 base64url chars (no padding).
    assert len(out["password"]) == 43


def test_api_key_prefix() -> None:
    out = sg.api_key(length=32, prefix="sk_test", separator="_")
    assert out["password"].startswith("sk_test_")


def test_pin_default() -> None:
    out = sg.pin(digits=6)
    assert out["password"].isdigit()
    assert len(out["password"]) == 6


def test_entropy_estimate() -> None:
    out = sg.entropy("Tr0ub4dor&3")
    assert out["entropy_bits"] > 0
    assert "crack_time_estimates" in out


def test_estimate_crack_time_helper() -> None:
    estimates = sg.estimate_crack_time("Tr0ub4dor&3")
    assert isinstance(estimates, list)
    assert len(estimates) >= 5
    profile_ids = {e["profile_id"] for e in estimates}
    assert "nation-state-v1" in profile_ids


def test_entropy_below_floor_raises() -> None:
    with pytest.raises(sg.SecretgeneratorError) as excinfo:
        # length 4 alphanum is ~24 bits, far below the 80-bit floor.
        sg.password(length=4, charset="alphanum-v1")
    err = excinfo.value
    # The error envelope must carry the stable code.
    assert err.code == "E_ENTROPY_TOO_LOW", err.envelope


def test_schema_pinning_rejects_mismatch() -> None:
    # Schema 999 does not exist; the CLI must refuse.
    with pytest.raises(sg.SecretgeneratorError):
        sg.password(length=24, charset="alphanum-v1", require_schema_version=999)
