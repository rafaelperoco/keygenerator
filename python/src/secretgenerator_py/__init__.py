"""Auditable random credential generation backed by the secretgenerator CLI.

The Python package is a thin wrapper around the CLI's stable schema-v1
JSON contract: each function shells out to ``secretgenerator``, parses
the JSON envelope, and returns it as a dict. Use the CLI directly when
you need exotic flags; use this module when you want idiomatic Python.

Install the binary once with whichever method you prefer:

    npm install -g @secretgenerator/cli
    # or: brew install rafaelperoco/tap/secretgenerator
    # or: download from https://github.com/rafaelperoco/secretgenerator/releases

All functions raise :class:`SecretgeneratorError` when the binary exits
non-zero, with the structured JSON error envelope attached as
``error.envelope`` so callers can branch on stable error codes
(``E_ENTROPY_TOO_LOW``, ``E_CHARSET_EMPTY``, ``E_CLASS_IMPOSSIBLE``, etc.)
instead of parsing free-form messages.
"""

from __future__ import annotations

from .api import (
    SCHEMA_VERSION,
    SecretgeneratorError,
    api_key,
    entropy,
    estimate_crack_time,
    passphrase,
    password,
    pin,
    secret,
)

__all__ = [
    "SCHEMA_VERSION",
    "SecretgeneratorError",
    "api_key",
    "entropy",
    "estimate_crack_time",
    "passphrase",
    "password",
    "pin",
    "secret",
]

__version__ = "2.0.0"
