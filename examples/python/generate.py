"""Generate an auditable password by shelling out to secretgenerator.

The CLI prints a stable JSON envelope (schema v1). This wrapper pins the
schema version so any future incompatible change at the CLI side fails
loudly here instead of silently changing field shapes.

Install once:
    npm install -g @secretgenerator/cli
    # or: brew install rafaelperoco/tap/secretgenerator
"""

from __future__ import annotations

import json
import subprocess
import sys


def generate_password(length: int = 24) -> dict:
    proc = subprocess.run(
        [
            "secretgenerator",
            "password",
            "--json",
            "--require-schema-version=1",
            "--show-crack-time",
            "--length",
            str(length),
            "--charset",
            "alphanum-symbols-v1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


if __name__ == "__main__":
    result = generate_password(length=24)
    print(f"password: {result['password']}")
    print(f"entropy:  {result['entropy_bits']:.1f} bits")
    nation_state = next(
        e for e in result["crack_time_estimates"] if e["profile_id"] == "nation-state-v1"
    )
    print(f"crack:    {nation_state['human_readable']} (nation-state)")
    sys.exit(0)
