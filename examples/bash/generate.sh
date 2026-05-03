#!/usr/bin/env bash
#
# Generate an auditable password from a shell script. The CLI prints a
# stable JSON envelope (schema v1); we use `jq` to project the fields
# we care about.
#
# This snippet pins the schema version with --require-schema-version=1
# so a future incompatible change fails loudly instead of silently
# changing field shapes.
#
# Install once:
#   brew install rafaelperoco/tap/secretgenerator
#   # or: npm install -g @secretgenerator/cli

set -euo pipefail

length="${1:-24}"

result=$(secretgenerator password \
  --json \
  --require-schema-version=1 \
  --show-crack-time \
  --length "$length" \
  --charset alphanum-symbols-v1)

password=$(jq -r .password <<<"$result")
entropy=$(jq -r '.entropy_bits | (.*10|round)/10' <<<"$result")
crack=$(jq -r '.crack_time_estimates[] | select(.profile_id=="nation-state-v1") | .human_readable' <<<"$result")

printf 'password: %s\n' "$password"
printf 'entropy:  %s bits\n' "$entropy"
printf 'crack:    %s (nation-state)\n' "$crack"
