#!/bin/bash
INPUT=$(cat)
# avoid loops: if we already blocked once this turn, let Claude stop
echo "$INPUT" | grep -q '"stop_hook_active":true' && exit 0
# only gate when Rust sources changed
git diff --quiet HEAD -- '*.rs' 'Cargo.toml' 2>/dev/null && exit 0
OUT=$( { cargo fmt --all --check && \
         cargo clippy --all-targets --all-features -q -- -D warnings && \
         cargo nextest run --no-fail-fast; } 2>&1 )
if [ $? -ne 0 ]; then
  echo "Rust gate failed. Fix before finishing:" >&2
  echo "$OUT" | tail -40 >&2
  exit 2
fi
exit 0