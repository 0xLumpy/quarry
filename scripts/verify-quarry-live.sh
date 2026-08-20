#!/usr/bin/env bash
# Explicitly authorized, operator-run diagnostics against a designated live fixture.
# This script is intentionally excluded from pull-request CI.

set -euo pipefail

if [[ "${QUARRY_LIVE_APPROVED:-}" != "1" ]]; then
  echo "refusing live contact: set QUARRY_LIVE_APPROVED=1 after authorization" >&2
  exit 6
fi
if [[ -z "${RANGE_APEX:-}" ]]; then
  echo "refusing live contact: RANGE_APEX must name the authorized fixture" >&2
  exit 2
fi

python3 - "$RANGE_APEX" <<'PYEOF'
import re
import sys

host = sys.argv[1]
if len(host) > 253 or host != host.lower() or host.endswith("."):
    raise SystemExit("RANGE_APEX must be a canonical lowercase ASCII hostname")
labels = host.split(".")
if len(labels) < 2 or any(
    len(label) > 63
    or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
    for label in labels
):
    raise SystemExit("RANGE_APEX must be a canonical lowercase ASCII hostname")
PYEOF

for tool in dnsx httpx timeout python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required live diagnostic tool: $tool" >&2
    exit 3
  fi
done

live_tmp="$(mktemp -d)"
chmod 700 "$live_tmp"
trap 'rm -rf "$live_tmp"' EXIT

echo "== Quarry authorized live verification =="
echo "range=$RANGE_APEX"

printf 'assets.%s\nadmin.%s\nwww.%s\n' \
  "$RANGE_APEX" "$RANGE_APEX" "$RANGE_APEX" > "$live_tmp/dns-input.txt"
if ! timeout 45 dnsx \
  -l "$live_tmp/dns-input.txt" -cname -a -json -silent -retry 3 -duc \
  > "$live_tmp/dns.jsonl"; then
  echo "FAIL: dnsx live diagnostic did not complete" >&2
  exit 4
fi
python3 - "$RANGE_APEX" "$live_tmp/dns.jsonl" <<'PYEOF'
import json
import sys

apex, path = sys.argv[1:]
dangling = []
with open(path, encoding="utf-8") as rows:
    for line in rows:
        value = json.loads(line)
        if value.get("cname") and not value.get("a"):
            dangling.append(value.get("host"))
expected = [f"assets.{apex}"]
if sorted(dangling) != expected:
    raise SystemExit(f"FAIL: expected dangling CNAME {expected!r}, got {sorted(dangling)!r}")
print("PASS: dangling-CNAME fixture")
PYEOF

printf 'www.%s\n' "$RANGE_APEX" > "$live_tmp/http-input.txt"
if ! timeout 45 httpx \
  -l "$live_tmp/http-input.txt" -json -silent -ports 443 -irh -duc \
  > "$live_tmp/http.jsonl"; then
  echo "FAIL: httpx live diagnostic did not complete" >&2
  exit 5
fi
python3 - "$RANGE_APEX" "$live_tmp/http.jsonl" <<'PYEOF'
import json
import re
import sys

apex, path = sys.argv[1:]
hostname = re.compile(
    r"\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
found = set()
with open(path, encoding="utf-8") as rows:
    for line in rows:
        value = json.loads(line)
        csp = (value.get("header") or {}).get("content_security_policy")
        if not csp:
            continue
        for candidate in hostname.findall(csp):
            candidate = candidate.lower()
            if candidate == apex or candidate.endswith("." + apex):
                found.add(candidate)
expected = f"cf-edge-9d2c.{apex}"
if expected not in found:
    raise SystemExit(f"FAIL: expected CSP sibling {expected!r}, got {sorted(found)!r}")
print("PASS: CSP-sibling fixture")
PYEOF

echo "authorized live verification passed"
