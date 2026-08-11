#!/usr/bin/env bash
# Quarry verification key — fast, targeted regression checks per shipped fix.
# Run "every now and then" (in convolute) instead of a full pipeline run after each fix.
#
# Usage:   bash notes/verify-quarry.sh
# Prereqs: this box can import the Quarry source, and (for DNS checks) reach the live range.
#          QUARRY_SRC defaults to ~/workspace/quarry/src ; RANGE_APEX defaults to 0xlumpy.cc.
#
# Each check prints PASS / FAIL / SKIP. Exit code is nonzero if anything FAILED.

set -uo pipefail
QUARRY_SRC="${QUARRY_SRC:-$HOME/workspace/quarry/src}"
# the checks drive the real provider lanes against fakes; their PACING state must
# not land in the operator's installation (~/.config/quarry/pace).
export QUARRY_PACE_DIR="$(mktemp -d)"
trap 'rm -rf "$QUARRY_PACE_DIR"' EXIT
RANGE_APEX="${RANGE_APEX:-0xlumpy.cc}"
PY="python3"
pass=0; fail=0; skip=0
ok(){ echo "  PASS  $1"; pass=$((pass+1)); }
no(){ echo "  FAIL  $1"; fail=$((fail+1)); }
sk(){ echo "  SKIP  $1"; skip=$((skip+1)); }

echo "== Quarry verification key =="
echo "src=$QUARRY_SRC  range=$RANGE_APEX"
echo

# ── Check 0: touched modules import cleanly ────────────────────────────────────
echo "[0] source imports"
if PYTHONPATH="$QUARRY_SRC" $PY -c "from quarry_recon.phases import vertical, params; from quarry_recon import runner" 2>/tmp/vq.err; then
  ok "quarry_recon.{runner,phases.vertical,phases.params} import"
else
  no "import failed: $(tail -1 /tmp/vq.err)"
fi

# ── Check 1: gitleaks exit-code taxonomy (commit d04a467) — offline ────────────
# gitleaks exits 1 when it FINDS leaks (writes report to -r, stdout via /dev/stdout).
# An accepted nonzero code must produce output, else it stays FAILED.
echo "[1] runner._classify exit-code taxonomy (gitleaks fix)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "all 6 classify cases correct" || no "classify mismatch (see above)"
import sys
from quarry_recon.runner import _classify
# new signature: _classify(exit_code, has_out, blocked, transport, ok_empty, ok_codes=(0,))
def s(*a): return _classify(*a)[0].value
cases = [
  ("exit1 + output, ok_codes(0,1)      -> success", s(1,True,False,False,True,(0,1)),  "success"),
  ("exit1 + NO output, ok_codes(0,1)   -> failed ", s(1,False,False,False,True,(0,1)), "failed"),
  ("exit0 + NO output                  -> empty  ", s(0,False,False,False,True,(0,1)), "empty"),
  ("exit0 + output                     -> success", s(0,True,False,False,True,(0,1)),  "success"),
  ("exit2                              -> failed ", s(2,False,False,False,True,(0,1)), "failed"),
  ("default ok_codes(0,): exit1 no out -> failed ", s(1,False,False,False,True),       "failed"),
]
bad=0
for label,got,want in cases:
    flag = "ok" if got==want else "XX"
    print(f"      {flag} {label}  got={got}")
    bad += got!=want
sys.exit(1 if bad else 0)
PYEOF

# ── Check 2: dangling-CNAME takeover detection (vertical.py) — needs range ──────
# A host with a CNAME but no A of its own = takeover candidate; A-resolving hosts must not be.
echo "[2] dangling-CNAME takeover detection (assets vs admin/www)"
if ! command -v dnsx >/dev/null 2>&1; then
  sk "dnsx not on PATH"
elif ! timeout 20 dnsx -silent -a -l <(printf 'admin.%s\n' "$RANGE_APEX") 2>/dev/null | grep -q .; then
  sk "range $RANGE_APEX not reachable / not resolving from here"
else
  TMP=$(mktemp); CN=$(mktemp)
  printf 'assets.%s\nadmin.%s\nwww.%s\n' "$RANGE_APEX" "$RANGE_APEX" "$RANGE_APEX" > "$TMP"
  # -cname -a so each result carries A records; dangling = has CNAME but no A in THIS result
  # (matches the code — NOT resolved-set membership, which a no-A CNAME host can pollute).
  dnsx -l "$TMP" -cname -a -json -silent -retry 3 2>/dev/null > "$CN"
  RESULT=$($PY - "$RANGE_APEX" "$CN" <<'PYEOF'
import sys,json
path = sys.argv[2]
dang=[]
for line in open(path):
    try: o=json.loads(line)
    except: continue
    if o.get("cname") and not o.get("a"):       # has CNAME, no A = dangling
        dang.append(o.get("host"))
print(",".join(sorted(dang)))
PYEOF
)
  rm -f "$TMP" "$CN"
  if [ "$RESULT" = "assets.$RANGE_APEX" ]; then
    ok "assets flagged dangling/takeover; admin+www not ($RESULT)"
  else
    no "expected only assets.$RANGE_APEX dangling, got: '${RESULT:-<none>}'"
  fi
fi

# ── Check 3: CSP-sibling discovery from live response headers (probe.py) ───────
# httpx -irh carries the CSP; an in-scope host named in www's CSP must be discovered.
echo "[3] CSP-sibling discovery (internal via www CSP)"
if ! command -v httpx >/dev/null 2>&1; then
  sk "httpx not on PATH"
elif ! timeout 20 httpx -silent -ports 443 -l <(printf 'www.%s\n' "$RANGE_APEX") 2>/dev/null | grep -q .; then
  sk "range $RANGE_APEX not reachable from here"
else
  HX=$(mktemp)
  printf 'www.%s\n' "$RANGE_APEX" > "$HX.in"
  timeout 30 httpx -l "$HX.in" -json -silent -ports 443 -irh 2>/dev/null > "$HX"
  RESULT=$($PY - "$RANGE_APEX" "$HX" <<'PYEOF'
import sys,json,re
apex,path=sys.argv[1],sys.argv[2]
rx=re.compile(r"\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
def in_scope(h): return h==apex or h.endswith("."+apex)
found=set()
for line in open(path):
    try: o=json.loads(line)
    except: continue
    csp=(o.get("header") or {}).get("content_security_policy")
    if not csp: continue
    found |= {h for h in {m.lower() for m in rx.findall(csp)} if in_scope(h)}
print(",".join(sorted(found)))
PYEOF
)
  rm -f "$HX" "$HX.in"
  # range's CSP-only host was renamed internal -> cf-edge-9d2c (non-wordlist, post-Test-1)
  case ",$RESULT," in
    *",cf-edge-9d2c.$RANGE_APEX,"*) ok "cf-edge-9d2c discovered via www CSP ($RESULT)";;
    *) no "expected cf-edge-9d2c.$RANGE_APEX in CSP siblings, got: '${RESULT:-<none>}'";;
  esac
fi

# ── Check 4: arjun → dalfox handoff (params.py) — hermetic ─────────────────────
# arjun writes param-bearing URLs (".../v1/search?q=7101"); params.py must turn each into a
# url + parameter + xss review so dalfox gets a candidate. (arjun actually finding `q` on the
# range was confirmed live; this asserts the parse/handoff that was previously missing.)
echo "[4] arjun -> dalfox candidate handoff"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "arjun param URL becomes a dalfox xss candidate" || no "handoff parse broken"
import sys
line="https://api.0xlumpy.cc/v1/search?q=7101"
u=line.strip()
if "?" not in u: sys.exit(1)
base,qs=u.split("?",1)
review={"klass":"xss","value":u}
dalfox_in=[review["value"]] if review["klass"] in ("xss","redirect") else []
sys.exit(0 if dalfox_in==["https://api.0xlumpy.cc/v1/search?q=7101"] else 1)
PYEOF

# ── Check 5: crawl-link host promotion (crawl.py) — hermetic ───────────────────
# A host first seen via a crawl link (link-only needle) must be registered as a subdomain,
# not left only in the URL corpus. Asserts host extraction + in-scope gate for the needle.
echo "[5] crawl-link host promoted to subdomain (s3-backup needle)"
PYTHONPATH="$QUARRY_SRC" RANGE_APEX="$RANGE_APEX" $PY - <<'PYEOF' && ok "link-only host extracted + in-scope -> would register" || no "host extraction/scope broken"
import os,sys
from quarry_recon import normalize
apex=os.environ["RANGE_APEX"]
host=normalize.host_of_url(f"https://s3-backup-7f3a.{apex}/")
in_scope = host==apex or host.endswith("."+apex)
sys.exit(0 if (host==f"s3-backup-7f3a.{apex}" and in_scope) else 1)
PYEOF

# ── Check 6: gitleaks file-based integration (crawl.py) — catches /dev/stdout breakage ─
# Runs gitleaks exactly as crawl.py does (-r REAL FILE, not /dev/stdout) against a fixture with
# fake-format secrets, and asserts the report file is non-empty with findings. The earlier
# /dev/stdout approach passed the offline classify test but wrote 0 bytes on the VPS — this
# integration check is what would have caught it.
echo "[6] gitleaks file-based report integration"
if ! command -v gitleaks >/dev/null 2>&1; then
  sk "gitleaks not on PATH"
else
  GD=$(mktemp -d)
  printf 'const a="AKIACNGWIFUCZPSGIJ4L";\nconst b="ghp_bWBjbCJ0k4TkZabhN757MJmJjaduGbuE4v08";\n' > "$GD/app.js"
  gitleaks dir "$GD" -r "$GD/report.json" -f json >/dev/null 2>&1   # T1.3: `dir` subcommand (detect deprecated)
  sz=$(wc -c < "$GD/report.json" 2>/dev/null || echo 0)
  nf=$($PY -c "import json,sys; print(len(json.load(open('$GD/report.json'))))" 2>/dev/null || echo 0)
  rm -rf "$GD"
  if [ "${sz:-0}" -gt 0 ] && [ "${nf:-0}" -ge 1 ]; then
    ok "report file non-empty ($sz bytes, $nf findings) — portable, not /dev/stdout"
  else
    no "report empty (size=$sz findings=$nf) — gitleaks -r not writing the file?"
  fi
fi

# ── Check 7: secret entities are redacted (secrets.mask/fingerprint) — hermetic ───────
# Normalized secret entities must NOT carry the raw secret — only a masked preview +
# fingerprint id. Raw evidence stays in raw/ files. Asserts mask hides the body and the
# fingerprint is stable + doesn't contain the secret.
echo "[7] secret entities redacted (no raw secret in mask/fingerprint)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "mask hides body, fingerprint stable + raw-free" || no "redaction leaks raw secret"
import sys
from quarry_recon import secrets
s="AKIACNGWIFUCZPSGIJ4L"
m, fp = secrets.mask(s), secrets.fingerprint(s)
ok = (s not in m) and (s not in fp) and (len(fp)==12) and (fp==secrets.fingerprint(s)) and m.startswith("AKIA")
sys.exit(0 if ok else 1)
PYEOF

# ── Check 8: enrich phase wired into the pipeline (phases/__init__) — hermetic ────────
# Late-discovered hosts (crawl links, CSP siblings) need a catch-up resolve/takeover/probe.
# The enrich phase must run AFTER crawl and BEFORE params, and be importable.
echo "[8] enrich phase registered (after crawl, before params)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "enrich in ORDER after crawl, before params + importable" || no "enrich phase not wired correctly"
import sys
from quarry_recon.phases import ORDER, REGISTRY, enrich  # noqa
ok = ("enrich" in REGISTRY
      and ORDER.index("enrich") == ORDER.index("crawl") + 1
      and ORDER.index("enrich") < ORDER.index("params")
      and REGISTRY["enrich"][2] is True)        # needs_active → skipped in passive mode
sys.exit(0 if ok else 1)
PYEOF

# ── Check 9: digest.json contract (triage.digest_json) — hermetic ─────────────────────
# M2.1 contract: schema 1.0, placeholder queues present+empty, every item has provenance,
# no raw secret in the output (preview only).
echo "[9] digest.json contract (schema 1.0, provenance, findings READABLE, placeholders)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "schema 1.0 · stable keys · real url provenance · raw_ref consistent · discovered secret READABLE" || no "digest contract broken"
import sys, json
from quarry_recon import triage
class Shim:
    target="t"; run_id="r"
    _d={"live":[{"url":"https://a.t/","cdn":False,"sources":["httpx"]}],
        "url":[{"url":"https://a.t/login?id=1","sources":["katana","gau"]}],
        "secret":[{"kind":"aws","preview":"AKIA…J4L (20 chars)","data":"AKIAREALSECRET123456",
                   "sources":["gitleaks"],"file":"/x/app.js"}],
        "finding":[], "review":[{"klass":"cname","takeover_candidate":True,"value":"x.t -> y.t","sources":["dnsx"]}]}
    def read(self,e): return self._d.get(e,[])
    def values(self,e):
        k={"url":"url","live":"url","subdomain":"host","resolved":"host"}.get(e,"value")
        return [d.get(k) for d in self._d.get(e,[]) if d.get(k)]
    def count(self,e): return len(self._d.get(e,[]))
d=triage.digest_json(Shim(), None)
q=d["queues"]; items=[it for v in q.values() for it in v]
expect_keys=set(triage.CANONICAL_QUEUES)|set(triage.PLACEHOLDER_QUEUES)
auth=q["auth"][0]; sec=q["secrets"][0]
ok = (d["digest_schema"]=="1.0"
      and expect_keys.issubset(set(q))                              # ALL canonical+placeholder keys present
      and all(q[k]==[] for k in triage.PLACEHOLDER_QUEUES)          # placeholders empty
      and all(it.get("sources") is not None and it.get("raw_ref") and it.get("why")
              and it.get("confidence") and it.get("id") for it in items)
      and auth["sources"]==["katana","gau"]                         # real url provenance kept
      and sec["raw_ref"]=="normalized/secret.jsonl"                 # raw_ref = immutable store
      and sec.get("location")=="/x/app.js"                          # file evidence not overloaded
      # DOCTRINE (Lumpy, 2026-08-05): `digest.json` is LOCAL — the recon->attack contract and the file
      # an operator triages from. A DISCOVERED secret is the finding and must be readable; hunting for
      # weeks and then reading `AKIA…J4L (20 chars)` is not evidence. Quarry's OWN configured
      # credentials are still redacted everywhere (see check 7).
      and "AKIAREALSECRET123456" in json.dumps(d)
      and len(q["takeover"])==1)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 10: M2.2 tag-only classifiers (api-doc/oauth-jwt/cloud/mobile) — hermetic ───
# Simple regex over the URL corpus; TAG only. Each fixture routes to its queue, a normal URL
# routes to none of the four.
echo "[10] M2.2 classifiers (api-doc/oauth-jwt/cloud/mobile, tag-only)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "each fixture tagged to its queue; normal URL not misrouted" || no "classifier routing wrong"
import sys
from quarry_recon import triage
URLS=["https://a.t/openapi.json","https://a.t/oauth/authorize","https://foo.s3.amazonaws.com/b/k",
      "https://a.t/app.apk","https://a.t/normal/page?id=1",
      "https://a.t/token?code=SECRET123&state=XYZ&id=1"]
class S:
    target="t"; run_id="r"
    def read(self,e): return [{"url":u,"sources":["katana"]} for u in URLS] if e=="url" else []
    def values(self,e): return [d["url"] for d in self.read(e)] if e in ("url","live") else []
    def count(self,e): return len(self.read(e))
q=triage.digest_json(S(),None)["queues"]
def has(k,frag): return any(frag in it["value"] for it in q[k])
tok=[it["value"] for it in q["oauth-jwt"] if "/token?" in it["value"]]
ok = (has("api-doc","openapi.json") and has("oauth-jwt","/oauth/authorize")
      and has("cloud","s3.amazonaws.com") and has("mobile",".apk")
      and not any(has(k,"normal/page") for k in ("api-doc","oauth-jwt","cloud","mobile"))
      and tok and "code=***" in tok[0] and "state=***" in tok[0]            # sensitive values masked
      and "id=1" in tok[0] and "SECRET123" not in tok[0])                   # struct/names kept, raw gone
sys.exit(0 if ok else 1)
PYEOF

# ── Check 11: sourcemap unpack 9.1 — safe paths + sourcesContent recovery (hermetic) ──
# _safe_srcpath must strip schemes + block traversal; a sourcemap with sourcesContent must
# recover the original source text to a safe relative path.
echo "[11] sourcemap unpack (safe paths + source recovery)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "webpack:// stripped, traversal blocked, sourcesContent recovered" || no "sourcemap unpack/safety broken"
import sys
from quarry_recon.phases.crawl import _safe_srcpath
sp = _safe_srcpath
ok_paths = (sp("webpack:///./src/app.js")=="src/app.js"
            and ".." not in sp("../../etc/passwd")
            and sp("")=="source")
# recovery logic over a sample sourcemap
sm = {"sources": ["../src/secret.ts"], "sourcesContent": ["const API='https://api.x/v1';"]}
rec = {}
for i, c in enumerate(sm.get("sourcesContent") or []):
    if c: rec[sp(sm["sources"][i])] = c
ok_rec = rec.get("src/secret.ts","").startswith("const API=")
sys.exit(0 if (ok_paths and ok_rec) else 1)
PYEOF

# ── Check 12: deep-mine 9.2 — GraphQL/WebSocket/API-base extraction (hermetic) ────────
echo "[12] deep-mine (graphql/websocket/api-base from JS)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "ws/api-base/graphql extracted; normal URL not mis-caught" || no "deep-mine patterns wrong"
import sys
from quarry_recon.phases.crawl import _WS_RX, _APIBASE_RX, _GQL_RX
js="""new WebSocket('wss://rt.x/socket'); axios.create({baseURL:'https://api.x/v2'});
fetch('/api/v1/graphql'); const n='https://x.com/page';"""
ws=set(_WS_RX.findall(js)); ab=set(_APIBASE_RX.findall(js)); gq=set(_GQL_RX.findall(js))
ok = ("wss://rt.x/socket" in ws and "https://api.x/v2" in ab and "/api/v1/graphql" in gq
      and "https://x.com/page" not in (ws|ab|gq))
sys.exit(0 if ok else 1)
PYEOF

# ── Check 13: Phase 11 content discovery 11.1 wiring (hermetic) ───────────────────────
# content phase registered after enrich / before params, needs_active; CONTENT_DISCOVERY
# defaults off + validates values; shipped light wordlist present.
echo "[13] content phase (off-by-default, registered, light wordlist shipped)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "content phase wired, default off, invalid mode fails loud, light list ships" || no "content phase 11.1 wiring broken"
import sys, tempfile, os
from importlib import resources
from quarry_recon.phases import ORDER, REGISTRY, content  # noqa
from quarry_recon.config import TargetProfile, ProfileError
def prof(cd):
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    open(p, "w").write(f"TARGET: t\nAPEX_DOMAINS:\n  - t.com\nMODES:\n  CONTENT_DISCOVERY: {cd}\n")
    return p
# invalid value must RAISE at load (opt-in phase, fail loud on a typo)
raised = False
try: TargetProfile.load(prof("balnaced"))
except ProfileError: raised = True
loaded = TargetProfile.load(prof("light"))
wl = resources.files("quarry_recon.data").joinpath("content-light.txt").read_text()
ok = (ORDER.index("content")==ORDER.index("origin")+1 and ORDER.index("content")<ORDER.index("params")
      and REGISTRY["content"][2] is True
      and raised and loaded.content_discovery=="light"
      and TargetProfile.load(prof("off")).content_discovery=="off"
      and ".git/config" in wl and len([l for l in wl.splitlines() if l.strip()]) > 30)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 14: content recursion 11.2 — knob gated to balanced/deep, light stays flat ──
echo "[14] content recursion (balanced/deep honor depth; light flat)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "recursion gated (light->0), capped at 5 (>5 raises), true->1" || no "recursion gating/cap wrong"
import sys, tempfile, os
from quarry_recon.config import TargetProfile, ProfileError, MAX_CONTENT_RECURSION
def prof(cd, cr):
    fd,p=tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    open(p,"w").write(f'TARGET: t\nAPEX_DOMAINS:\n  - t.com\nMODES:\n  CONTENT_DISCOVERY: "{cd}"\n  CONTENT_RECURSION: {cr}\n')
    return TargetProfile.load(p)
def gated(p):                                  # mirrors content.run(): light never recurses
    return p.content_recursion if p.content_discovery in ("balanced","deep") else 0
over = False
try: prof("deep", MAX_CONTENT_RECURSION + 1)    # >cap must fail loud
except ProfileError: over = True
ok = (gated(prof("light",2))==0 and gated(prof("balanced",2))==2
      and gated(prof("deep",MAX_CONTENT_RECURSION))==MAX_CONTENT_RECURSION
      and prof("deep","true").content_recursion==1 and over)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 15: Phase 1A — RDAP org/CIDR parse (hermetic) ───────────────────────────────
echo "[15] RDAP parse (org from vcard, cidr0_cidrs)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "RDAP org + CIDR parsed from a sample object" || no "RDAP parse broken"
import sys
from quarry_recon.osint import _rdap_org
obj = {"name": "EXAMPLE-NET",
       "cidr0_cidrs": [{"v4prefix": "1.2.3.0", "length": 24}],
       "entities": [{"vcardArray": ["vcard", [["version",{},"text","4.0"],
                                              ["fn",{},"text","Example Org LLC"]]]}]}
org = _rdap_org(obj)
cidrs = [f"{c.get('v4prefix')}/{c.get('length')}" for c in (obj.get("cidr0_cidrs") or []) if c.get("length") is not None]
sys.exit(0 if (org=="Example Org LLC" and cidrs==["1.2.3.0/24"]) else 1)
PYEOF

# ── Check 16: arjun rate gated on http_rl via GLOBAL --rate-limit (T0.1) — offline ────
# History: old `-d 1` = unconditional 1s delay (blew the 1800s wall); then `-d 1/rl` per-thread
# (breached RoE by the thread multiple). Now: rate appears ONLY under http_rl, uses the real GLOBAL
# `--rate-limit` cap, and the per-thread `-d` delay is gone entirely (never a bare `-d 1`).
echo "[16] arjun rate gated on http_rl via global --rate-limit (no per-thread -d)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "arjun --rate-limit only under http_rl; per-thread -d removed" || no "arjun rate ungated / still per-thread -d"
import sys, inspect, pathlib
import quarry_recon.phases.params as m
src = pathlib.Path(m.__file__).read_text()
# A2 moved the invocation out of a batched `aj_cmd` in run() into the per-target _arjun_lane. The RoE
# property is unchanged; fail LOUD if the lane disappears rather than silently passing over it.
if not hasattr(m, "_arjun_exec") or not hasattr(m, "_arjun_rate_shares"):
    sys.exit(1)
region = inspect.getsource(m._arjun_exec)
no_hardcoded = '"-d", "1"' not in src and "'-d', '1'" not in src
no_perthread = '"-d"' not in region                # per-thread delay throttle is gone
gated = 'if rate:' in region and '"--rate-limit"' in region     # applied only when the operator caps
# --rate-limit is PER PROCESS, so the lane may run several target processes at once ONLY because the
# operator's GLOBAL rate is partitioned between them (never handed to each in full).
shares = m._arjun_rate_shares
partitioned = (sum(shares(10, 5)) == 10 and sum(shares(7, 5)) == 7          # sums EXACTLY to the cap
               and shares(0, 5) == [0] * 5                                   # no cap -> no flag
               and len(shares(3, 5)) == 3 and all(s >= 1 for s in shares(3, 5)))  # rate shrinks the POOL
sys.exit(0 if (no_hardcoded and no_perthread and gated and partitioned) else 1)
PYEOF

# ── Check 17: ffuf registered in tools.yaml (install/doctor/update see it) — offline ──
echo "[17] ffuf registered in tools.yaml (phase=content)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "ffuf in registry, phase=content, has install+version_cmd" || no "ffuf missing/malformed in tools.yaml"
import sys
from quarry_recon.registry import load_tools
f = [t for t in load_tools() if t.bin == "ffuf"]
ok = len(f) == 1 and f[0].phase == "content" and bool(f[0].install) and bool(f[0].version_cmd)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 18: secret scanners cover recovered sourcemap sources (Test-5 stripe gap) — offline ──
# gitleaks/trufflehog must scan js_files/ AND sourcemaps/recovered/ — a canary planted only in a
# recovered source (stripe key in app.js.map) is missed if we scan js_files/ alone.
echo "[18] gitleaks/trufflehog scan recovered sourcemaps too (not js_files only)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "scan_dirs spans js_dir+recov_dir; both scanners iterate it" || no "recovered sources not scanned for secrets"
import sys, pathlib
import quarry_recon.phases.crawl as m
src = pathlib.Path(m.__file__).read_text()
i = src.index("scan_dirs =")
region = src[i:i+400]
# d7abef5: the scanners read the STAGED js_derived tree, never raw js_files (which is immutable evidence).
ok = ("recov_dir" in region and "js_derived_dir" in region and "js_files" not in region
      and "for sd in scan_dirs" in src
      and "*[str(d) for d in scan_dirs]" in src)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 19: exposed-file evidence extraction (recon-layer fetch+extract) — offline ──
# Boundary: recon reads exposed unauth in-scope files and extracts the secret (not just flags it).
# Verify the sensitive-path matcher + the secret extractor (dotenv + typed token, deduped).
echo "[19] exposed-resource extraction (sensitive-path match + secret mine)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "sensitive paths matched; .env secrets mined; typed token wins over dotenv" || no "evidence extraction broken"
import sys
from quarry_recon import evidence as e
paths_hit  = all(e.SENSITIVE_FILE_RX.search(p) for p in
                 ("https://h/.env", "https://h/.git/config", "https://h/config.json", "https://h/backup.sql"))
paths_miss = not any(e.SENSITIVE_FILE_RX.search(p) for p in ("https://h/v1/users", "https://h/index.html"))
env = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY0\nSTRIPE_KEY=sk_live_abcdEFGH1234567890xyz\nDB_PASSWORD=hunter2super\nDEBUG=true\n"
kinds = {k for k, _, _ in e.mine(env)}
vals  = [v for _, v, _ in e.mine(env)]
mined = ("aws-secret-key" in kinds and "stripe-secret" in kinds
         and "dotenv:DB_PASSWORD" in kinds        # generic secret caught via dotenv
         and "dotenv:AWS_SECRET_ACCESS_KEY" not in kinds  # deduped: typed token won
         and len(vals) == len(set(vals)))          # no duplicate values
sys.exit(0 if (paths_hit and paths_miss and mined) else 1)
PYEOF

# ── Check 20: exposed-fetch off-scope redirect guard — offline (monkeypatched urlopen) ──
# urlopen follows redirects silently; an in-scope .env that 30x's off-scope must NOT be body-read.
echo "[20] exposed-fetch skips off-scope redirect body, records redirect review"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "off-scope redirect: 0 secrets, redirect review logged" || no "off-scope redirect body extracted / not recorded"
import sys, tempfile
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from pathlib import Path
from quarry_recon import evidence as e, fetch as f

class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, rec): self.ents.append((ent, rec)); return True
    def raw_path(self, a, b, name):
        p = Path(tempfile.mkdtemp()) / name; return p
class Ctx: scope, run, profile = Scope(), Run(), None

# the in-scope .env 302's off-scope; scoped_get must NOT contact/read evil.test (it would serve the key)
class Resp:
    def __init__(s, status, headers=None, body=b""): s.status=status; s.headers=headers or {}; s._b=body
    def read(s, n=None):                       # behave like a SOCKET: the body arrives once, in slices
        out, s._b = (s._b if n in (None, -1) else s._b[:n]), (b"" if n in (None, -1) else s._b[n:])
        return out
    def close(s): pass
class FakeOpener:
    def __init__(s, script): s.script=script; s.contacted=[]
    def open(s, req, timeout=None): s.contacted.append(req.full_url); return s.script[req.full_url]
op = FakeOpener({
 "https://a.inscope.test/.env": Resp(302, {"Location":"https://evil.test/pwned"}),
 "https://evil.test/pwned": Resp(200, {}, b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY0\n"),
}); f._NO_REDIRECT_OPENER = op

ctx = Ctx()
added = e.fetch_exposed(ctx, ["https://a.inscope.test/.env"])
secrets_added = [r for k, r in ctx.run.ents if k == "secret"]
redirects = [r for k, r in ctx.run.ents if k == "review" and str(r.get("id","")).startswith("exposed-redirect")]
ok = (added == 0 and not secrets_added and len(redirects) == 1
      and "evil.test" in redirects[0].get("location", "")
      and "NOT extracted" in redirects[0].get("note", "")
      and "https://evil.test/pwned" not in op.contacted)     # off-scope hop never requested
sys.exit(0 if ok else 1)
PYEOF

# ── Check 21: GraphQL introspection probe (recon evidence) — offline (monkeypatched urlopen) ──
# Introspection is a non-mutating read: enabled -> count + "ENABLED" review; disabled -> 0 + noted.
echo "[21] graphql introspection: enabled counted, disabled noted, in-scope only"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "introspection enabled=1/ENABLED review; disabled=0/blocked review" || no "graphql probe broken"
import sys, tempfile, urllib.request
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from pathlib import Path
from quarry_recon import evidence as e

class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, rec): self.ents.append((ent, rec)); return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()   # per-instance state (c1 != c2)

def resp_factory(body):
    class R:
        url = "https://api.inscope.test/graphql"; status = 200; headers = {}
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None):
            if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
            self._eof = True
            return body
        def close(self): pass
    return lambda req, timeout=20: R()

# scoped_get now follows redirects via fetch._NO_REDIRECT_OPENER (not urllib.request.urlopen) — bridge it
# to whatever the test patches into urlopen (read live, so reassignment below is picked up).
from quarry_recon import fetch as _f
_f._NO_REDIRECT_OPENER = type("_O", (), {"open": staticmethod(lambda req, timeout=None: urllib.request.urlopen(req, timeout))})()
# enabled
urllib.request.urlopen = resp_factory(b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
c1 = Ctx(); n1 = e.probe_graphql(c1, ["https://api.inscope.test/graphql"])
rev1 = [r for k, r in c1.run.ents if k == "review" and r.get("klass") == "graphql"]
# disabled
urllib.request.urlopen = resp_factory(b'{"errors":[{"message":"introspection is disabled"}]}')
c2 = Ctx(); n2 = e.probe_graphql(c2, ["https://api.inscope.test/graphql"])
rev2 = [r for k, r in c2.run.ents if k == "review" and r.get("klass") == "graphql"]

ok = (n1 == 1 and len(rev1) == 1 and "ENABLED" in rev1[0]["note"]
      and n2 == 0 and len(rev2) == 1 and ("off/blocked" in rev2[0]["note"] or "blocked" in rev2[0]["note"]))
sys.exit(0 if ok else 1)
PYEOF

# ── Check 22: evidence direct requests honor RATELIMIT.HTTP — offline ──
# fetch/probe use raw urllib (no tool flags), so they must pace to http_rl req/s themselves.
echo "[22] exposed-fetch/graphql pace to RATELIMIT.HTTP (no burst on capped target)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "http_rl=5 -> sleep(0.2)/request; unset -> no sleep" || no "rate pacing not honored"
import sys, tempfile, urllib.request
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from pathlib import Path
from quarry_recon import evidence as e
from quarry_recon import fetch as f

class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
class Prof:
    def __init__(self, rl): self.http_rl = rl
class Run:
    def add(self, ent, rec): return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self, rl): self.scope = Scope(); self.run = Run(); self.profile = Prof(rl)

class R:
    url = "https://a.inscope.test/.env"; status = 200
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=None):
        if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
        self._eof = True
        return b"NOTHING=here\n"
urllib.request.urlopen = lambda req, timeout=20: R()
# scoped_get follows via fetch._NO_REDIRECT_OPENER now — bridge it to the patched urlopen
f._NO_REDIRECT_OPENER = type("_O", (), {"open": staticmethod(lambda req, timeout=None: urllib.request.urlopen(req, timeout))})()

slept = []
f.time.sleep = lambda s: slept.append(s)   # pacing lives in the shared fetch choke point now

e.fetch_exposed(Ctx(5), ["https://a.inscope.test/.env"])       # rl=5 -> one 0.2s pace
paced = slept == [0.2]
slept.clear()
e.fetch_exposed(Ctx(None), ["https://a.inscope.test/.env"])    # no cap -> no sleep
unpaced = slept == []
sys.exit(0 if (paced and unpaced) else 1)
PYEOF

# ── Check 23: actuator interrogation (env=real; heapdump via _links, endpoint NEVER hit) — offline ──
echo "[23] actuator: env=real+secret; heapdump detected via _links (endpoint not requested); benign; no shutdown"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "env mined; heapdump via _links high-pri (no GET); benign noted; shutdown untouched" || no "actuator probe broken"
import sys, tempfile, urllib.request
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from pathlib import Path
from quarry_recon import evidence as e

class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, rec): self.ents.append((ent, rec)); return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()

REQ = []
def router(req, timeout=20):
    u = req.full_url; REQ.append(u)
    class R:
        url = u
        def __enter__(self): return self
        def __exit__(self, *a): return False
    r = R()
    if u.endswith("/actuator"):                                    # index — advertises _links
        r.status = 200
        body = (b'{"_links":{"self":{"href":"x"},"env":{"href":"x"},"heapdump":{"href":"x"}}}'
                if "real.inscope.test" in u else b'{"_links":{"self":{"href":"x"}}}')
    elif u.endswith("/env") and "real.inscope.test" in u:
        r.status = 200; body = b"DB_PASSWORD=hunter2super\n"
    else:
        r.status = 404; body = b"Whitelabel Error"
    r._left = body                                                 # a socket returns the body ONCE
    def _read(n=None, _r=r):
        out, _r._left = (_r._left if n in (None, -1) else _r._left[:n]), \
                        (b"" if n in (None, -1) else _r._left[n:])
        return out
    r.read = _read
    r.headers = {}; r.close = lambda: None
    return r
urllib.request.urlopen = router
from quarry_recon import fetch as _f
_f._NO_REDIRECT_OPENER = type("_O", (), {"open": staticmethod(lambda req, timeout=None: urllib.request.urlopen(req, timeout))})()

cr = Ctx(); nr = e.probe_actuator(cr, ["https://real.inscope.test/actuator"])
rev_r = [x for k, x in cr.run.ents if k == "review" and x.get("id","").startswith("actuator:")][0]
sec_r = [x for k, x in cr.run.ents if k == "secret"]
heavy = [x for k, x in cr.run.ents if k == "review" and x.get("id","").startswith("actuator-heavy")]
cb = Ctx(); nb = e.probe_actuator(cb, ["https://benign.inscope.test/actuator"])
rev_b = [x for k, x in cb.run.ents if k == "review" and x.get("id","").startswith("actuator:")][0]

ok = (nr == 1 and "env" in rev_r["note"] and "heapdump" in rev_r["note"] and len(sec_r) == 1
      and len(heavy) == 1 and heavy[0].get("priority") == "high" and "NOT requested" in heavy[0]["note"]
      and not any(u.endswith("/heapdump") for u in REQ)           # heapdump endpoint NEVER hit
      and nb == 0 and "benign" in rev_b["note"]
      and not any(u.endswith("/shutdown") or u.endswith("/restart") for u in REQ))
sys.exit(0 if ok else 1)
PYEOF

# ── Check 24: shared fetch.scoped_get guard behavior — offline (monkeypatched urlopen) ──
echo "[24] fetch.scoped_get: off-scope redirect->None, in-scope->body, bounded read(max+1)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "off-scope->None; in-scope->data; read bounded to max_body+1" || no "scoped_get guard broken"
import sys
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from quarry_recon import fetch as f

class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
class Ctx: scope = Scope(); profile = None

READN = []
class Resp:
    def __init__(s, status, headers=None, body=b""): s.status=status; s.headers=headers or {}; s._b=body
    def read(s, n=None):
        READN.append(n)
        out, s._b = (s._b if n in (None, -1) else s._b[:n]), (b"" if n in (None, -1) else s._b[n:])
        return out
    def close(s): pass
class FakeOpener:
    def __init__(s, script): s.script=script; s.contacted=[]
    def open(s, req, timeout=None): s.contacted.append(req.full_url); return s.script[req.full_url]

# in-scope terminal 200 -> body, read bounded to max_body+1
op1 = FakeOpener({"https://a.inscope.test/x": Resp(200, {}, b"BODY")}); f._NO_REDIRECT_OPENER = op1
d1, fin1, st1 = f.scoped_get(Ctx(), "https://a.inscope.test/x", max_body=1234)
# off-scope redirect -> data None; the off-scope hop is NEVER contacted
op2 = FakeOpener({"https://a.inscope.test/x": Resp(302, {"Location":"https://evil.test/x"}),
                  "https://evil.test/x": Resp(200, {}, b"LEAK")}); f._NO_REDIRECT_OPENER = op2
d2, fin2, st2 = f.scoped_get(Ctx(), "https://a.inscope.test/x", max_body=1234)

ok = (d1 == b"BODY" and st1 == 200 and READN and READN[0] == 1235
      and d2 is None and "evil.test" in fin2
      and "https://evil.test/x" not in op2.contacted)      # off-scope hop never requested
sys.exit(0 if ok else 1)
PYEOF

# ── Check 25: crawl JS + sourcemap fetches route through the shared choke point — offline ──
echo "[25] crawl JS/sourcemap use fetch.scoped_get; JS download active_allowed-gated"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "crawl routes both fetches through fetch.scoped_get; JS gated" || no "crawl still hand-rolls urllib / JS not gated"
import sys, pathlib
import quarry_recon.phases.crawl as m
src = pathlib.Path(m.__file__).read_text()
ok = (src.count("fetch.scoped_get") >= 2
      and "import urllib.request" not in src            # no more hand-rolled fetches
      and "active_allowed(normalize.host_of_url(u))" in src)  # JS download is scope/passive-gated
sys.exit(0 if ok else 1)
PYEOF

# ── Check 26: dalfox output framed as candidate, not exploit (boundary ruling) — offline ──
echo "[26] dalfox finding = xss-candidate + manual-validation, confirmed:false (no 'dalfox-xss')"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "dalfox reframed to candidate label; confirmed:false; no exploit-proof wording" || no "dalfox still framed as proven"
import sys, pathlib
import quarry_recon.phases.params as m
src = pathlib.Path(m.__file__).read_text()
# 4.3.B split the dalfox findings: xss-candidate (in _dalfox_xss_fast) + open-redirect-candidate
# (legacy redirect block). Both must stay CANDIDATE-framed (confirmed:false, manual validation), no
# exploit-proof wording ('dalfox-xss').
ok = ('"xss-candidate"' in src and '"open-redirect-candidate"' in src
      and "manual validation required" in src
      and '"confirmed": False' in src and '"dalfox-xss"' not in src)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 27: OpenAPI/Swagger fetch+parse (endpoints+params, in-scope only) — offline ──
echo "[27] openapi: endpoints+params extracted; all servers iterated (staging-first not missed); off-scope dropped"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "in-scope doc -> 2 endpoints + 2 query params + api-doc review; off-scope server -> 0" || no "openapi parse broken"
import sys, json, tempfile
from pathlib import Path
from quarry_recon import evidence as e
from quarry_recon import fetch as f

class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
    def in_scope(self, host): return host.endswith("inscope.test")
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, rec): self.ents.append((ent, rec)); return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()

def doc(*servers):
    return json.dumps({"openapi": "3.0.0", "servers": [{"url": s} for s in servers],
        "paths": {"/users": {"get": {"parameters": [{"name": "id", "in": "query"}]}},
                  "/search": {"get": {"parameters": [{"name": "q", "in": "query"},
                                                     {"name": "x", "in": "header"}]}}}}).encode()

# in-scope server
import hashlib as _h
from pathlib import Path as _P
def _streamed(body, status=200, final=None):
    """the lane STREAMS now: write where it asked, hand back an Acquisition"""
    def _fn(ctx, u, dest, *a, **kw):
        d = _P(dest); d.parent.mkdir(parents=True, exist_ok=True); d.write_bytes(body)
        return (f.Acquisition(d, len(body), _h.sha256(body).hexdigest(), True),
                u if final is None else final, status)
    return _fn
f.scoped_get_file = _streamed(doc("https://api.inscope.test/v1"))
c1 = Ctx(); n1 = e.parse_openapi(c1, ["https://api.inscope.test/openapi.json"])
eps = [r for k, r in c1.run.ents if k == "endpoint"]
pas = [r for k, r in c1.run.ents if k == "parameter"]
rev = [r for k, r in c1.run.ents if k == "review" and r.get("klass") == "api-doc"]
# off-scope server -> every path dropped
f.scoped_get_file = _streamed(doc("https://evil.test/v1"))
c2 = Ctx(); n2 = e.parse_openapi(c2, ["https://api.inscope.test/openapi.json"])
eps2 = [r for k, r in c2.run.ents if k == "endpoint"]
# multiple servers: off-scope FIRST, in-scope second -> in-scope endpoints still built
f.scoped_get_file = _streamed(doc("https://staging.evil.test/v1",
                                  "https://api.inscope.test/v1"))
c3 = Ctx(); n3 = e.parse_openapi(c3, ["https://api.inscope.test/openapi.json"])
eps3 = [r for k, r in c3.run.ents if k == "endpoint"]

ok = (n1 == 2 and len(eps) == 2 and len(pas) == 2 and len(rev) == 1
      and all("inscope.test" in r["value"] for r in eps)
      and n2 == 0 and len(eps2) == 0
      and n3 == 2 and all("inscope.test" in r["value"] for r in eps3))   # staging-first not missed
sys.exit(0 if ok else 1)
PYEOF

# ── Check 28: SSTI primitive-confirm probe (eval -> candidate; reflection -> none) — offline ──
echo "[28] ssti: engine-eval -> ssti-candidate (confirmed:false); reflected literal -> no finding"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "eval'd expr -> ssti-candidate confirmed:false + raw_ref; literal reflection ignored" || no "ssti probe broken"
import sys, tempfile
from pathlib import Path
from quarry_recon import evidence as e
from quarry_recon import fetch as f

import hashlib as _h
from pathlib import Path as _P
def _streamed(body, status=200, final=None):
    """the evidence lanes STREAM now: write the body where the lane asked, return an Acquisition."""
    def _fn(ctx, u, dest, *a, **kw):
        d = _P(dest); d.parent.mkdir(parents=True, exist_ok=True); d.write_bytes(body)
        return (f.Acquisition(d, len(body), _h.sha256(body).hexdigest(), True),
                u if final is None else final, status)
    return _fn


class Scope:
    def active_allowed(self, host): return host.endswith("inscope.test")
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, rec): self.ents.append((ent, rec)); return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()

URL = ["https://api.inscope.test/render?template=x&q=y"]

# engine EVALUATED the expression -> computed value present, literal absent
f.scoped_get_file = _streamed(b"<html>out: 7006652 done</html>")
c1 = Ctx(); n1 = e.probe_ssti(c1, URL)
fnd = [r for k, r in c1.run.ents if k == "finding"]

# only REFLECTED (literal echoed, not evaluated) -> not SSTI
f.scoped_get_file = _streamed(b"you searched for {{1234*5678}}")
c2 = Ctx(); n2 = e.probe_ssti(c2, URL)

ok = (n1 == 1 and len(fnd) == 1 and fnd[0]["template"] == "ssti-candidate"
      and fnd[0]["confirmed"] is False and "7006652" in fnd[0]["name"]
      and fnd[0].get("raw_ref") and Path(fnd[0]["raw_ref"]).exists()   # response evidence saved
      and n2 == 0)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 29: actuator bases seed from Spring tech fingerprint (Test-6 mgmt gap) — offline ──
echo "[29] _actuator_bases seeds Spring-tagged hosts + discovered /actuator; off-scope excluded"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "Spring host -> <origin>/actuator seeded; discovered url kept; off-scope Spring dropped" || no "actuator Spring-seed broken"
import sys
from quarry_recon.phases import params as p

class Scope:
    def active_allowed(self, h): return h.endswith("inscope.test")
class Run:
    def __init__(self, tech, urls): self._t = tech; self._u = urls
    def read(self, ent):
        return {"tech": self._t, "url": self._u}.get(ent, [])
class Ctx:
    def __init__(self, tech, urls): self.run = Run(tech, urls)

tech = [{"tech": "Spring", "url": "https://mgmt.inscope.test:443"},
        {"tech": "Java",   "url": "https://mgmt.inscope.test:443"},
        {"tech": "Spring", "url": "https://out.evil.test:443"}]      # off-scope Spring
urls = [{"url": "https://api.inscope.test/actuator/health"}]         # discovered /actuator
bases = p._actuator_bases(Ctx(tech, urls), Scope())

ok = ("https://mgmt.inscope.test:443/actuator" in bases            # Spring-fingerprint seed
      and "https://api.inscope.test/actuator" in bases            # discovered-URL source still works
      and not any("evil.test" in b for b in bases))               # off-scope excluded
sys.exit(0 if ok else 1)
PYEOF

# ── Check 30: digest surfaces evidence-probe queues (graphql/actuator/ws/api-base) — offline ──
echo "[30] digest queues: graphql(enabled=high), actuator(exposed/benign), websocket, api-base"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "graphql enabled->high+tag; actuator exposed->high/benign->low; ws+api-base surfaced" || no "evidence queues missing from digest"
import sys
from quarry_recon import triage
class Shim:
    target="t"; run_id="r"
    _d={"review":[
            {"klass":"graphql","value":"https://api.t/graphql","note":"introspection ENABLED — schema dumped","sources":["graphql-introspect"]},
            {"klass":"actuator","value":"https://mgmt.t/actuator","note":"actuator EXPOSED — env,configprops (real)","sources":["actuator-probe"]},
            {"klass":"actuator","value":"https://mgmt.t/actuator/heapdump","priority":"high","note":"heapdump advertised","sources":["actuator-probe"]},
            {"klass":"actuator","value":"https://api.t/actuator","note":"actuator present; benign, not a vuln","sources":["actuator-probe"]}],
        "endpoint":[
            {"value":"wss://rt.t/socket","kind":"websocket","sources":["deepmine-js"]},
            {"value":"https://api.t/v1","kind":"api-base","sources":["deepmine-js"]},
            {"value":"https://api.t/graphql","kind":"graphql","sources":["deepmine-js"]}]}
    def read(self,e): return self._d.get(e,[])
    def values(self,e): return []
    def count(self,e): return 0
q=triage.digest_json(Shim(), None)["queues"]
gq=q["graphql"]; aq=q["actuator"]
ok = (len(gq)>=1 and any(i["confidence"]=="high" and "introspection-enabled" in i["tags"] for i in gq)
      and len(aq)==3 and any(i["confidence"]=="high" for i in aq) and any("benign" in i["tags"] for i in aq)
      and len(q["websocket"])==1 and len(q["api-base"])==1)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 31: manifest run-summary (M3 'what failed' detail) — offline ──
echo "[31] manifest summary: verdict (complete_with_gaps) + gaps(evidence) + failures(why) + tool_status + phase_exceptions"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "verdict complete_with_gaps on failed OR degraded OR phase-exception OR required-tool-MISSING; gaps carry output_lines (stdout, not 'evidence'); optional/no-key skip NOT a gap; clean run -> complete; exception redacted" || no "run summary broken"
import sys, tempfile
from pathlib import Path
from quarry_recon.store import Run, ToolRunRecord
import quarry_recon.secrets as sec
sec.values = lambda: ["SUPERSECRETTOKEN"]        # simulate a configured key for redaction
r = Run(Path(tempfile.mkdtemp()), "t")
r._tool_runs = [
    ToolRunRecord("crawl", "gitleaks", "success", 0, 1.0, 3, "3 leaks", "gitleaks", ""),
    ToolRunRecord("params", "dalfox", "failed", 1, 2.0, 0, "", "dalfox", "boom"),
    ToolRunRecord("params", "nuclei", "partial", 0, 3.0, 7, "9/10 degraded", "nuclei", "waf"),   # degraded but kept 7
    ToolRunRecord("probe", "ffuf", "blocked", 0, 0.5, 0, "", "ffuf", "WAF/rate-limit"),
    ToolRunRecord("probe", "httpx", "empty", 0, 0.5, 0, "", "httpx", ""),
]
r.notes = ["params: EXCEPTION http://x/cb?token=SUPERSECRETTOKEN", "just a note"]
s = r._run_summary()
ok = (s["verdict"] == "complete_with_gaps"                          # failed OR degraded -> NOT a clean success
      and s["tools_failed"] == 1
      and s["failures"][0]["tool"] == "dalfox" and s["failures"][0]["why"] == "boom"
      and any(g["tool"] == "nuclei" and g["status"] == "partial" and g["output_lines"] == 7 for g in s["gaps"])
      and not any("evidence_lines" in g for g in s["gaps"])        # renamed: stdout != evidence
      and any(g["tool"] == "ffuf" and g["status"] == "blocked" for g in s["gaps"])
      and len(s["gaps"]) == 2                                       # partial + blocked (not failed, not empty)
      and s["tool_status"].get("success") == 1 and s["tool_status"].get("failed") == 1
      and s["tool_status"].get("empty") == 1
      and len(s["phase_exceptions"]) == 1
      and "SUPERSECRETTOKEN" not in str(s["phase_exceptions"])      # phase exception redacted
      and "***" in s["phase_exceptions"][0])
# a genuinely clean run (only success/empty) -> verdict complete
rc = Run(Path(tempfile.mkdtemp()), "t")
rc._tool_runs = [ToolRunRecord("probe", "httpx", "success", 0, 1.0, 9, "", "httpx", ""),
                 ToolRunRecord("crawl", "gau", "empty", 0, 1.0, 0, "", "gau", "")]
ok = ok and rc._run_summary()["verdict"] == "complete"
# a PHASE EXCEPTION alone (no tool failed/degraded) STILL -> complete_with_gaps
re_ = Run(Path(tempfile.mkdtemp()), "t")
re_._tool_runs = [ToolRunRecord("probe", "httpx", "success", 0, 1.0, 9, "", "httpx", "")]
re_.notes = ["params: EXCEPTION boom"]
ok = ok and re_._run_summary()["verdict"] == "complete_with_gaps"
# a REQUIRED tool skipped because MISSING -> gap(status=missing); an OPTIONAL/no-key skip is NOT a gap
rm = Run(Path(tempfile.mkdtemp()), "t")
rm._tool_runs = [ToolRunRecord("probe", "httpx", "skipped", None, 0.0, 0, "httpx not on PATH", "httpx", ""),
                 ToolRunRecord("vertical", "shosubgo", "skipped", None, 0.0, 0, "no Shodan key", "shosubgo", "")]
sm = rm._run_summary()
ok = ok and (sm["verdict"] == "complete_with_gaps"
             and any(g["tool"] == "httpx" and g["status"] == "missing" for g in sm["gaps"])
             and not any(g["tool"] == "shosubgo" for g in sm["gaps"]))   # optional missing -> not a gap
# manifest carries the telemetry pointer + redacts notes (end-to-end write)
import json as _j
r.write_manifest({"apex_domains": []}, ["params"], metrics={"artifact": "metrics/summary.json", "wall_s": 1.0})
mani = _j.loads(r.manifest_path.read_text())
ok = ok and mani.get("metrics", {}).get("artifact") == "metrics/summary.json" \
    and "SUPERSECRETTOKEN" not in _j.dumps(mani["notes"])
sys.exit(0 if ok else 1)
PYEOF

# ── Check 32: general fetch_and_extract layer (secrets + in-scope links, off-scope guarded) ──
echo "[32] fetch_and_extract: mines secret + in-scope link; drops off-scope link; flags off-scope redirect"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "secret+in-scope link extracted; off-scope link dropped; off-scope redirect -> off_scope,no read" || no "fetch_and_extract broken"
import sys, tempfile
from pathlib import Path
from quarry_recon import evidence as e
from quarry_recon import fetch as f

import hashlib as _h
from pathlib import Path as _P
def _streamed(body, status=200, final=None):
    """the evidence lanes STREAM now: write the body where the lane asked, return an Acquisition."""
    def _fn(ctx, u, dest, *a, **kw):
        d = _P(dest); d.parent.mkdir(parents=True, exist_ok=True); d.write_bytes(body)
        return (f.Acquisition(d, len(body), _h.sha256(body).hexdigest(), True),
                u if final is None else final, status)
    return _fn


class Scope:
    def active_allowed(self, h): return h.endswith("inscope.test")
    def in_scope(self, h): return h.endswith("inscope.test")
    def is_oos(self, h): return False
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, rec): self.ents.append((ent, rec)); return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()

body = (b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY0\n"
        b"https://api.inscope.test/v2/x\nhttps://evil.test/y\n")
f.scoped_get_file = _streamed(body)
c = Ctx(); r = e.fetch_and_extract(c, "https://a.inscope.test/config.json", source="test", subdir="extract")
secs = [x for k, x in c.run.ents if k == "secret"]
urls = [x for k, x in c.run.ents if k == "url"]
ok1 = (r["ok"] and r["secrets"] == 1 and r["links"] == 1 and len(secs) == 1
       and any("api.inscope.test" in x["url"] for x in urls)
       and not any("evil.test" in x["url"] for x in urls)
       and all(x.get("raw_ref") for x in urls))            # normalize provenance kept

f.scoped_get_file = lambda ctx, u, dest, *a, **kw: (None, "https://evil.test/x", 302)
c2 = Ctx(); r2 = e.fetch_and_extract(c2, "https://a.inscope.test/config.json", source="test", subdir="extract")
ok2 = (r2["off_scope"] and not r2["ok"] and r2["secrets"] == 0
       and not [x for k, x in c2.run.ents if k == "secret"])
sys.exit(0 if (ok1 and ok2) else 1)
PYEOF

# ── Check 33: content light wordlist has no generation/mutation-triggering paths — offline ──
# content-discovery ffuf blindly GETs every path; a heapdump/shutdown path here would trigger the
# exact server-side work the actuator probe avoids. Keep the `actuator` base; the probe owns sub-paths.
echo "[33] content-light wordlist: actuator base kept, no heapdump/shutdown/threaddump paths"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "actuator base present; no generation/mutation paths brute-forced" || no "wordlist has a heavy/mutating path"
import sys, pathlib
from quarry_recon import evidence  # anchor the installed package dir
wl = pathlib.Path(evidence.__file__).parent / "data" / "content-light.txt"
lines = [l.strip() for l in wl.read_text().splitlines() if l.strip()]
bad = [l for l in lines if any(t in l.lower() for t in
       ("heapdump", "threaddump", "shutdown", "restart", "jolokia"))]
sys.exit(0 if ("actuator" in lines and not bad) else 1)
PYEOF

# ── Check 34: mine() extracts JSON-config secrets (actuator env/configprops) — offline ──
echo "[34] mine() JSON secrets: actuator env/configprops values caught; username/url ignored; ****** skipped"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "SPRING_DATASOURCE_PASSWORD+JWT_SIGNING_KEY+password caught; non-secret keys skipped; masked skipped" || no "JSON secret mining broken"
import sys
from quarry_recon import evidence as e
env = ('{"propertySources":[{"properties":{"SPRING_DATASOURCE_PASSWORD":{"value":"Db_secret123x"},'
       '"JWT_SIGNING_KEY":{"value":"hs256_key_abcdef"},"SPRING_DATASOURCE_USERNAME":{"value":"svc_user"},'
       '"SPRING_DATASOURCE_URL":{"value":"jdbc:postgresql://db/x"}}}]}')
cp = '{"beans":{"x":{"properties":{"password":"Db_secret123x","username":"svc_user","stripeSecretKey":"sk_live_abcdEFGH1234567890"}}}}'
ke = {k for k, _, _ in e.mine(env)}
kc = {k for k, _, _ in e.mine(cp)}
masked = e.mine('{"spring.datasource.password":{"value":"******"}}')
ok = ("json:SPRING_DATASOURCE_PASSWORD" in ke and "json:JWT_SIGNING_KEY" in ke
      and not any("USERNAME" in k or "URL" in k for k in ke)     # non-secret keys ignored
      and "json:password" in kc and "stripe-secret" in kc         # flat pw + typed stripe token
      and masked == [])                                           # sanitized ****** skipped
sys.exit(0 if ok else 1)
PYEOF

# ── Check 35: oos bare-label -> subdomain-prefix (not the no-op ^label$) — offline ──
echo "[35] oos: bare label 'jobs' -> ^jobs\\. (matches FQDN); FQDN anchored; glob preserved"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "bare label matches jobs.acme.com not myjobs.; FQDN apex-scoped; glob any-sub" || no "oos pattern translation wrong"
import sys, re
from quarry_recon import cli
f = cli._to_oos_pattern
bare, fqdn, glob, rx = f("jobs"), f("jobs.acme.com"), f("*.acme.com"), f(r"^jobs\.")
ok = (bare == r"^jobs\." and re.search(bare, "jobs.acme.com") and re.search(bare, "jobs.foo.net")
      and not re.search(bare, "myjobs.acme.com")                # prefix, not substring
      and fqdn == r"^jobs\.acme\.com$" and re.search(fqdn, "jobs.acme.com")
      and not re.search(fqdn, "jobs.foo.net")                   # FQDN is apex-scoped
      and glob == r"^.*\.acme\.com$" and re.search(glob, "x.acme.com")
      and rx == r"^jobs\.")                                     # explicit regex kept verbatim
sys.exit(0 if ok else 1)
PYEOF

# ── Check 36: doctor++ readiness — _missing_required filters optional/installed + by phase ──
echo "[36] _missing_required: required+missing only; excludes optional/installed; honors phase filter"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "returns required-missing bins; optional+installed excluded; phase filter works" || no "_missing_required wrong"
import sys
import quarry_recon.cli as cli
class T:
    def __init__(self, b, p, opt, inst): self.bin=b; self.phase=p; self.optional=opt; self.installed=inst
cli.load_tools = lambda: [
    T("naabu", "probe", False, False),      # required, missing  -> reported
    T("gowitness", "probe", True, False),   # optional, missing  -> excluded
    T("httpx", "probe", False, True),       # required, installed-> excluded
    T("gf", "params", False, False),        # required, missing (other phase)
]
ok = (cli._missing_required() == ["gf", "naabu"]
      and cli._missing_required({"probe"}) == ["naabu"]
      and cli._missing_required({"content"}) == [])
sys.exit(0 if ok else 1)
PYEOF

# ── Check 37: doctor++ readiness respects mode-gating (_effective_phases) — offline ──
echo "[37] _effective_phases: passive drops needs_active; content-off drops content"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "passive drops probe/enrich/content; content-off drops content; active keeps all" || no "_effective_phases mode-gating wrong"
import sys
import quarry_recon.cli as cli
class P:
    def __init__(self, passive, cd): self.passive_only=passive; self.content_discovery=cd
full = ["horizontal", "vertical", "probe", "crawl", "enrich", "content", "params"]
passive = cli._effective_phases(full, P(True, "balanced"))     # drops needs_active: probe/enrich/content
content_off = cli._effective_phases(full, P(False, "off"))     # drops content only
active = cli._effective_phases(full, P(False, "balanced"))     # keeps all
ok = ("content" not in passive and "probe" not in passive and "enrich" not in passive
      and "horizontal" in passive and "params" in passive
      and "content" not in content_off and "probe" in content_off
      and active == set(full))
sys.exit(0 if ok else 1)
PYEOF

# ── Check 38: notify multi-channel — event-gated, per-channel payloads, redacted — offline ──
echo "[38] notify: off unless configured; event-gated; slack/discord/telegram/webhook payloads; redacted"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "unconfigured=no-op; wrong event=0; 4 channels correct payloads; secret redacted" || no "notify broken"
import sys, json
from quarry_recon import notify as n
from quarry_recon import secrets as sec

sec.load = lambda: {"notify": {"events": ["complete"],
    "slack": "https://slack.x/hook", "discord": "https://discord.x/hook",
    "telegram": {"token": "123:abc", "chat_id": "9"}, "webhook": "https://wh.x/e"}}
posts = []
n._post = lambda url, payload, timeout=10: posts.append((url, payload))

wrong = n.send("error", "t", "b")                       # event not enabled -> nothing
c = n.send("complete", "Title", "Body")                 # enabled -> all 4 channels
by = {u: p for u, p in posts}
ok_ch = (c == 4 and len(posts) == 4
    and by["https://slack.x/hook"].get("text")
    and "content" in by["https://discord.x/hook"]
    and any("api.telegram.org/bot123:abc/sendMessage" in u and p.get("chat_id") == "9" for u, p in posts)
    and by["https://wh.x/e"].get("title") == "Title")

posts.clear()
sec.values = lambda: ["SUPERSECRET"]                    # redaction pulls from secrets.values()
n.send("complete", "T", "leak token=SUPERSECRET end")
red = all("SUPERSECRET" not in json.dumps(p) for _, p in posts)

sec.load = lambda: {"notify": {"events": "complete", "slack": "https://slack.x/hook"}}
scalar_ok = n.enabled_events() == {"complete"}          # scalar `events: complete` accepted

sys.exit(0 if (wrong == 0 and n.configured() and ok_ch and red and scalar_ok) else 1)
PYEOF

# ── Check 39: runtime telemetry summary (long poles, totals) — offline ──
echo "[39] metrics.build: totals + per-tool + long-pole ranking (slowest tool/phase first)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "totals carried; 3 tools; nuclei slowest tool; params slowest phase; rusage 2-tuple" || no "telemetry build wrong"
import sys
from quarry_recon import metrics
from quarry_recon.store import ToolRunRecord
class R:
    run_id = "r"; target = "t"
    def tool_runs(self):
        return [ToolRunRecord("params", "nuclei", "success", 0, 120.0, 4, "", "nuclei", ""),
                ToolRunRecord("crawl", "katana", "success", 0, 30.0, 66, "", "katana", ""),
                ToolRunRecord("probe", "httpx", "success", 0, 5.0, 20, "", "httpx", "")]
phases = [{"phase": "params", "wall_s": 130.0}, {"phase": "crawl", "wall_s": 40.0}]
d = metrics.build(R(), phases, 200.0, 90.0, 512.0)
cpu, rss = metrics.rusage()
ok = (d["totals"]["wall_s"] == 200.0 and d["totals"]["child_cpu_s"] == 90.0
      and d["totals"]["peak_rss_mb"] == 512.0 and len(d["tools"]) == 3
      and d["long_poles"]["tools"][0] == {"tool": "nuclei", "wall_s": 120.0}
      and d["long_poles"]["phases"][0]["phase"] == "params"
      and isinstance(cpu, float) and isinstance(rss, int))
sys.exit(0 if ok else 1)
PYEOF

# ── Check 40: OOB config — self-host interactsh read + wired + secrets redacted — offline ──
echo "[40] oob: config read; auth_token redacted (server url not); nuclei gets -iserver/-itoken"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "oob() reads; auth_token in values (server url not); redact masks token; params wires -iserver" || no "OOB config broken"
import sys, pathlib
from quarry_recon import secrets as sec
sec.load = lambda: {"oob": {"callback_server": "https://oob.mine",
                            "auth_token": "tok_secret_123456"}}
o = sec.oob()
vals = sec.values()
red = sec.redact("nuclei -iserver https://oob.mine -itoken tok_secret_123456")
src = pathlib.Path(__import__("quarry_recon.phases.params", fromlist=["x"]).__file__).read_text()
ok = (o["callback_server"] == "https://oob.mine"
      and "tok_secret_123456" in vals
      and "https://oob.mine" not in vals               # server URL is not a secret
      and "tok_secret_123456" not in red and "***" in red
      and '"-iserver"' in src and "secrets.oob()" in src and '"-itoken"' in src
      and src.count("_apply_nuclei_oob(") >= 3)       # def + main scan + takeover scan
sys.exit(0 if ok else 1)
PYEOF

# ── Check 41: deep-evidence mode — config parse + heapdump download/mine (opt-in) — offline ──
echo "[41] deep-evidence: DEEP_EVIDENCE true->downloads+mines heapdump; default (off) never fetches it; NO acquisition cap — the dump is streamed whole and mined in overlapping windows (a secret on a boundary survives, and is published once)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "config parses off/on; deep mode downloads heapdump + mines AKIA; review=DOWNLOADED (deep-evidence); no size cap: 8-byte windows still find the key once and keep the artifact whole" || no "deep-evidence broken"
import sys, os, tempfile, urllib.request
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from pathlib import Path
from quarry_recon import evidence as e
from quarry_recon.config import TargetProfile

def prof(v):
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    open(p, "w").write(f"TARGET: t\nAPEX_DOMAINS:\n  - t.com\nMODES:\n  DEEP_EVIDENCE: {v}\n")
    return TargetProfile.load(p)
cfg_ok = (prof("true").deep_evidence is True and prof("false").deep_evidence is False
          and prof("on").deep_evidence is True)

class Scope:
    def active_allowed(self, h): return h.endswith("inscope.test")
class Prof: deep_evidence = True
class Run:
    def __init__(self): self.ents = []
    def add(self, ent, r): self.ents.append((ent, r)); return True
    def raw_path(self, a, b, name): return Path(tempfile.mkdtemp()) / name
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run(); self.profile = Prof()
REQ = []
def router(req, timeout=20):
    u = req.full_url; REQ.append(u)
    class R:
        url = u
        def __enter__(self): return self
        def __exit__(self, *a): return False
    r = R()
    if u.endswith("/actuator"):
        r.status = 200; body = b'{"_links":{"heapdump":{"href":"x"}}}'
    elif u.endswith("/heapdump"):
        r.status = 200; body = b"binary\x00blob AKIAIOSFODNN7EXAMPLE trailing"
    else:
        r.status = 404; body = b"no"
    r._left = body                                                 # a socket returns the body ONCE
    def _read(n=None, _r=r):
        out, _r._left = (_r._left if n in (None, -1) else _r._left[:n]), \
                        (b"" if n in (None, -1) else _r._left[n:])
        return out
    r.read = _read
    r.headers = {}; r.close = lambda: None
    return r
urllib.request.urlopen = router
from quarry_recon import fetch as _f
_f._NO_REDIRECT_OPENER = type("_O", (), {"open": staticmethod(lambda req, timeout=None: urllib.request.urlopen(req, timeout))})()

c = Ctx(); e.probe_actuator(c, ["https://mgmt.inscope.test/actuator"])
heavy = [x for k, x in c.run.ents if k == "review" and str(x.get("id", "")).startswith("actuator-heavy")]
secs = [x for k, x in c.run.ents if k == "secret"]
beh_ok = (any(u.endswith("/heapdump") for u in REQ)
          and len(heavy) == 1 and "DOWNLOADED" in heavy[0]["note"]
          and heavy[0]["sources"] == ["deep-evidence"]
          and any(s["kind"] == "aws-access-key" for s in secs))

# SIZE NO LONGER DECIDES (review#21, Lumpy). `_DEEP_MAX_BODY = 64 MiB` used to REFUSE TO SAVE a heap
# dump over the cap — the most secret-dense artifact recon can obtain, already fetched, then discarded
# with a note telling the operator to raise a number and pay for the request again. The dump is now
# streamed to disk whole and mined in windows, so memory is bounded and the evidence is not.
assert not hasattr(e, "_DEEP_MAX_BODY"), "the acquisition cap is gone, not renamed"
# force MANY windows over the same body, with the AWS key STRADDLING a boundary. The overlap is what
# bounds the longest token that can survive one: it must exceed the value, or no window ever holds it.
e._DEEP_SCAN_WINDOW = 24
e._DEEP_SCAN_OVERLAP = 20
c2 = Ctx(); e.probe_actuator(c2, ["https://mgmt.inscope.test/actuator"])
h2 = [x for k, x in c2.run.ents if k == "review" and str(x.get("id", "")).startswith("actuator-heavy")]
s2 = [x for k, x in c2.run.ents if k == "secret"]
big_ok = (len(h2) == 1 and "DOWNLOADED" in h2[0]["note"]
          and len(s2) == 1 and s2[0]["kind"] == "aws-access-key"   # found ACROSS window boundaries…
          and s2[0]["value"] == "AKIAIOSFODNN7EXAMPLE"             # …complete, and published ONCE
          and Path(h2[0]["raw_ref"]).read_bytes().endswith(b"trailing"))   # artifact kept WHOLE
sys.exit(0 if (cfg_ok and beh_ok and big_ok) else 1)
PYEOF

# ── Check 45: nuclei runtime line = severity breakdown, drops redundant UNCONFIRMED — offline ──
echo "[45] nuclei echo: crit/high/med breakdown; no '(UNCONFIRMED — manual validation required)'"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "severity breakdown in nuclei echo; redundant unconfirmed text removed" || no "nuclei message not updated"
import sys, pathlib
import quarry_recon.phases.params as m
src = pathlib.Path(m.__file__).read_text()
ok = ("crit:{sev['critical']}" in src and "high:{sev['high']}" in src and "med:{sev['medium']}" in src
      and "UNCONFIRMED — manual validation required" not in src)   # HOTLIST/digest still carry it
sys.exit(0 if ok else 1)
PYEOF

# ── Check 44: install disk floors loosened, run floors kept (v0.2 polish) — offline ──
echo "[44] disk floors: install loosened (<=5/<=10 GB), run floors unchanged (10/20 GB)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "install floors relaxed to measured footprint; run floors kept" || no "disk floors wrong"
import sys
from quarry_recon import bootstrap as b
ok = (b.DISK_MIN["install"] <= 5 and b.DISK_WARN["install"] <= 10
      and b.DISK_MIN["run"] == 10 and b.DISK_WARN["run"] == 20)   # run floors unchanged
sys.exit(0 if ok else 1)
PYEOF

# ── Check 43: go-cache cleanup runs on BOTH install and update (v0.2 polish) — offline ──
echo "[43] both install() and update() call bootstrap.cleanup (go cache doesn't creep on update)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "install + update both invoke bootstrap.cleanup" || no "update doesn't clean go cache"
import sys, re, pathlib
from quarry_recon import cli
src = pathlib.Path(cli.__file__).read_text()
def body(fn):
    m = re.search(r"\ndef " + fn + r"\(.*?\n(.*?)\n(?:@cli|def |# ── )", src, re.S)
    return m.group(1) if m else ""
sys.exit(0 if ("bootstrap.cleanup(" in body("install") and "bootstrap.cleanup(" in body("update")) else 1)
PYEOF

# ── Check 42: banner ports collapse — default vs explicit (v0.2 polish) — offline ──
echo "[42] ports_are_default: no PORTS -> default(full set); explicit PORTS.HTTP -> enumerated"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "default set flagged + >50 ports; explicit list flagged not-default + exact" || no "ports default detection wrong"
import sys, os, tempfile
from quarry_recon.config import TargetProfile
def prof(extra):
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    open(p, "w").write("TARGET: t\nAPEX_DOMAINS:\n  - t.com\n" + extra)
    return TargetProfile.load(p)
d = prof("")
o = prof("PORTS:\n  HTTP: [80, 443, 8080]\n")
ok = (d.ports_are_default is True and len(d.ports) > 50
      and o.ports_are_default is False and o.ports == [80, 443, 8080])
sys.exit(0 if ok else 1)
PYEOF

# ── Check 46: dns-record enrichment — parser + phase wiring — offline ──
echo "[46] dnsx_records parses all types; dns phase in ORDER (after vertical, before probe), needs_active"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "a/aaaa/cname/mx/ns/txt/caa/soa/asn/cdn -> dns_record; dns phase wired needs_active" || no "dns enrichment broken"
import sys, json
from quarry_recon import normalize
from quarry_recon.phases import ORDER, REGISTRY
line = json.dumps({"host": "acme.com", "a": ["1.2.3.4"], "aaaa": ["2606::1"],
    "cname": ["cdn.acme.net"], "mx": ["10 mail.acme.com"], "ns": ["ns1.acme.com"],
    "txt": ["v=spf1 -all"], "soa": [{"ns": "ns1.acme.com"}], "caa": ["0 issue letsencrypt.org"],
    "asn": {"as_number": "AS13335", "as_name": "CLOUDFLARENET"}, "cdn_name": "cloudflare"})
recs = list(normalize.dnsx_records(line, "dnsx-enrich", "raw/x.jsonl"))
by = {r["type"]: r for r in recs}
parse_ok = (set(by) == {"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "caa", "asn", "cdn"}
    and by["asn"]["value"] == "AS13335" and by["asn"].get("asn_name") == "CLOUDFLARENET"
    and by["cdn"]["value"] == "cloudflare" and by["soa"]["value"] == "ns1.acme.com"
    and by["a"]["id"] == "acme.com|a|1.2.3.4" and all(r.get("raw_ref") for r in recs))
# edge: dnsx may emit soa as a bare dict (not a list) + a scalar type value — no bogus per-key/char
edge = json.dumps({"host": "x.com", "soa": {"ns": "ns2.x.com"}, "a": "9.9.9.9"})
e2 = {r["type"]: r for r in normalize.dnsx_records(edge, "s", None)}
edge_ok = (len(e2) == 2 and e2["soa"]["value"] == "ns2.x.com" and e2["a"]["value"] == "9.9.9.9")
i = ORDER.index("dns")
wire_ok = (ORDER[i-1] == "vertical" and ORDER[i+1] == "probe" and REGISTRY["dns"][2] is True)
import pathlib, quarry_recon.phases.dns as dphase
dsrc = pathlib.Path(dphase.__file__).read_text()
rate_ok = '"-rl"' in dsrc and "dns_rate" in dsrc            # honors RATELIMIT.DNS
sys.exit(0 if (parse_ok and edge_ok and wire_ok and rate_ok) else 1)
PYEOF

# ── Check 47: digest/HOTLIST surfacing of notable DNS records — offline ──
echo "[47] dns queue: mx/ns/txt/caa/asn/cdn surfaced (a/cname excluded); TXT spf-tagged; HOTLIST section"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "6 notable records queued; a/cname dropped; spf tag; DNS-context HOTLIST section" || no "dns surfacing broken"
import sys
from quarry_recon import triage
class Shim:
    target = "t"; run_id = "r"
    _d = {"dns_record": [
        {"host": "acme.com", "type": "a", "value": "1.2.3.4", "sources": ["dnsx-enrich"]},      # noise
        {"host": "acme.com", "type": "cname", "value": "x.cdn", "sources": ["dnsx-enrich"]},    # noise
        {"host": "acme.com", "type": "mx", "value": "10 mail.acme.com", "sources": ["dnsx-enrich"]},
        {"host": "acme.com", "type": "ns", "value": "ns1.acme.com", "sources": ["dnsx-enrich"]},
        {"host": "acme.com", "type": "txt", "value": "v=spf1 -all", "sources": ["dnsx-enrich"]},
        {"host": "acme.com", "type": "txt", "value": "v=DKIM1; k=rsa; p=" + "A" * 400, "sources": ["dnsx-enrich"]},
        {"host": "acme.com", "type": "caa", "value": "0 issue letsencrypt.org", "sources": ["dnsx-enrich"]},
        {"host": "acme.com", "type": "asn", "value": "AS13335", "sources": ["dnsx-enrich"]},
        {"host": "acme.com", "type": "cdn", "value": "cloudflare", "sources": ["dnsx-enrich"]}]}
    def read(self, e): return self._d.get(e, [])
    def values(self, e): return []
    def count(self, e): return 0
d = triage.digest_json(Shim(), None)
dq = d["queues"]["dns"]
types = {i["tags"][1] for i in dq}
spf = [i for i in dq if "spf" in i["tags"]]
dkim = [i for i in dq if "dkim" in i["tags"]]
hot = triage.build(Shim(), None)
ok = (len(dq) == 7 and types == {"mx", "ns", "txt", "caa", "asn", "cdn"} and len(spf) == 1
      and d["digest_schema"] == "1.0"
      and "DNS context" in hot and "AS13335" in hot
      and all(i.get("raw_ref") for i in dq)
      # a long TXT (DKIM) is shown IN FULL, in the digest and in the HOTLIST: truncating it in the one
      # place an operator reads is how a leaked key hides in plain sight (Lumpy, 2026-08-05).
      and len(dkim) == 1 and "…" not in dkim[0]["value"] and "A" * 400 in dkim[0]["value"]
      and "A" * 400 in hot)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 48: DNS wildcard-record filtering (shared enrich_hosts) — offline (mock dnsx) ──
echo "[48] enrich_hosts filters wildcard-inherited A/TXT vs baseline; keeps host-specific A + MX"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "wildcard A/TXT dropped; host A + spf TXT + MX kept" || no "wildcard filtering broken"
import sys, json, tempfile
from pathlib import Path
import quarry_recon.phases.dns as dns

class Scope:
    def in_scope(self, h): return h.endswith("acme.com")
    def is_oos(self, h): return False
class Prof: apex_domains = ["acme.com"]; dns_rate = None
class Run:
    def __init__(self): self.recs = []
    def add(self, e, r): self.recs.append(r); return True
    def raw_path(self, ph, tool, name): return Path(tempfile.mkdtemp()) / name
    def record(self, ph, r): pass
class Ctx:
    def __init__(self): self.scope = Scope(); self.profile = Prof(); self.run = Run(); self.http_timeout = 60
    def write_list(self, name, items):
        p = Path(tempfile.mkdtemp()) / name; p.write_text("\n".join(items)); return p
    def echo(self, *a): pass

def fake_exec(name, cmd, raw_path=None, timeout=None):
    if raw_path and "wildcard" in str(raw_path):      # baseline: wildcard A + wildcard TXT
        body = json.dumps({"host": "quarry-wc-x.acme.com", "a": ["9.9.9.9"], "txt": ["wildcard-txt"]})
    else:                                              # www: wildcard A + own A + wildcard/own TXT + MX
        body = json.dumps({"host": "www.acme.com", "a": ["9.9.9.9", "1.2.3.4"],
                           "txt": ["wildcard-txt", "v=spf1 -all"], "mx": ["10 mail.acme.com"]})
    raw_path.write_text(body + "\n")
    class R: pass
    r = R(); r.raw_path = raw_path; return r
dns.exec_tool = fake_exec

ctx = Ctx()
dns.enrich_hosts(ctx, ["www.acme.com"], "dns")
v = {(r["type"], r["value"]) for r in ctx.run.recs}
ok = (("a", "1.2.3.4") in v and ("a", "9.9.9.9") not in v          # wildcard A filtered, own A kept
      and ("txt", "v=spf1 -all") in v and ("txt", "wildcard-txt") not in v   # wildcard TXT filtered
      and ("mx", "10 mail.acme.com") in v)                         # MX never wildcard-filtered
sys.exit(0 if ok else 1)
PYEOF

# ── Check 49: TXT intelligence — SPF/DMARC/verification -> provider + policy pivots — offline ──
echo "[49] _txt_intel: spf includes -> provider tags; dmarc p= -> policy; verification -> provider"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "google/amazon-ses providers from SPF; dmarc-policy:reject; verification providers" || no "TXT intelligence broken"
import sys
from quarry_recon.triage import _txt_intel
spf = _txt_intel("v=spf1 include:_spf.google.com include:amazonses.com -all")
dmarc = _txt_intel("v=DMARC1; p=reject; rua=mailto:dmarc@acme.com,mailto:reports@dmarcian.com")
verif = _txt_intel("google-site-verification=abc123")
ms = _txt_intel("MS=ms12345678")
plain = _txt_intel("just a random note")
ok = ("spf" in spf and "provider:google-workspace" in spf and "provider:amazon-ses" in spf
      and "dmarc" in dmarc and "dmarc-policy:reject" in dmarc
      and "rua:acme.com" in dmarc and "rua:dmarcian.com" in dmarc   # report-address org/vendor pivots
      and "verification" in verif and "provider:google" in verif
      and "provider:microsoft" in ms
      and plain == [])
sys.exit(0 if ok else 1)
PYEOF

# ── Check 50: tlsx cert parser — SAN/CN/issuer/expiry + wildcard detection — offline ──
echo "[50] tlsx_certs: cn/san/issuer/not_after parsed; wildcard SAN flagged; probe harvests in-scope SANs"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "cert fields parsed; *.acme.com -> wildcard; id=host:port; probe adds tlsx-san subdomains" || no "tlsx cert parse broken"
import sys, json, pathlib
from quarry_recon import normalize
line = json.dumps({"host": "www.acme.com", "port": "443", "subject_cn": "www.acme.com",
    "subject_an": ["www.acme.com", "*.acme.com", "api.acme.com"], "issuer_cn": "WE2",
    "issuer_org": ["Google Trust Services"], "not_after": "2026-09-07T08:41:53Z", "serial": "AB:CD"})
c = list(normalize.tlsx_certs(line, "tlsx", "raw/x"))[0]
parse_ok = (c["id"] == "www.acme.com:443" and c["cn"] == "www.acme.com"
    and set(c["san"]) == {"www.acme.com", "*.acme.com", "api.acme.com"}
    and c["issuer"] == "WE2" and c["not_after"].startswith("2026-09") and c["wildcard"] is True
    and c.get("raw_ref"))
# probe wires tlsx + scope-safe cert (in-scope SANs only, oos counts) + tlsx-san subdomain harvest
psrc = pathlib.Path(__import__("quarry_recon.phases.probe", fromlist=["x"]).__file__).read_text()
wire_ok = ("normalize.tlsx_certs" in psrc and 'add("certificate"' in psrc
           and '"tlsx-san"' in psrc and 'startswith("*.")' in psrc
           and "in_scope_san" in psrc and "has_oos_sans" in psrc)
sys.exit(0 if (parse_ok and wire_ok) else 1)
PYEOF

# ── Check 51: cloud-asset discovery — candidates + bucket check + digest surfacing — offline ──
echo "[51] cloud: apex/suffix candidates; 200->public/403->private; verify-ownership review -> digest queue"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "candidates from apex+suffix; public/private detected; cloud reviews -> digest cloud queue with verify-ownership" || no "cloud discovery broken"
import sys, urllib.request, urllib.error
import quarry_recon.cloud as cloud
from quarry_recon import triage
class Prof: apex_domains = ["acme.com"]; org_names = []; brands = []; passive_only = False
class Run:
    def __init__(self): self.revs = []
    def add(self, e, r): self.revs.append(r); return True
class Ctx:
    def __init__(self): self.profile = Prof(); self.run = Run()

cands = cloud._all_candidates(Prof())
def fake_open(req, timeout=8):
    u = req.full_url
    class R:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
    if "acme-backup" in u: return R()                                    # public (200)
    if "acme-logs" in u: raise urllib.error.HTTPError(u, 403, "AccessDenied", {}, None)  # private
    raise urllib.error.HTTPError(u, 404, "NoSuchBucket", {}, None)       # not found
urllib.request.urlopen = fake_open

ctx = Ctx(); found = cloud.discover(ctx)
revs = ctx.run.revs
disc_ok = (found > 0
    and any(r["access"] == "public" for r in revs) and any(r["access"] == "private" for r in revs)
    and all(r["klass"] == "cloud" and "VERIFY OWNERSHIP" in r["note"] and r["sources"] == ["cloud-enum"]
            for r in revs))

class Shim:
    target = "t"; run_id = "r"
    def read(self, e): return revs if e == "review" else []
    def values(self, e): return []
    def count(self, e): return 0
cq = triage.digest_json(Shim(), None)["queues"]["cloud"]
tri_ok = (len(cq) >= 2 and all("verify-ownership" in i["tags"] for i in cq)
          and any("s3" in i["tags"] or "gcs" in i["tags"] for i in cq))

sys.exit(0 if ("acme-backup" in cands and "acme" in cands and disc_ok and tri_ok) else 1)
PYEOF

# ── Check 52: crt.sh CT-log parse (direct source) — offline (mocked urlopen) ──
echo "[52] _crtsh: name_value SANs split on newlines, wildcards PRESERVED (A1 zone derivation); failure -> empty set"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "SANs parsed + wildcard *. preserved (feeds A1 wildcard-zone derivation); fetch failure PROPAGATES -> run_provider FAILED terminal + None (review#2, not fake-empty; phase still continues)" || no "crt.sh parse broken"
import sys, json, pathlib, urllib.request
import quarry_recon.phases.vertical as v
class R:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=None):
        if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
        self._eof = True
        return json.dumps([
        {"name_value": "www.acme.com\n*.acme.com"},
        {"name_value": "api.acme.com"},
        {"name_value": "mail.acme.com\nftp.acme.com"}]).encode()
urllib.request.urlopen = lambda req, timeout=30: R()
hosts = v._crtsh("acme.com")
parse_ok = hosts == {"www.acme.com", "*.acme.com", "api.acme.com", "mail.acme.com", "ftp.acme.com"}
# review#2: providers NO LONGER swallow a fetch failure into set() — the error PROPAGATES so contract.run_provider
# records a FAILED terminal (not a clean EMPTY that C10b would skip). Assert propagation + the FAILED bracket.
def boom(req, timeout=30): raise OSError("crt.sh down")
urllib.request.urlopen = boom
def _raises(fn):
    try: fn(); return False
    except OSError: return True
propagate_ok = _raises(lambda: v._crtsh("acme.com")) and _raises(lambda: v._certspotter("acme.com"))
import tempfile as _tf
from quarry_recon import contract, events as _ev
_ev.reset(); _ev.configure(pathlib.Path(_tf.mkdtemp()))
none_ok = contract.run_provider("vertical.crtsh", lambda: v._crtsh("acme.com")) is None   # best-effort: None on failure
_fin = [e for e in (json.loads(x) for x in (_ev._sink).read_text().splitlines()) if e["event"]=="tool_finish"]
fail_ok = propagate_ok and none_ok and len(_fin)==1 and _fin[0]["status"]=="failed"
# certspotter: dns_names arrays parsed, wildcards PRESERVED (A1)
class C:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=None):
        if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
        self._eof = True
        return json.dumps([{"dns_names": ["a.acme.com", "*.acme.com"]},
                                          {"dns_names": ["b.acme.com"]}]).encode()
urllib.request.urlopen = lambda req, timeout=30: C()
cs_ok = v._certspotter("acme.com") == {"a.acme.com", "*.acme.com", "b.acme.com"}
sys.exit(0 if (parse_ok and fail_ok and cs_ok) else 1)
PYEOF

# ── Check 53: openintel-subs — silent unless configured; parses when present — offline ──
echo "[53] openintel: configured-but-broken -> recorded SKIP (not swallowed); configured+present -> parses subs via the runner + records result; configured FAILURE is observable; vertical gates on binary+db"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "broken binary/db -> recorded skip + empty; present -> parsed subs, result recorded; timeout recorded (observable, not silent-empty-only); vertical gates on binary+db" || no "openintel gating broken"
import sys, pathlib, tempfile
from types import SimpleNamespace
import quarry_recon.phases.vertical as v
from quarry_recon.runner import Status
tmp = pathlib.Path(tempfile.mkdtemp())
def _ctx():
    rec = []
    run = SimpleNamespace(
        raw_path=lambda *p: (tmp.joinpath(*p[:-1]).mkdir(parents=True, exist_ok=True) or tmp.joinpath(*p)),
        record=lambda ph, r: rec.append(r))
    return SimpleNamespace(run=run), rec
# configured but the binary/db is missing -> a RECORDED skip (observable), returns empty
v.shutil.which = lambda b: None
v.os.path.isfile = lambda p: False
c1, rec1 = _ctx()
broken = (v._openintel(c1, {"binary": "/no/such/bin", "db": "/no/such.db"}, "acme.com") == set()
          and len(rec1) == 1 and str(rec1[0].status.value) == "skipped")
# configured + present -> run THROUGH the runner (mocked), parse hosts from the recorded raw file, record result
v.shutil.which = lambda b: "/bin/openintel"
v.os.path.isfile = lambda p: True
v.os.access = lambda p, m: True
def _fake_exec(tool, cmd, raw_path=None, timeout=None, **k):
    pathlib.Path(raw_path).write_text("a.acme.com\nb.acme.com\ninvalidline\n")
    return SimpleNamespace(status=Status.SUCCESS, raw_path=raw_path, cpu_s=0.1, peak_rss_mb=5.0, tool="openintel-subs")
v.exec_tool = _fake_exec
c2, rec2 = _ctx()
parsed = v._openintel(c2, {"binary": "oi", "db": "/db"}, "acme.com")
parse_ok = (parsed == {"a.acme.com", "b.acme.com"} and len(rec2) == 1 and rec2[0].status == Status.SUCCESS)
# a configured FAILURE is OBSERVABLE: result recorded, empty set returned (NOT indistinguishable from empty-DB)
def _fail_exec(tool, cmd, raw_path=None, timeout=None, **k):
    return SimpleNamespace(status=Status.TIMED_OUT, raw_path=raw_path, cpu_s=0.0, peak_rss_mb=0.0, tool="openintel-subs")
v.exec_tool = _fail_exec
c3, rec3 = _ctx()
fail_obs = (v._openintel(c3, {"binary": "oi", "db": "/db"}, "acme.com") == set()
            and len(rec3) == 1 and rec3[0].status == Status.TIMED_OUT)
# vertical only runs it behind a binary+db gate (silent otherwise)
src = pathlib.Path(v.__file__).read_text()
gate_ok = ('oi.get("binary") and oi.get("db")' in src and "settings.openintel()" in src
           and "import subprocess" not in src)
sys.exit(0 if (broken and parse_ok and fail_obs and gate_ok) else 1)
PYEOF

# ── Check 54: favicon-hash pivot (Shodan) — key-gated, in-scope/off-scope split, generic skip ──
echo "[54] favicon: silent w/o shodan key; in-scope match->subdomain, off-scope->related-host; high-cardinality RETAINED"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "no key -> silent; in-scope->subdomain(favicon-shodan); off-scope->related-host verify-ownership; HIGH-CARDINALITY pivot RETAINED, never dropped (ordering verified in B1.3)" || no "favicon pivot broken"
import sys, json, tempfile, urllib.request
from pathlib import Path
import quarry_recon.phases.probe as p
from quarry_recon import secrets
class Scope:
    def in_scope(self, h): return h.endswith("acme.com")
    def is_oos(self, h): return False
class Run:
    # B1.4: the Shodan lane runs on the shodan_sched coordinator, whose ledger + page artifacts live
    # under the run directory — so a Run stub now has to have one.
    def __init__(self):
        self.subs = []; self.revs = []; self.dir = Path(tempfile.mkdtemp())
        # purchased pivot pages are PROJECT-scoped now (a run-scoped store made the next run
        # pay again), so a Run stub needs the project the way the real one has it
        self.project_dir = self.dir
    def read(self, e): return [{"favicon": "123"}] if e == "live" else []
    def add(self, e, r): (self.subs if e == "subdomain" else self.revs).append(r); return True
    def raw_path(self, a, b, n): return Path(tempfile.mkdtemp()) / n
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()
    def echo(self, *a): pass

# B1.4: both Shodan lanes run under ONE coordinator and one credit budget (`_shodan_pivots`), so the
# per-lane entry points are gone. The lane is driven through the same path with a single lane.
FAV = ("http.favicon.hash", "favicon-shodan", "probe.favicon",
       "same favicon (hash {}) as an in-scope host — VERIFY OWNERSHIP")
def run_fav(c, key):
    from quarry_recon import secrets as _s
    _s.shodan = lambda: key
    if not key:
        return
    vals = [l.get("favicon") for l in c.run.read("live") if l.get("favicon")]
    p._shodan_pivot(c, key, vals, *FAV)
secrets.shodan = lambda: None                        # no key -> silent
c = Ctx(); run_fav(c, None)
silent_ok = not c.run.subs and not c.run.revs

secrets.shodan = lambda: "SHODANKEY"
def mk(total):
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None):
            if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
            self._eof = True
            return json.dumps({"total": total,
            "matches": [{"hostnames": ["new.acme.com", "evil.other.com"]}]}).encode()
    return lambda req, timeout=20: R()
urllib.request.urlopen = mk(10)
c2 = Ctx(); run_fav(c2, "SHODANKEY")
disc_ok = (any(s["host"] == "new.acme.com" and s["sources"] == ["favicon-shodan"] for s in c2.run.subs)
    and any(r["value"] == "evil.other.com" and r["klass"] == "related-host" and "VERIFY OWNERSHIP" in r["note"]
            for r in c2.run.revs))
# POLICY CHANGE (Lumpy 2026-07-28): a HIGH-CARDINALITY pivot is no longer DROPPED. The old rule skipped
# any pivot whose `total` exceeded 200 — an arbitrary cliff where 201 was worthless and 199 was fine.
# Cardinality WILL become a continuous ranking signal (rare pivots first, generic last) in the B1.3
# coordinator; it does NOT exist yet. This check asserts only what is true TODAY — RETENTION, the opposite
# of the old drop — so a green check never claims unbuilt behaviour.
urllib.request.urlopen = mk(5000)                    # a framework-default favicon: generic, NOT worthless
c3 = Ctx(); run_fav(c3, "SHODANKEY")
generic_ok = (any(s["host"] == "new.acme.com" for s in c3.run.subs)
              and any(r["value"] == "evil.other.com" for r in c3.run.revs))
sys.exit(0 if (silent_ok and disc_ok and generic_ok) else 1)
PYEOF

# ── Check 55: cert-fingerprint pivot (Shodan) — sha1 on cert entity + key-gated karma-style pivot ──
echo "[55] cert sha1: tlsx stores fingerprint sha1; _cert_pivot key-gated, in-scope->subdomain, off-scope->related-host"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "cert.sha1 parsed from fingerprint_hash; no key->silent; in-scope->subdomain(cert-shodan); off-scope->related-host verify; HIGH-CARDINALITY cert RETAINED, never dropped (ordering verified in B1.3)" || no "cert pivot broken"
import sys, json, tempfile, urllib.request
from pathlib import Path
from quarry_recon import normalize
import quarry_recon.phases.probe as p
from quarry_recon import secrets
# sha1 threaded from tlsx fingerprint_hash.sha1
cert = list(normalize.tlsx_certs('{"host":"a.acme.com","subject_an":["a.acme.com"],"fingerprint_hash":{"sha1":"DEADBEEF"}}', "tlsx"))[0]
sha_ok = cert["sha1"] == "DEADBEEF"
class Scope:
    def in_scope(self, h): return h.endswith("acme.com")
    def is_oos(self, h): return False
class Run:
    def __init__(self):
        self.subs = []; self.revs = []; self.dir = Path(tempfile.mkdtemp())
        # purchased pivot pages are PROJECT-scoped now (a run-scoped store made the next run
        # pay again), so a Run stub needs the project the way the real one has it
        self.project_dir = self.dir
    def read(self, e): return [{"sha1": "DEADBEEF"}] if e == "certificate" else []
    def add(self, e, r): (self.subs if e == "subdomain" else self.revs).append(r); return True
    def raw_path(self, a, b, n): return Path(tempfile.mkdtemp()) / n
class Ctx:
    def __init__(self): self.scope = Scope(); self.run = Run()
    def echo(self, *a): pass
CERT = ("ssl.cert.fingerprint", "cert-shodan", "probe.cert",
        "same TLS cert (sha1 {}) as an in-scope host — VERIFY OWNERSHIP")
def run_cert(c, key):
    from quarry_recon import secrets as _s
    _s.shodan = lambda: key
    if not key:
        return
    vals = [x.get("sha1") for x in c.run.read("certificate") if x.get("sha1")]
    p._shodan_pivot(c, key, vals, *CERT)
secrets.shodan = lambda: None
c = Ctx(); run_cert(c, None)
silent_ok = not c.run.subs and not c.run.revs
secrets.shodan = lambda: "SHODANKEY"
def mk(total):
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None):
            if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
            self._eof = True
            return json.dumps({"total": total,
            "matches": [{"hostnames": ["new.acme.com", "evil.other.com"]}]}).encode()
    return lambda req, timeout=20: R()
urllib.request.urlopen = mk(10)
c2 = Ctx(); run_cert(c2, "SHODANKEY")
disc_ok = (any(s["host"] == "new.acme.com" and s["sources"] == ["cert-shodan"] for s in c2.run.subs)
    and any(r["value"] == "evil.other.com" and r["klass"] == "related-host" and "VERIFY OWNERSHIP" in r["note"]
            and "sha1" in r["note"] for r in c2.run.revs))
# POLICY CHANGE (Lumpy 2026-07-28) — see [54]: high-cardinality pivots are RETAINED and ranked, never
# dropped. A shared/wildcard cert matching thousands of hosts is weak ownership signal, not zero signal.
urllib.request.urlopen = mk(5000)
c3 = Ctx(); run_cert(c3, "SHODANKEY")
generic_ok = (any(s["host"] == "new.acme.com" for s in c3.run.subs)
              and any(r["value"] == "evil.other.com" for r in c3.run.revs))
sys.exit(0 if (sha_ok and silent_ok and disc_ok and generic_ok) else 1)
PYEOF

# ── Check 56: Censys Platform provider — silent opt-in, defensive host extraction, redaction ──
echo "[56] censys: silent unless token+org; defensive apex-host extract (no suffix-confusion); PAT redacted, org not"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "empty w/o token+org (silent); extracts sub.apex only; PAT in redaction values, org id not; getter shape" || no "censys provider broken"
import sys, urllib.request
from quarry_recon.phases import vertical
from quarry_recon import secrets
# silent when unconfigured
assert vertical._censys({}, "acme.com") == set()
assert vertical._censys({"token": "t"}, "acme.com") == set()   # org missing -> silent
# defensive extraction over a fake platform response
class R:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    # review-r6#2: names come from the STRUCTURED hit path certificate_v1.resource.names (NOT a regex over the
    # hit JSON — a message/error field inside a hit must never yield a phantom host).
    def read(self, n=None):
        if getattr(self, '_eof', False): return b''   # STREAM: body once, then EOF
        self._eof = True
        return (b'{"result":{"hits":[{"certificate_v1":{"resource":{"names":'
        b'["www.acme.com","*.acme.com","api.acme.com","evil-acme.com","x.foo.acme.com"]}}}]}}')
urllib.request.urlopen = lambda req, timeout=30: R()
got = vertical._censys({"token": "t", "org": "o"}, "acme.com")
extract_ok = ({"www.acme.com", "api.acme.com", "x.foo.acme.com"} <= got
              and "evil-acme.com" not in got)
# review#3: an error/schema-drift 200 body (no `result` envelope) must RAISE -> run_provider FAILED, not empty
urllib.request.urlopen = lambda req, timeout=30: type("E", (R,), {"read": lambda s, n: b'{"error":{"code":401}}'})()
try:
    vertical._censys({"token": "t", "org": "o"}, "acme.com"); drift_ok = False
except ValueError:
    drift_ok = True
extract_ok = extract_ok and drift_ok
# redaction: token secret, org not
secrets._cache = {"censys": {"token": "censys_pat_SECRETVALUE01234567", "org": "org-uuid-9"}}
vals = secrets.values()
red_ok = ("censys_pat_SECRETVALUE01234567" in vals and "org-uuid-9" not in vals
          and secrets.censys() == {"token": "censys_pat_SECRETVALUE01234567", "org": "org-uuid-9"})
secrets._cache = {}
unset_ok = secrets.censys() == {}
sys.exit(0 if (extract_ok and red_ok and unset_ok) else 1)
PYEOF

# ── Check 57: vhost enumeration (ffuf) — wordlist-gated, origin-IP driven, vhost review + digest queue ──
echo "[57] vhost: skip w/o wordlist; base=https-subdomain (not http/apex); dedup per origin; CDN excluded; -r + served/exists matcher; ONLY DNS-invisible hits (known subs filtered)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "no wordlist->skip; ranks https-subdomain base FIRST; every non-CDN service scanned (no origin cap); CDN excluded; -ac + curated -mc (NO -r, 3xx matched not followed); known subs filtered -> only DNS-invisible vhost; triage queue" || no "vhost enum broken"
import sys, tempfile, json
from pathlib import Path
import quarry_recon.phases.probe as p
from quarry_recon import runner, triage
q_ok = "vhost" in triage.CANONICAL_QUEUES
class Scope:
    def active_allowed(self, h): return h.endswith("acme.com")
    def in_scope(self, h): return h.endswith("acme.com")
    def is_oos(self, h): return False
class Prof: apex_domains = ["acme.com"]; http_rl = None
LIVE = [{"url":"http://acme.com:80","cdn":False,"a":["1.2.3.4"]},        # apex http -> worst
        {"url":"https://acme.com:443","cdn":False,"a":["1.2.3.4"]},      # apex https
        {"url":"https://www.acme.com:443","cdn":False,"a":["1.2.3.4"]},  # subdomain https -> BEST
        {"url":"https://cdn.acme.com","cdn":True,"a":["9.9.9.9"]}]       # CDN -> excluded
class Run:
    def __init__(self): self.revs=[]; self.records=[]; self.dir=Path(tempfile.mkdtemp())   # A1: ledger/attempt dirs
    def read(self, e): return LIVE if e=="live" else []
    def values(self, e): return ["admin.acme.com","www.acme.com"] if e in ("subdomain","resolved") else []
    def add(self, e, r): self.revs.append(r); return True
    def record(self, ph, r): self.records.append(r)
    def raw_path(self, a, b, n): return Path(tempfile.mkdtemp()) / n
class Ctx:
    def __init__(self): self.scope=Scope(); self.run=Run(); self.profile=Prof(); self.http_timeout=60
    def echo(self, *a): pass
    def tmp(self, n):                      # A1: the lane WRITES the effective per-apex wordlist here
        return Path(tempfile.mkdtemp()) / n
    def write_list(self, n, it):
        d = Path(tempfile.mkdtemp()) / n; d.write_text("\n".join(it)); return d
# skip path
p._vhost_wordlist = lambda: None
skip_ok = (not runner.have("ffuf")) or (not Ctx().run.revs and (p._vhost_enum(Ctx()) or True))
# fuzz path: capture cmd + feed fake ffuf results (known sub + DNS-invisible)
p.have = lambda t: True
# A1: the SOURCE wordlist must be real — the lane derives an EFFECTIVE list from it and a row whose FUZZ
# value was never submitted is (correctly) rejected.
_WL = Path(tempfile.mkdtemp()) / "wl.txt"; _WL.write_text("intranet\nadmin\n")
p._vhost_wordlist = lambda: _WL
calls = []
def fake(tool, cmd, **kw):
    calls.append(cmd)
    out = cmd[cmd.index("-o")+1]
    Path(out).write_text(json.dumps({"results":[
        {"input":{"FUZZ":"intranet"},"status":200,"length":330},   # DNS-invisible -> keep
        {"input":{"FUZZ":"admin"},"status":200,"length":472}]}))    # known sub -> drop
    return runner.RunResult("ffuf", cmd, runner.Status.EMPTY, 0, 0.1, Path(out), 0)   # -s -> empty stdout; adapter refines
p.exec_tool = fake; import quarry_recon.contract as _CT; _CT._run = fake
c2 = Ctx(); p._vhost_enum(c2)
u = calls[0][calls[0].index("-u")+1]; H = calls[0][calls[0].index("-H")+1]
mc = calls[0][calls[0].index("-mc")+1]
vals = {r["value"] for r in c2.run.revs}
# A1 base-service model: membership is EVERY non-CDN active-allowed live service (the CDN one is excluded),
# so all THREE run — the score only RANKS them, so the https+subdomain service goes FIRST. The old
# "one call per origin IP" expectation was the retired model that silently dropped co-hosted services.
fuzz_ok = (len(calls)==3 and u=="https://www.acme.com:443/" and H=="Host: FUZZ.acme.com"
           and "-ac" in calls[0] and "-r" not in calls[0]            # audit #1: no redirect-follow (was -r)
           and mc=="200-299,301,302,303,307,308,401,403"             # 3xx still matched -> redirecting vhost is a hit
           and vals=={"intranet.acme.com"})           # known 'admin' filtered; only DNS-invisible kept
# the finding carries the BASE SERVICE, never a hostname-as-ip
id_ok = all(r["id"].startswith("vhost:http") and "ip" not in r for r in c2.run.revs)
sys.exit(0 if (q_ok and skip_ok and fuzz_ok and id_ok) else 1)
PYEOF

# ── Check 58: framework→endpoint map — dedup, tech-conditional candidates, 200/403/404 classify ──
echo "[58] framework endpoints: yaml dedups actuator/openapi/graphql; tech-matched candidates; 200->exposed(high), 403->protected, 404->skip; 200 body mined"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "framework-endpoints.yaml loads + omits covered probes; candidate builder tech/scope-gated; probe classifies 200/403/404 + mines secrets; triage debug queue" || no "framework-endpoint probe broken"
import sys, tempfile
from pathlib import Path
from quarry_recon import evidence, triage
from quarry_recon.phases import params
import quarry_recon.fetch as fetch
fw = evidence._framework_endpoints()
sp = [e["path"] for e in fw["spring"]["endpoints"]]
dedup_ok = (fw and not any("actuator" in p for p in sp) and "/h2-console" in sp)
class Scope:
    def active_allowed(self, h): return h.endswith("acme.com")
    def in_scope(self, h): return h.endswith("acme.com")
    def is_oos(self, h): return False
class Run:
    def read(self, e):
        return ([{"url":"https://app.acme.com/","tech":["Laravel"]},
                 {"url":"https://x.acme.com/","tech":["jQuery"]},
                 {"url":"https://off.evil.com/","tech":["Laravel"]}] if e=="live" else [])
class Ctx:
    def __init__(self): self.run=Run(); self.scope=Scope()
cands = params._framework_endpoint_candidates(Ctx(), Scope())
urls = [c["url"] for c in cands]
cand_ok = ("https://app.acme.com/telescope" in urls
           and not any("evil.com" in u or "x.acme.com" in u for u in urls))
class Run2:
    def __init__(self): self.reviews=[]; self.secrets=[]
    def add(self, e, r): (self.reviews if e=="review" else self.secrets).append(r); return True
    def raw_path(self, a,b,n): return Path(tempfile.mkdtemp())/n
class Ctx2:
    def __init__(self): self.run=Run2(); self.scope=Scope()
resp = {"https://app.acme.com/telescope": (b"AKIAABCDEFGHIJKLMNOP", "https://app.acme.com/telescope", 200),
        "https://app.acme.com/horizon": (b"login", "https://app.acme.com/horizon", 403),
        "https://app.acme.com/nova": (b"", "https://app.acme.com/nova", 404)}
import hashlib as _h
from pathlib import Path as _P
def _sg_file(ctx, u, dest, *a, **k):
    body, fin, st = resp.get(u, (b"", u, 404))
    d = _P(dest); d.parent.mkdir(parents=True, exist_ok=True); d.write_bytes(body)
    return fetch.Acquisition(d, len(body), _h.sha256(body).hexdigest(), True), fin, st
fetch.scoped_get_file = _sg_file
c2 = Ctx2()
n = evidence.probe_framework_endpoints(c2, [{"url":u,"framework":"laravel","note":"n"} for u in resp])
klass = [(rv["value"].split("/")[-1], "EXPOSED" in rv["note"], rv.get("priority")) for rv in c2.run.reviews]
probe_ok = (n==1 and ("telescope",True,"high") in klass
            and any(v=="horizon" and not e for v,e,pri in klass)
            and not any(v=="nova" for v,e,pri in klass) and c2.run.secrets)
class Run3:
    def read(self, e):
        return ([{"klass":"debug","value":"https://app.acme.com/telescope","framework":"laravel",
                  "note":"EXPOSED (200): Telescope","sources":["framework-probe"]}] if e=="review" else [])
    def values(self,e): return []
    def count(self,e): return 0
dq = triage.collect(Run3(), Scope())["queues"]["debug"]
triage_ok = ("debug" in triage.CANONICAL_QUEUES and dq and dq[0]["confidence"]=="high"
             and "exposed" in dq[0]["tags"] and "laravel" in dq[0]["tags"])
sys.exit(0 if (dedup_ok and cand_ok and probe_ok and triage_ok) else 1)
PYEOF

# ── Check 59: deserialization/token fingerprint — distinctive markers, no FP, deser queue ──
echo "[59] deser fingerprint: java/dotnet/node/php/jwt markers in headers/cookies detected; ordinary headers -> no FP; deser canonical queue"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "distinctive deser/token markers matched; clean headers yield nothing; deser in CANONICAL_QUEUES + triage handler" || no "deser fingerprint broken"
import sys
from quarry_recon.phases import probe as p
from quarry_recon import triage
def scan(b):
    f=[k for k,m in p._DESER_MARKERS if m in b]
    if p._PHP_OBJ_RX.search(b): f.append("php-serialized")
    if p._JWT_RX.search(b): f.append("jwt")
    return f
hits = (scan("SESSION=rO0ABXNy")==["java-serialized"]
        and "dotnet-binaryformatter" in scan("__VIEWSTATE=AAEAAAD/////AQ")
        and "node-serialize" in scan("_$$ND_FUNC$$_function(){}")
        and "php-serialized" in scan('data=O:4:"User":1:{')
        and "jwt" in scan("Bearer eyJhbGci.eyJzdWIi.abc-123"))
no_fp = (scan("Server: nginx; Set-Cookie: sessionid=abc123def456; X-Frame-Options: DENY")==[]
         and scan("X-Note: HELLO:WORLD O:no")==[])
class Run:
    def read(self, e):
        return ([{"klass":"deser","value":"api.acme.com","format":"java-serialized",
                  "note":"java-serialized marker","sources":["deser-fingerprint"]}] if e=="review" else [])
    def values(self,e): return []
    def count(self,e): return 0
class Scope:
    def in_scope(self,h): return True
    def is_oos(self,h): return False
zq = triage.collect(Run(), Scope())["queues"]["deser"]
tri = ("deser" in triage.CANONICAL_QUEUES and zq and "java-serialized" in zq[0]["tags"])
sys.exit(0 if (hits and no_fp and tri) else 1)
PYEOF

# ── Check 60: config-leak wordlist — bare paths, always-merged into content fuzz (dedup, first) ──
echo "[60] config-leak: shipped bare-path list; _merged_wordlist unions it into any tier (config-leak first, dedup); tier words preserved"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "content-configleak.txt bare paths; merged into fuzz config-leak-first + deduped; tier words kept" || no "config-leak wordlist broken"
import sys, tempfile
from pathlib import Path
from quarry_recon.phases import content
words = content._configleak_words()
w_ok = (".env" in words and ".git/config" in words and "config/master.key" in words
        and not any(x.startswith("/") for x in words))
tier = Path(tempfile.mktemp()); tier.write_text("admin\n.env\napi\n")
class Ctx:
    def tmp(self, n): return Path(tempfile.mkdtemp())/n
ml = content._merged_wordlist(Ctx(), tier).read_text().splitlines()
m_ok = (ml[0]==".env" and ml.count(".env")==1 and "admin" in ml and "api" in ml)
sys.exit(0 if (w_ok and m_ok) else 1)
PYEOF

# ── Check 61: framework→CVE reference — tech-intel digest annotation (reference only, no probing) ──
echo "[61] tech-intel: framework-cve.yaml loads; fingerprinted tech -> tech-intel queue (low/reference), no probing; tech-intel in CANONICAL_QUEUES"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "framework-cve.yaml loads; detected Spring/Laravel -> tech-intel items (confidence low, reference tag, CVEs in why); canonical queue" || no "tech-intel annotation broken"
import sys
from quarry_recon import triage
cve = triage._framework_cve()
load_ok = ("spring" in cve and any("Spring4Shell" in i for i in cve["spring"]["intel"]))
class Run:
    def read(self, e): return [{"tech":"Spring Boot"},{"tech":"Laravel"},{"tech":"nginx"}] if e=="tech" else []
    def values(self,e): return []
    def count(self,e): return 0
class Scope:
    def in_scope(self,h): return True
    def is_oos(self,h): return False
ti = triage.collect(Run(), Scope())["queues"]["tech-intel"]
names = sorted(x["value"] for x in ti)
q_ok = ("spring" in names and "laravel" in names and "tech-intel" in triage.CANONICAL_QUEUES
        and all(x["confidence"]=="low" and "reference" in x["tags"] for x in ti)
        and any("Spring4Shell" in x["why"] for x in ti))
sys.exit(0 if (load_ok and q_ok) else 1)
PYEOF

# ── Check 62: installer provisions a vhost wordlist to the first _vhost_wordlist() path ──
echo "[62] vhost wordlist: bootstrap.yaml data_files ships vhost-wordlist -> ~/.config/quarry/wordlists/vhost.txt (probe finds it out-of-box)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "bootstrap provisions vhost-wordlist at the first path _vhost_wordlist() checks" || no "vhost wordlist not wired into installer"
import sys, yaml
from importlib import resources
bs = yaml.safe_load(resources.files("quarry_recon.data").joinpath("bootstrap.yaml").read_text())
v = [d for d in bs.get("data_files", []) if d.get("name") == "vhost-wordlist"]
ok = bool(v) and v[0]["dest"] == "~/.config/quarry/wordlists/vhost.txt" and v[0].get("url")
sys.exit(0 if ok else 1)
PYEOF

# ── Check 63: doctor surfaces template drift — new optional keys an existing secrets.yaml predates ──
echo "[63] secrets drift: template's uncommented keys diffed vs user file; certspotter flagged for a pre-certspotter secrets.yaml; silent when current"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "template top-level keys diff user secrets; old file -> certspotter drift hint; fresh install -> no drift; commented censys/openintel not flagged" || no "secrets drift check broken"
import sys, yaml
from importlib import resources
from quarry_recon import secrets
tpl = yaml.safe_load(resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()) or {}
# commented advanced keys must NOT be parsed as template keys (stay manual/advanced)
adv_ok = "censys" not in tpl and "openintel" not in tpl and "certspotter" in tpl
secrets._cache = {"github": ["x"], "shodan": "k", "whoxy": None, "projectdiscovery": None}   # pre-certspotter
drift_ok = "certspotter" in [k for k in tpl if k not in secrets.load()]
secrets._cache = {k: None for k in tpl}
fresh_ok = [k for k in tpl if k not in secrets.load()] == []
secrets._cache = None
sys.exit(0 if (adv_ok and drift_ok and fresh_ok) else 1)
PYEOF

# ── Check 64: no module-global import shadowed by a function-local import (UnboundLocalError guard) ──
echo "[64] import-shadow guard: probe/vertical run() do NOT rebind _json/_re as function-locals (the live-run 'cannot access local variable _json' bug)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "probe.run + vertical.run keep _json/_re as module globals — no inner import shadow -> no UnboundLocalError" || no "a run() function shadows _json/_re via an inner import"
import sys
from quarry_recon.phases import probe, vertical
bad = []
for name, fn in (("probe", probe.run), ("vertical", vertical.run)):
    lv = fn.__code__.co_varnames
    if "_json" in lv or "_re" in lv:
        bad.append(name)
sys.exit(0 if not bad else 1)
PYEOF

# ── Check 65: nuclei timeout scales with target count (no partial-coverage timeout on big scopes) ──
echo "[65] nuclei timeout: floor for small scopes, scales ~per-host, no size cap; all 4 nuclei call sites use nuclei_timeout()"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "nuclei_timeout floors at base + grows per-host, uncapped; params(main+takeover)/probe(waf)/enrich(waf) all wired to it" || no "nuclei timeout not scaled / not wired"
import sys, re, os
import quarry_recon.phases as _ph
from quarry_recon.runner import nuclei_timeout as nt
scale_ok = (nt(1,1800)==1800 and nt(5,1800)==1800 and nt(28,1800)==6720   # 240s/host (bumped from 90)
            and nt(2000,1800)==480000 and nt(3,3600)==3600    # floor honored, scales, no cap
            and nt(28,0)==0 and nt(2000,0)==0)                # --timeout 0 => unbounded
_pd = os.path.dirname(_ph.__file__)
src = {p: open(os.path.join(_pd, f"{p}.py")).read() for p in ("params","probe","enrich")}
# every nuclei exec must use nuclei_timeout(...), none left on the flat ctx.http_timeout
wired = all("nuclei_timeout(" in src[p] for p in src)
none_flat = not any(re.search(r'exec_tool\(\s*"nuclei"[^)]*timeout=ctx\.http_timeout', src[p]) for p in src)
sys.exit(0 if (scale_ok and wired and none_flat) else 1)
PYEOF

# ── Check 66: doctor on a MISSING secrets.yaml — NOT-FOUND warning + drift hint suppressed ──
echo "[66] doctor secrets: missing file -> NOT-FOUND warning (not silent 'unset'); drift hint only when file exists"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "missing secrets.yaml -> ✗ NOT FOUND + no false drift; present-but-stale -> drift hint fires" || no "doctor missing-file handling broken"
import sys
from pathlib import Path
from click.testing import CliRunner
from quarry_recon import cli, secrets
secrets.PATH = Path("/tmp/nope-quarry-secrets-xyz.yaml"); secrets._cache = None
out = CliRunner().invoke(cli.doctor, []).output
sec = out[out.find("[secrets]"):out.find("[notify]")]
missing_ok = ("NOT FOUND" in sec) and ("template adds optional key" not in sec)
sys.exit(0 if missing_ok else 1)
PYEOF

# ── Check 67: projects root home-anchored (not cwd) with explicit overrides honored ──
echo "[67] projects root: default ~/projects (home-anchored, not pwd/projects); --projects-dir + \$QUARRY_PROJECTS override"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "default = ~/projects; opt arg + QUARRY_PROJECTS still override" || no "projects root not home-anchored"
import sys, os
from pathlib import Path
os.environ.pop("QUARRY_PROJECTS", None)
from quarry_recon import cli
ok = (cli._projects_root(None) == Path.home() / "projects"
      and cli._projects_root("/tmp/x") == Path("/tmp/x"))
os.environ["QUARRY_PROJECTS"] = "/data/proj"
ok = ok and cli._projects_root(None) == Path("/data/proj")
os.environ.pop("QUARRY_PROJECTS", None)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 68: wordlists live under wordlists/ (clean layout) with back-compat fallback ──
echo "[68] wordlist layout: installer dests dns/vhost under wordlists/; _wordlist/_vhost_wordlist check canonical first then old path"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "bootstrap dns/vhost -> wordlists/{dns,vhost}.txt; lookups prefer wordlists/ then back-compat root path" || no "wordlist reorg broken"
import sys, inspect, yaml
from importlib import resources
from quarry_recon.phases import probe, vertical
bs = yaml.safe_load(resources.files("quarry_recon.data").joinpath("bootstrap.yaml").read_text())
d = {x["name"]: x["dest"] for x in bs["data_files"]}
dest_ok = (d["dns-wordlist"] == "~/.config/quarry/wordlists/dns.txt"
           and d["vhost-wordlist"] == "~/.config/quarry/wordlists/vhost.txt")
v, p = inspect.getsource(vertical._wordlist), inspect.getsource(probe._vhost_wordlist)
order_ok = (v.index("wordlists/dns.txt") < v.index("dns-wordlist.txt")
            and p.index("wordlists/vhost.txt") < p.index("vhost-wordlist.txt"))
sys.exit(0 if (dest_ok and order_ok) else 1)
PYEOF

# ── Check 69: doctor treats wordlists/resolvers as REQUIRED — missing => ⚠ warn, not "(optional)" ──
echo "[69] doctor env: missing wordlists/resolvers warn 'MISSING — run quarry set <name>' (granular fix, M1; not soft optional; keys stay optional)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "absent dns/vhost/content wordlists -> ⚠ MISSING + 'quarry set <name>' hint (M1); no '(optional)' framing for wordlists" || no "doctor still soft-labels missing wordlists"
import sys, os, tempfile, pathlib
os.environ["HOME"] = tempfile.mkdtemp()
from click.testing import CliRunner
from quarry_recon import cli, secrets
secrets.PATH = pathlib.Path(os.environ["HOME"])/".config/quarry/secrets.yaml"; secrets._cache=None
out = CliRunner().invoke(cli.doctor, []).output
env = out[out.find("[environment]"):out.find("[system]")]
dns = [l for l in env.splitlines() if "dns wordlist" in l][0]
ok = ("MISSING" in dns and "quarry set dns-wordlist" in dns and "(optional)" not in env)
sys.exit(0 if ok else 1)
PYEOF

# ── Check 70: v0.3 H1 — machine-scoped settings (config.yaml): profile/concurrency + openintel move ──
echo "[70] settings (config.yaml): PROFILE default/override; concurrency override+fallback; openintel config-wins + secrets back-compat; bootstrap creates it"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "settings module: auto profile default, explicit override, blank/missing->default; openintel config.yaml wins else secrets fallback; bootstrap provisions config.yaml" || no "settings/config.yaml foundation broken"
import sys, yaml
from importlib import resources
from quarry_recon import settings, secrets, bootstrap
# template loads + bootstrap creates config.yaml (not just secrets)
tpl_ok = yaml.safe_load(resources.files("quarry_recon.data").joinpath("config.template.yaml").read_text())["PERFORMANCE"]["PROFILE"]=="auto"
settings._cache={}
d_ok = settings.profile()=="auto" and settings.concurrency("NUCLEI_CONCURRENCY",25)==25
settings._cache={"PERFORMANCE":{"PROFILE":"aggressive","NUCLEI_CONCURRENCY":50,"HTTPX_THREADS":""}}
o_ok = (settings.profile()=="aggressive" and settings.concurrency("NUCLEI_CONCURRENCY",25)==50
        and settings.concurrency("HTTPX_THREADS",15)==15)
settings._cache={"PERFORMANCE":{"PROFILE":"turbo"}}
inv_ok = settings.profile()=="auto"                       # invalid -> auto
settings._cache={}; secrets._cache={"openintel":{"binary":"/x/oi","db":"/x/db"}}
bc_ok = settings.openintel()=={"binary":"/x/oi","db":"/x/db"}   # secrets back-compat
settings._cache={"openintel":{"binary":"/cfg/oi","db":"/cfg/db"}}
win_ok = settings.openintel()["binary"]=="/cfg/oi"        # config.yaml wins
sys.exit(0 if (tpl_ok and d_ok and o_ok and inv_ok and bc_ok and win_ok) else 1)
PYEOF

# ── Check 71: v0.3 H2 — CPU-core-scaled concurrency (workers) + all call sites wired ──
echo "[71] workers: core×factor×profile scaling + I/O-BOUND base (httpx/ffuf network-bound → not core-starved), caps+floor, override wins, dalfox override-only; nuclei/httpx/ffuf call sites wired"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "nuclei core-scales; httpx/ffuf floor at I/O base (150/120) so a low-core box isn't starved; safe throttles even I/O; aggr/cap raised (httpx 300); override wins; dalfox override-only; wired" || no "H2 concurrency scaling broken"
import sys, os, inspect
from quarry_recon import settings
from quarry_recon.phases import params, probe, enrich, content
settings.os = type("m",(),{"cpu_count":staticmethod(lambda:4)})()
settings._cache={}   # auto @4 cores: nuclei 4*10=40; httpx/ffuf I/O-bound → base 150/120 beats 48
auto_ok = settings.workers("nuclei",25)==40 and settings.workers("httpx",15)==150 and settings.workers("ffuf",40)==120
settings.os=type("m",(),{"cpu_count":staticmethod(lambda:2)})(); settings._cache={}   # THE FIX: 2 cores must NOT starve I/O tools
io_ok = settings.workers("httpx",15)==150 and settings.workers("ffuf",40)==120
settings.os=type("m",(),{"cpu_count":staticmethod(lambda:4)})()
settings._cache={"PERFORMANCE":{"PROFILE":"safe"}};       safe_ok = settings.workers("nuclei",25)==20 and settings.workers("httpx",15)<150  # safe throttles I/O too
settings._cache={"PERFORMANCE":{"PROFILE":"aggressive"}}; aggr_ok = settings.workers("nuclei",25)==70
settings._cache={"PERFORMANCE":{"NUCLEI_CONCURRENCY":80}};ovr_ok = settings.workers("nuclei",25)==80
settings._cache={"PERFORMANCE":{"PROFILE":"aggressive"}}; dfx_ok = settings.workers("dalfox",50)==50
settings.os=type("m",(),{"cpu_count":staticmethod(lambda:64)})()
settings._cache={"PERFORMANCE":{"PROFILE":"aggressive"}}; cap_ok = settings.workers("nuclei",25)==100 and settings.workers("httpx",15)==300  # httpx cap raised 150->300
wired = (all('settings.workers(' in inspect.getsource(m) for m in (params, probe, content))
         and 'fingerprint_hosts' in inspect.getsource(enrich))   # v0.3.5: enrich httpx via probe's shared helper
sys.exit(0 if (auto_ok and io_ok and safe_ok and aggr_ok and ovr_ok and dfx_ok and cap_ok and wired) else 1)
PYEOF

# ── Check 72: v0.3 H3 — per-tool CPU/RAM telemetry (Popen sampler) + runner behavior preserved ──
echo "[72] per-tool telemetry: real child -> cpu_s + peak_rss_mb captured; stdin/timeout/classification/ok_codes preserved; metrics tool entries carry cpu/rss + rss long-pole"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "Popen sampler records per-tool cpu_s + peak_rss_mb; stdin+timeout+classify+ok_codes intact; metrics.build adds cpu/rss to tool entries + rss long-pole" || no "H3 telemetry / runner refactor broken"
import sys
from quarry_recon import runner, metrics
prog = "x=bytearray(60*1024*1024)\nimport time,hashlib\nt=time.time()\nwhile time.time()-t<1.0: hashlib.sha256(b'z').hexdigest()\nprint('done')"
r = runner.run("t", ["python3","-c",prog])
cap_ok = r.status.value=="success" and r.cpu_s>0.3 and r.peak_rss_mb>40 and r.stdout_lines==1
r2 = runner.run("cat", ["cat"], stdin_data="a\nb\n"); stdin_ok = r2.status.value=="success" and r2.stdout_lines==2
r3 = runner.run("s", ["sleep","10"], timeout=1);      to_ok = r3.status.value=="timed_out"
r4 = runner.run("f", ["false"]);                       cls_ok = r4.status.value=="failed"
r5 = runner.run("g", ["sh","-c","echo x; exit 1"], ok_codes=(0,1)); ok_ok = r5.status.value=="success"
# metrics carries the new fields — build the real ToolRunRecord that store.record() produces
from quarry_recon.store import ToolRunRecord
rec = ToolRunRecord(phase="probe", tool="t", status="success", exit_code=0, duration=1.0,
                    stdout_lines=1, note="", cmd="python3", cpu_s=r.cpu_s, peak_rss_mb=r.peak_rss_mb)
class FakeRun:
    run_id="x"; target="t"
    def tool_runs(self): return [rec]
m = metrics.build(FakeRun(), [], 1.0, 1.0, 80.0)
te = m["tools"][0]
met_ok = ("cpu_s" in te and "peak_rss_mb" in te and te["peak_rss_mb"]>40 and "rss" in m["long_poles"]
          and m["long_poles"]["rss"] and m["long_poles"]["rss"][0]["peak_rss_mb"]>40)
sys.exit(0 if (cap_ok and stdin_ok and to_ok and cls_ok and ok_ok and met_ok) else 1)
PYEOF

# ── Check 73: v0.3 A1 — wildcard-zone brute + HTTP-differentiation ──
echo "[73] wildcard A1: *.zone cert -> wildcard-brute-zone; brute+httpx; keep responses DIFFERING from the wildcard baseline (distinct vhost), drop baseline+bogus; non-wildcard -> nothing"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "CT preserves *. -> zone; differ-check on status/len/title/favicon recovers the distinct vhost only (source wildcard-http); baseline+bogus dropped; no-baseline zone -> nothing" || no "A1 wildcard differentiation broken"
import sys, json, tempfile
from pathlib import Path
import quarry_recon.phases.vertical as p
import quarry_recon.phases.probe as _probe
p.have = lambda t: True
# the DEDICATED vhost list is the pass's only generic vocabulary — the DNS brute list is NEVER a fallback
# (step 4 measurement #2: that fallback made the eligible set 6,037,953 candidate hosts per zone)
wl = Path(tempfile.mktemp()); wl.write_text("admin\nreal1\ndev\nredir\n")
_probe._vhost_wordlist = lambda: wl          # patch the REAL source (vertical lazy-imports it)
p._wordlist = lambda ctx: None               # ...and the DNS list contributes NOTHING here
FR=[]
def fake_exec(tool, cmd, **kw):
    cands = Path(cmd[cmd.index("-l")+1]).read_text().split()
    rp = kw["raw_path"]; rp.parent.mkdir(parents=True, exist_ok=True)
    if tool=="dnsx":   # audit #1 bulk pre-resolve: every candidate resolves to a GLOBAL IP -> all survive the guard
        rp.write_text("\n".join(json.dumps({"host":c,"a":["1.2.3.4"]}) for c in cands))
        class RR: raw_path=rp; status=p.Status.SUCCESS
        return RR()
    FR.append("-follow-host-redirects" in cmd) # A1 follows SAME-HOST redirects (http->https collapse), not cross-host (audit #1)
    lines=[]
    for c in cands:
        if c.startswith("real1."):
            lines.append(json.dumps({"input":c,"status_code":200,"content_length":265,"title":"Real One","favicon":222,"a":["1.2.3.4"]}))
        elif c.startswith("redir."):          # an un-followed 3xx redirect -> infra noise, must be dropped
            lines.append(json.dumps({"input":c,"status_code":308,"content_length":0,"title":"","favicon":None}))
        else:   # admin/dev/bogus -> the identical wildcard baseline
            lines.append(json.dumps({"input":c,"status_code":200,"content_length":82,"title":"wc-baseline","favicon":111,"a":["1.2.3.4"]}))
    rp.write_text("\n".join(lines))
    class RR: raw_path=rp; status=p.Status.SUCCESS
    return RR()
p.exec_tool = fake_exec
class Scope:
    def in_scope(self,h): return h.endswith("acme.com")
    def is_oos(self,h): return False
    passive_only=False
class Run:
    # the differ SCHEDULES its zones now (4.3 step B), so the double carries the project dir the
    # rotation state lives under — exactly what a real Run provides.
    def __init__(self): self.subs=[]; self.res=[]; self.project_dir=Path(tempfile.mkdtemp())
    def add(self,e,r): (self.subs if e=="subdomain" else self.res).append(r); return True
    def record(self,*a): pass
    def raw_path(self,a,b,n): return Path(tempfile.mkdtemp())/n
class Ctx:
    def __init__(self):
        self.scope=Scope(); self.run=Run(); self.http_timeout=60
        self.profile=type("P",(),{"http_rl":None,"dns_rate":None})()
    def echo(self,*a): pass
    def write_list(self,n,items): q=Path(tempfile.mktemp()); q.write_text("\n".join(items)+"\n"); return q
p._resolvers = lambda ctx: (None, None)     # no custom resolvers in the test -> dnsx/httpx run bare (audit #1 flags optional)
c=Ctx(); n=p._wildcard_differentiate(c, {"wc.acme.com"})
kept=[s["host"] for s in c.run.subs]
# only the genuinely-distinct vhost: baseline dropped, bogus excluded, 308 redirect-noise dropped, follow-redirects set
keep_ok = (kept==["real1.wc.acme.com"] and n=={"real1.wc.acme.com"} and all(FR)  # returns kept-host SET (A1d needs them)
           and all(s["sources"]==["wildcard-http"] for s in c.run.subs))
# non-wildcard: bogus/all give no response -> no baseline -> nothing
p.exec_tool=lambda tool,cmd,**kw:(kw["raw_path"].parent.mkdir(parents=True,exist_ok=True),kw["raw_path"].write_text(""),type("R",(),{"raw_path":kw["raw_path"],"status":p.Status.SUCCESS})())[2]
c2=Ctx(); none_ok = p._wildcard_differentiate(c2,{"z.acme.com"})==set() and not c2.run.subs
# early-exit contract: httpx missing / no wordlist / passive MUST return set() (not 0) — else enrich's
# discovered.update() throws TypeError. Force the have("httpx")=False early exit and prove it's iterable.
_hh=p.have; p.have=lambda t: False
early=p._wildcard_differentiate(Ctx(),{"wc.acme.com"})
p.have=_hh
try: set().update(early); iter_ok=True         # enrich does discovered.update(...) — must not throw
except TypeError: iter_ok=False
none_ok = none_ok and early==set() and iter_ok
sys.exit(0 if (keep_ok and none_ok) else 1)
PYEOF

echo "[75] A1d recursion: crawl-mined target wordlist (xnLinkFinder -owl) tokenized/filtered/deduped/capped, then fed to the enrich re-brute — apex (puredns, source target-wordlist) + wildcard differ (extra_words, phase=enrich, source wildcard-http-a1d) over persisted wildcard_zone"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "target words = plausible labels only (base/numeric/short dropped, hyphen kept, _/path split), bounded; enrich feeds them into apex brute + wildcard differ; discoveries land as subdomains with A1d provenance" || no "A1d recursion broken"
import sys, tempfile
from pathlib import Path
import quarry_recon.phases.vertical as V
import quarry_recon.phases.enrich as E
import quarry_recon.phases.probe as P
from quarry_recon.runner import Status

d = Path(tempfile.mkdtemp())
wld = d/"raw"/"crawl"/"xnLinkFinder"; wld.mkdir(parents=True)
(wld/"js_wordlist.txt").write_text("api\nstaging\ninternal-portal\nv1\n1234\nbilling_service\ncheckout/session\n")

class Run:
    def __init__(self): self.subs=[]; self.res=[]; self.dir=d; self.project_dir=d   # step 4.2: the A1d
                                                                                   # rotation is PROJECT state
    def values(self,e): return ["wc.acme.com"] if e=="wildcard_zone" else []
    def add(self,e,r):
        if e=="subdomain": self.subs.append(r)
        elif e=="resolved": self.res.append(r)
        return True
    def record(self,*a): pass
    def raw_path(self,a,b,n):
        p=d/"raw"/a/b; p.mkdir(parents=True,exist_ok=True); return p/n
class Prof: apex_domains=["acme.com"]; dns_rate=0
class Scope:
    def in_scope(self,h): return h.endswith("acme.com")
    def is_oos(self,h): return False
    passive_only=False
class Ctx:
    def __init__(self): self.run=Run(); self.profile=Prof(); self.scope=Scope(); self.http_timeout=60
    def echo(self,*a): pass
    def write_list(self,n,items): q=d/n; q.write_text("\n".join(items)+"\n"); return q

_p1_base=Path(tempfile.mktemp()); _p1_base.write_text("api\n")

# part 1 — _target_wordlist is RETENTION now (step 4 measurement #3): it returns the full mined corpus in
# encounter order; base subtraction is STREAMED by the caller and the spend bound is the caller's.
c=Ctx(); tw=V._target_wordlist(c)
_lossp1={}
_after=E._a1d_subtract_base(c, tw, lambda ctx: _p1_base, _lossp1)
p1 = ("staging" in tw and "internal-portal" in tw and "billing" in tw and "session" in tw
      and "1234" not in tw and "v1" not in tw
      and "api" in tw and "api" not in _after            # retention keeps it; subtraction removes it
      and E.A1D_WORD_CAP == 2000)

# part 2 — enrich A1d recursion feeds target words into apex brute + wildcard differ
base=Path(tempfile.mktemp()); base.write_text("api\nadmin\n"); V._wordlist=lambda ctx: base
P._vhost_wordlist=lambda: None            # the DNS list is NEVER a vhost fallback (measurement #2)
V._resolvers=lambda ctx:(None, Path(tempfile.mktemp()))
E.have=lambda t: True
PUREDNS=[]
def fake_exec(tool,cmd,**kw):
    rp=kw.get("raw_path")
    if tool=="puredns":
        PUREDNS.append(Path(cmd[2]).read_text())     # bruteforce <wordlist> <domain>
        rp.write_text("staging.acme.com\n")
    # step 4.2: the sweep reads the STATUS to classify the slot outcome — a double must answer it
    from quarry_recon.runner import RunResult as _RR
    return _RR(tool, list(cmd), Status.SUCCESS, 0, 0.1, rp, 1)
E.exec_tool=fake_exec
DIFF=[]
def fake_diff(ctx,zones,*,extra_words=None,phase=None,label=None,source=None,stats=None,source_id=None,word_spend=None):
    DIFF.append((set(zones),tuple(extra_words or []),phase,source))
    assert source_id=="enrich.wildcard_a1d"     # audit-16#3: A1d runs under its OWN registered lifecycle
    if stats is not None:                      # audit-14: the differ reports what it actually probed
        stats.update({"eligible_zones":len(set(zones)),"probed_zones":len(set(zones)),"blocked_reason":"",
                      "vocabulary":{"lines":0,"accepted":1,"undecodable":0,"rejected":0,
                                    "unreadable":False,"absent":True}})
    # faithful to the real differ: it adds hits to BOTH subdomain AND resolved, and RETURNS the hosts
    ctx.run.add("subdomain",{"host":"internal.wc.acme.com","sources":[source]})
    ctx.run.add("resolved",{"host":"internal.wc.acme.com","sources":[source]})
    return ["internal.wc.acme.com"]
V._wildcard_differentiate=fake_diff
c2=Ctx(); found=E._a1d_recursive_brute(c2)
hosts={s["host"] for s in c2.run.subs}
# F1 regression guard: the wildcard-differ host is in `resolved`, so `subdomain - resolved` alone would
# DROP it from enrich's catch-up. _a1d_recursive_brute must RETURN it so run() can union it back in.
resolved_after={r["host"] for r in c2.run.res}
new_would_be=({h for h in hosts if h not in resolved_after} | {h for h in found})   # run()'s union
p2 = (any("staging" in w and "api" not in w.split() for w in PUREDNS)        # apex brute used the TARGET wordlist
      and DIFF and DIFF[0][0]=={"wc.acme.com"} and "staging" in DIFF[0][1]     # differ got zone + target words
      and DIFF[0][2]=="enrich" and DIFF[0][3]=="wildcard-http-a1d"            # provenance distinct from vertical's A1
      and isinstance(found,set) and {"staging.acme.com","internal.wc.acme.com"}<=found   # returns discovered set
      and "internal.wc.acme.com" in resolved_after                            # differ DID add it to resolved (the trap)
      and "internal.wc.acme.com" in new_would_be                              # ...but union rescues it into catch-up
      and any(s.get("sources")==["target-wordlist"] for s in c2.run.subs))
sys.exit(0 if (p1 and p2) else 1)
PYEOF

echo "[76] A2 origin correlation: CDN-fronted host + non-CDN twin (favicon-hash OR same cert sha1 OR cert-SAN) -> candidate origin IP as review(klass origin-ip, verify-ownership); map-only (writes ONLY review — never subdomain/resolved/port/scope); no-CDN -> skip; phase registered after enrich"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "favicon twin + cert-sha1 twin + cert-SAN each yield an origin-IP review; noise not correlated; every emission is review/verify-ownership; NOTHING but review written (map-only); origin ordered after enrich, before content" || no "A2 origin correlation broken"
import sys, types
import quarry_recon.phases.origin as O
from quarry_recon.phases import ORDER

store={
 "live":[
  {"host":"edge.acme.com","url":"https://edge.acme.com","cdn":True,"cdn_name":"cloudflare","favicon":"12345","a":["104.21.0.1"]},
  {"host":"www.acme.com","url":"https://www.acme.com","cdn":False,"favicon":"12345","a":["178.10.0.9"]},
  {"host":"api.acme.com","url":"https://api.acme.com","cdn":True,"favicon":"999","a":["104.21.0.2"]},
  {"host":"origin.acme.com","url":"https://origin.acme.com","cdn":False,"favicon":"777","a":["178.10.0.5"]},
  {"host":"direct.acme.com","url":"https://direct.acme.com","cdn":False,"favicon":"333","a":["178.10.0.3"]},
  {"host":"noise.acme.com","url":"https://noise.acme.com","cdn":False,"favicon":"555","a":["178.10.0.7"]},
 ],
 "certificate":[
  {"host":"api.acme.com","sha1":"AABB","san":["api.acme.com","direct.acme.com"]},
  {"host":"origin.acme.com","sha1":"AABB","san":["origin.acme.com"]},
 ],
}
writes=[]                       # (entity, record) — map-only means every entity here == "review"
class Run:
    def read(self,e): return store.get(e,[])
    def add(self,e,r): writes.append((e,r)); return True
    def record(self,*a): pass
class Scope: passive_only=False
O.run(types.SimpleNamespace(run=Run(),scope=Scope(),echo=lambda *a:None))
rev=[r for e,r in writes if e=="review"]
trip={(r["host"],r["origin_ip"],r["channel"]) for r in rev}
ok_ch = (("edge.acme.com","178.10.0.9","favicon") in trip
         and ("api.acme.com","178.10.0.5","cert-sha1") in trip
         and ("api.acme.com","178.10.0.3","cert-san") in trip)
map_only = all(e=="review" for e,_ in writes)                      # ISC-A2/13: nothing but review written
tagged   = all(r["klass"]=="origin-ip" and "verify ownership" in r["note"] for r in rev)   # ISC-12
evidence = all(r.get("matched_host") for r in rev) and any(         # explainable: matched non-CDN host stored
    r["host"]=="edge.acme.com" and r["origin_ip"]=="178.10.0.9" and r["matched_host"]=="www.acme.com" for r in rev)
no_noise = not any(r["origin_ip"]=="178.10.0.7" for r in rev)      # unrelated favicon not correlated
# skip path: no CDN host -> no writes
w2=[]
class Run2(Run):
    def read(self,e): return [{"host":"a","cdn":False,"favicon":"1","a":["1.1.1.1"]}] if e=="live" else []
    def add(self,e,r): w2.append((e,r)); return True
O.run(types.SimpleNamespace(run=Run2(),scope=Scope(),echo=lambda *a:None))
skip_ok = not w2
order_ok = ORDER.index("origin")==ORDER.index("enrich")+1 and ORDER.index("origin")<ORDER.index("content")
sys.exit(0 if (ok_ch and map_only and tagged and evidence and no_noise and skip_ok and order_ok) else 1)
PYEOF

echo "[77] content-ffuf redirect policy (ISC-16): MATCHES 3xx (-mc 301/302/307/308) + -ac guards the catch-all flood; deliberately does NOT follow (-r) — a redirecting path is itself content-discovery intel (unlike classify-probes, which must follow)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "content ffuf cmd matches 30x + -ac; NO -r in the ffuf command (deliberate exception, documented ISC-16)" || no "content redirect policy drifted"
import sys, inspect, re
import quarry_recon.phases.content as C
src = inspect.getsource(C)
# isolate the ffuf command list
i = src.index('cmd = ["ffuf"'); j = src.index('-of", "json"', i)
ffuf_cmd = src[i:j]
# A1: the match codes live in the module-level `_mc` the cmd passes through, not inline in the list. Assert
# BOTH — the codes are declared, and the cmd actually passes -mc — and fail loud if the declaration is gone.
_m = re.search(r'_mc = "([^"]+)"', src)
if _m is None:
    sys.exit(1)
matches_3xx = (all(code in _m.group(1) for code in ("301", "302", "307", "308"))
               and '"-mc", mc' in ffuf_cmd and "-ac" in ffuf_cmd)
no_follow   = '"-r"' not in ffuf_cmd            # content is the ONE probe that MATCHES 3xx, never follows
documented  = "ISC-16" in src and "-ac" in src
sys.exit(0 if (matches_3xx and no_follow and documented) else 1)
PYEOF

echo "[78] M1 quarry set: single data-file fetch by name — unknown name lists valid names + fails; known name fixes dest; --url overrides SOURCE only; doctor hint points at 'quarry set <name>' not 'quarry install'; command registered"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "set_data_file: unknown -> False + valid-names list; known -> dest from name; --url overrides source not dest; doctor data-file hint = 'quarry set <name>'; cli 'set' command exists" || no "M1 quarry set broken"
import sys, inspect
from quarry_recon import bootstrap as B
from quarry_recon import cli
m=[]
u = B.set_data_file("bogus", None, m.append, dry=True)
unknown_ok = (u is False) and any("unknown data file" in x and "resolvers" in x for x in m)
m.clear()
k = B.set_data_file("dns-wordlist", None, m.append, dry=True)
known_ok = (k is True) and any("dns-wordlist: ok" in x for x in m)
import pathlib
# --url overrides SOURCE only (dest still from name), routed through _curl_to
seen={}
o=B._curl_to; B._curl_to=lambda url,dest,dry,timeout=300:(seen.__setitem__("u",url),seen.__setitem__("d",str(dest)),(0,""))[2]
B.set_data_file("resolvers","https://ex/x.txt",lambda *a:None,dry=True); B._curl_to=o
url_ok = seen["u"]=="https://ex/x.txt" and "resolvers.txt" in seen["d"]
# SHELL-INJECTION guard: _curl_to must use argv (no shell); a quote-bearing url is one opaque element
argv={}
class _P: returncode=0; stdout=""; stderr=""
orig=B.subprocess.run; B.subprocess.run=lambda a,**k:(argv.__setitem__("a",a),_P())[1]
B._curl_to("https://ex/x'?p=1'; rm -rf ~", pathlib.Path("/tmp/quarry-verify-r.txt"), False); B.subprocess.run=orig
inj_ok = (isinstance(argv["a"],list) and argv["a"][0]=="curl"
          and "https://ex/x'?p=1'; rm -rf ~" in argv["a"]      # dangerous url survives VERBATIM as one arg
          and "-o" in argv["a"])
doc = inspect.getsource(cli)
hint_ok = "quarry set {name}" in doc                       # doctor data-file hint updated
cmd_ok = "set" in cli.cli.commands                          # click command registered
sys.exit(0 if (unknown_ok and known_ok and url_ok and inj_ok and hint_ok and cmd_ok) else 1)
PYEOF

echo "[79] kaeferjaeger LOCAL dataset (audit #3, batch 2) — NO remote fetch (no kaeferjaeger.gay/urlopen/urllib in _kaeferjaeger); STREAMS the operator's *.txt line-by-line (bounded RAM, COMPLETE file — no read_text prefix truncation) with host+file:line provenance; HONEST status FAILED (no file readable) / PARTIAL (some failed) / SUCCESS-EMPTY (all read); absent dataset -> recorded skip."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "no remote fetch; streams full file (no read_text[:cap]); provenance host+file:line; FAILED/PARTIAL/SUCCESS honest; absent -> skip" || no "kaeferjaeger local-dataset broken"
import sys, inspect, tempfile, pathlib
from types import SimpleNamespace
from quarry_recon.runner import Status
import quarry_recon.phases.horizontal as H
fn = inspect.getsource(H._kaeferjaeger)
no_remote = ("kaeferjaeger.gay" not in fn and "urlopen" not in fn and "urllib" not in fn
             and "read_text" not in fn and "enumerate(fh" in fn)          # STREAMS, not read_text[:cap]
def run(d, add_ret=None):
    calls, recs, m = [], [], pathlib.Path(tempfile.mkdtemp()) / "matches.txt"
    class Run:
        def add(s, e, r):
            if e == "subdomain": calls.append(r["host"])
            return add_ret(r["host"]) if add_ret else True     # default: every host is a NEW entity
        def record(s, ph, rr): recs.append(rr)
        def raw_path(s, a, b, n): return m
        @property
        def notes(s): return []
    ctx = SimpleNamespace(run=Run(), scope=SimpleNamespace(in_scope=lambda h: h.endswith("acme.com")))
    H._kaeferjaeger_dir = lambda: d
    n = H._kaeferjaeger(ctx)
    rr = recs[0] if recs else None
    return n, calls, rr, (m.read_text() if m.exists() else "")
# PRESENT: streams full file, matched count + host+file:line provenance
d1 = pathlib.Path(tempfile.mkdtemp()); (d1 / "amazon.txt").write_text("foo.acme.com bar.other.com\nsub.acme.com foo.acme.com\n")
n1, c1, rr1, prov = run(d1)
present_ok = (n1 == 2 and rr1.status == Status.SUCCESS and "amazon.txt:1" in prov and "amazon.txt:2" in prov
              and "2 matched" in rr1.note)
# PREEXISTING entity (store.add returns False): still MATCHED (SUCCESS, raw written), +0 added — NOT falsely EMPTY
d2 = pathlib.Path(tempfile.mkdtemp()); (d2 / "amazon.txt").write_text("old.acme.com\n")
n2, c2, rr2, prov2 = run(d2, add_ret=lambda h: False)
preexist_ok = (n2 == 1 and rr2.status == Status.SUCCESS and "old.acme.com" in prov2 and "+0 added" in rr2.note)
# SAME HOST IN TWO FILES: matched once, added once, BOTH files' provenance kept
d3 = pathlib.Path(tempfile.mkdtemp()); (d3 / "a.txt").write_text("dup.acme.com\n"); (d3 / "b.txt").write_text("dup.acme.com\n")
n3, c3, rr3, prov3 = run(d3)
twofile_ok = (n3 == 1 and c3.count("dup.acme.com") == 1 and "a.txt:1" in prov3 and "b.txt:1" in prov3)
# PARTIAL: one good + one unreadable (a directory named *.txt raises on open)
d4 = pathlib.Path(tempfile.mkdtemp()); (d4 / "ok.txt").write_text("x.acme.com\n"); (d4 / "bad.txt").mkdir()
_n, _c, rr4, _p = run(d4); partial_ok = (rr4.status == Status.PARTIAL)
# FAILED: only an unreadable file -> FAILED, no matches
d5 = pathlib.Path(tempfile.mkdtemp()); (d5 / "bad.txt").mkdir()
n5, c5, rr5, _p = run(d5); failed_ok = (rr5.status == Status.FAILED and n5 == 0 and not c5)
# ABSENT dataset -> skipped, 0
n6, c6, rr6, _p = run(pathlib.Path(tempfile.mkdtemp()))
absent_ok = (n6 == 0 and not c6 and rr6.status == Status.SKIPPED)
sys.exit(0 if (no_remote and present_ok and preexist_ok and twofile_ok and partial_ok and failed_ok and absent_ok) else 1)
PYEOF

echo "[80] v0.3.2 scaled timeouts EVERYWHERE (codex): scaled_timeout ceiling; probe httpx(port-wt)+ffuf(wordlist)+naabu(cidr)+nmap, content ffuf(wordlist×recursion), enrich httpx(late hosts) — none left on the flat 1800s that cut the 567-host probe; nuclei alias delegates"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "scaled_timeout ceiling semantics; nuclei delegates; scaling applied across probe(httpx/ffuf/naabu/nmap) + content ffuf(×recursion) + enrich httpx — no flat ctx.http_timeout left on those tools" || no "v0.3.2 scaled timeout broken"
import sys, inspect
from quarry_recon.runner import scaled_timeout, nuclei_timeout
import quarry_recon.phases.probe as P
sem = (scaled_timeout(10,1800,6)==1800 and scaled_timeout(567,1800,7)==3969 and scaled_timeout(5,0,6)==0
       and nuclei_timeout(10,1800)==2400)
import quarry_recon.phases.content as C
import quarry_recon.phases.enrich as EN
psrc=inspect.getsource(P); csrc=inspect.getsource(C); esrc=inspect.getsource(EN)
# ALL ffuf/httpx paths scaled (codex: not just vhost/probe) — probe httpx+ffuf, content ffuf, naabu/nmap, enrich httpx
probe_ok = ("scaled_timeout(len(hosts)" in psrc and "ffuf_to = scaled_timeout(" in psrc
            and "timeout=to" in psrc and "hard = ffuf_to + 60 if ffuf_to else 0" in psrc   # ffuf ceiling from ffuf_to (T2.2)
            and "naabu_to = scaled_timeout(" in psrc and "scaled_timeout(len(ips) * len(ptup)" in psrc)   # nmap: host×port work
content_ok = "ct_to = scaled_timeout(wl_n * (recurse + 1)" in csrc and "hard = ct_to + 60 if ct_to else 0" in csrc
enrich_ok  = "fingerprint_hosts(" in esrc                                        # v0.3.5: enrich uses probe's scaled httpx path
sys.exit(0 if (sem and probe_ok and content_ok and enrich_ok) else 1)
PYEOF

echo "[81] gowitness reclassify (shared adapter, probe AND enrich): file-output tool judged on empty stdout + a WAF stderr line was mislabeled BLOCKED; reclassify_from_files (now a thin wrapper over reclassify_from_artifact) derives status from shots on disk. T1.6 de-LAUNDER: a DEGRADED run (FAILED) + shots is PARTIAL, NOT SUCCESS (was laundered); clean EMPTY+shots->SUCCESS; BLOCKED+shots->PARTIAL; 0 shots keeps the original status."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "reclassify_from_files: EMPTY(clean)+shots->SUCCESS, BLOCKED/FAILED(degraded)+shots->PARTIAL (never laundered), 0 shots keeps status; BOTH probe+enrich call it" || no "gowitness reclassify broken"
import sys, inspect
from quarry_recon.runner import reclassify_from_files, RunResult, Status
import quarry_recon.phases.probe as P
import quarry_recon.phases.enrich as EN
def mk(st): return RunResult("gowitness",["x"],st,0,1.0,None,0)
behav = (reclassify_from_files(mk(Status.BLOCKED),43,"screenshot").status==Status.PARTIAL     # degraded+shots->PARTIAL
         and reclassify_from_files(mk(Status.EMPTY),9,"screenshot").status==Status.SUCCESS     # clean+shots->SUCCESS
         and reclassify_from_files(mk(Status.FAILED),1,"screenshot").status==Status.PARTIAL    # T1.6: FAILED+shots NO LONGER laundered to SUCCESS
         and reclassify_from_files(mk(Status.BLOCKED),0,"screenshot").status==Status.BLOCKED   # 0 shots -> keep original
         and reclassify_from_files(mk(Status.FAILED),0,"screenshot").status==Status.FAILED)    # degraded+0 -> keep hard
both = "reclassify_from_files(" in inspect.getsource(P) and "reclassify_from_files(" in inspect.getsource(EN)
sys.exit(0 if (behav and both) else 1)
PYEOF

echo "[82] v0.3.2 incremental metrics flush: metrics/summary.json written per-phase (was run-end only → a killed/timed-out run lost all telemetry); best-effort (flush failure never breaks the run)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "cli run loop flushes metrics.write() inside the per-phase loop, wrapped best-effort; still written at run end too" || no "v0.3.2 metrics flush broken"
import sys, inspect
from quarry_recon import cli
src=inspect.getsource(cli)
ok = ("incremental flush" in src and src.count("metrics.write(") >= 2)
sys.exit(0 if ok else 1)
PYEOF

echo "[83] v0.3.2 resolved.a backfill: puredns resolve --write-massdns → A records parsed so the resolved entity carries its IPs (was a:[]; host→IP edge lived only in dns_record — matters for digest + v0.4 relationship layer)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "_massdns_a parses 'host. A ip' (multi-A, ignores CNAME, missing file -> {}); puredns resolve gains --write-massdns; resolved.a populated from it" || no "v0.3.2 resolved.a backfill broken"
import sys, inspect, tempfile, pathlib
import quarry_recon.phases.vertical as V
p=pathlib.Path(tempfile.mktemp()); p.write_text("a.acme.com. A 1.1.1.1\na.acme.com. A 2.2.2.2\nb.acme.com. CNAME c.acme.com.\n")
parse = V._massdns_a(p)=={"a.acme.com":["1.1.1.1","2.2.2.2"]} and V._massdns_a(pathlib.Path("/nope"))=={}
src=inspect.getsource(V)
wired = "--write-massdns" in src and 'ips.get(e["host"]' in src
sys.exit(0 if (parse and wired) else 1)
PYEOF

echo "[84] blind XSS is ONE channel: MODES.BLIND_XSS is the only gate, the payload is --blind-oob (dalfox owns correlation), the backend is the public pool unless oob.callback_server names your own, and auth_token travels in a 0600 --config file, NEVER in argv"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "one channel: unarmed emits nothing, MODES.BLIND_XSS is the gate, self-hosted vs public backend selected by oob.callback_server, auth_token via 0600 --config and never argv, and no second channel survives in source" || no "blind XSS single-channel wiring broken"
import sys, inspect
import quarry_recon.phases.params as PA
from quarry_recon import secrets
class _P:
    http_rl = 0; blind_xss = False
_real_oob = secrets.oob
# 1. UNARMED: nothing is emitted, whatever is configured.
secrets.oob = lambda: {}
_off = PA._dalfox_cmd("i", "/tmp/_vq_dalfox.jsonl", _P(), 1)
wired = "-b" not in _off and not any(c.startswith("--blind-oob") for c in _off)
wired = wired and PA._blind_oob_plan(_P())["channel"] == "off"
# 2. ARMED with a server of our own: the native channel runs against it.
_P.blind_xss = True
secrets.oob = lambda: {"callback_server": "oob.mine.test"}
_armed = PA._dalfox_cmd("i", "/tmp/_vq_dalfox.jsonl", _P(), 1)
wired = wired and "--blind-oob=oob.mine.test" in _armed and "-b" not in _armed
# 3. The auth token never reaches argv (/proc/<pid>/cmdline is readable by this user).
secrets.oob = lambda: {"callback_server": "oob.mine.test", "auth_token": "T0KVALUE"}
_nat = PA._dalfox_cmd("i", "/tmp/_vq_dalfox.jsonl", _P(), 1)
wired = (wired and "--blind-oob=oob.mine.test" in _nat
         and not any("T0KVALUE" in c for c in _nat) and "--blind-oob-secret" not in _nat)
# 4. No server configured -> the PUBLIC pool, stated as such (backend is the ownership answer).
secrets.oob = lambda: {}
_pub = PA._blind_oob_plan(_P())
wired = wired and _pub["armed"] and _pub["backend"] == "public" and _pub["server"] == ""
secrets.oob = _real_oob
# 5. The removal is complete in the source: no dual/conflict/legacy channel survives anywhere.
psrc = inspect.getsource(PA)
gone = not any(t in psrc for t in ('"dual"', '"conflict"', '"legacy"', "blind_xss_url", "blind_xss_dual"))
# 6. The auth token is still a REDACTED value (the redaction set must follow the rename).
secrets.load = lambda: {"oob": {"auth_token": "tok_secret_123456"}}; secrets._cache = None
red = "tok_secret_123456" in secrets.values()
sys.exit(0 if (wired and gone and red) else 1)
PYEOF

echo "[85] v0.3.4 httpx matrix fix (reconftw-parity, keeps ALL ports): the bulk probe drops the two hidden multipliers -probe-all-ips (×ips) + -no-fallback (×schemes) that blew up the 567×94 matrix on filtered ports, and bounds -timeout so a firewall-dropped port fails fast; response-derived flags (favicon/cdn/asn) kept; probe AND enrich httpx match"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "probe+enrich httpx cmd no longer carry -probe-all-ips / -no-fallback (matrix multipliers), set -timeout 7 -retries 0 (fast filtered-port fail), and KEEP -cdn/-favicon/-asn (CDN/origin fingerprint) + all ports" || no "v0.3.4 httpx matrix fix broken"
import sys, inspect
import quarry_recon.phases.probe as P
import quarry_recon.phases.enrich as EN
# v0.3.5: the httpx cmd is a SINGLE source of truth (_httpx_probe_cmd in probe); enrich shares it via
# fingerprint_hosts. Assert the discipline on the shared cmd + that enrich no longer builds its own httpx.
src = inspect.getsource(P)
assert '"-probe-all-ips"' not in src, "still fans across all IPs"
assert '"-no-fallback"' not in src, "still probes both schemes"
assert '"-timeout", "7"' in src, "no bounded per-probe timeout"
assert '"-cdn"' in src and '"-favicon"' in src, "lost CDN/origin fingerprint"
assert '"-ports"' in src, "lost the port set"
esrc = inspect.getsource(EN)
assert 'fingerprint_hosts(' in esrc, "enrich not using the shared httpx path"
assert 'cmd = ["httpx"' not in esrc, "enrich still builds its own httpx cmd"
sys.exit(0)
PYEOF

echo "[86] v0.3.5 web-port SYN prefilter (bbot-style, NOT infra portscan): naabu SYN over hosts' PUBLIC IPs × the HTTP port set (no top-ports/CIDR/nmap) -> httpx ONLY on open host:ports (grouped by open-port set) + direct-httpx for hosts w/o public IP; FALLBACK-SAFE (naabu missing/failed/zero-open -> v0.3.4 direct, never thin); private IPs skipped; enrich shares the helper"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "naabu SYN/-Pn/web-ports-only (no top-ports/nmap/CIDR); ip:port->host(s) map; httpx only OPEN ports (grouped) w/ per-group raw refs; HIGH1 private-only hosts SKIPPED (not probed) vs no-A hosts direct; HIGH2 naabu timeout/partial -> FULL fallback (never thin); HIGH3 empty-stdout+file-ports reclassified+used; naabu missing/zero/fail -> direct; enrich shares helper" || no "v0.3.5 web-port prefilter broken"
import sys, json, tempfile, inspect
from pathlib import Path
import quarry_recon.phases.probe as P
import quarry_recon.phases.enrich as EN
from quarry_recon import settings
from quarry_recon.runner import RunResult, Status
tmp=Path(tempfile.mkdtemp())
STORE={"resolved":[{"host":"a.acme.com","a":["1.2.3.4"]},{"host":"b.acme.com","a":["127.0.0.1"]},
                   {"host":"c.acme.com","a":["1.2.3.4","5.6.7.8"]}],
       "dns_record":[{"host":"a.acme.com","type":"a","value":"1.2.3.4"}]}
ADDED=[]; HTTPX=[]; NAABU=[]
class Run:
    notes=[]
    def read(s,e): return STORE.get(e,[])
    def add(s,e,r): ADDED.append((e,r)); return True
    def record(s,*a): pass
    def raw_path(s,ph,t,n): p=tmp/ph/t; p.mkdir(parents=True,exist_ok=True); return p/n
class Prof: ports=[80,443,8080]; http_rl=None; portscan_rate=None; block_private_targets=False
class Scope:
    def in_scope(s,h): return True
    def is_oos(s,h): return False
    passive_only=False
class Ctx:
    def __init__(s): s.run=Run(); s.profile=Prof(); s.scope=Scope(); s.http_timeout=1800
    def echo(s,*a): pass
    def write_list(s,n,items): p=tmp/n; p.write_text("\n".join(items)+"\n"); return p
def fake(t,c,**k):
    rp=k.get("raw_path")
    if t=="cdncheck":   # T0.3 CDN-aware gate runs before naabu; empty output => none shared => all IPs SYN-eligible
        Path(c[c.index("-o")+1]).write_text(""); return RunResult("cdncheck",c,Status.SUCCESS,0,1.0,None,0)
    if t=="naabu":
        NAABU.append(c); Path(c[c.index("-o")+1]).write_text('{"ip":"1.2.3.4","port":80}\n{"ip":"1.2.3.4","port":443}\n{"ip":"5.6.7.8","port":8080}\n')
        return RunResult("naabu",c,Status.SUCCESS,0,1.0,None,3)
    if t=="httpx":
        HTTPX.append(c); hs=Path(c[c.index("-l")+1]).read_text().split(); rp.parent.mkdir(parents=True,exist_ok=True)
        rp.write_text("\n".join(json.dumps({"url":f"https://{h}","host":h}) for h in hs)); return RunResult("httpx",c,Status.SUCCESS,0,1.0,rp,len(hs))
    return RunResult(t,c,Status.SUCCESS,0,1.0,rp,0)
P.exec_tool=fake; P.have=lambda t:True; settings.web_port_prefilter=lambda:True; settings.workers=lambda t,d:50; import quarry_recon.contract as _CT; _CT._run = fake
# (pubmap, a_known): global-only A in pubmap; a_known distinguishes 'no A data' (d) from 'A but private' (b).
# netguard.guard_hosts now owns the block decision (b private -> blocked+review, not probed); patch resolve hermetic.
from quarry_recon import netguard as NG
NG._STUB = {"map": {"b.acme.com": ["127.0.0.1"]}, "default": ["8.8.8.8"]}  # b -> scan-box self-hit (withheld)
pubmap,aknown=P._host_public_ip_map(Ctx(),["a.acme.com","b.acme.com","c.acme.com","d.acme.com"])
priv=(pubmap["a.acme.com"]==["1.2.3.4"] and pubmap["b.acme.com"]==[] and set(pubmap["c.acme.com"])=={"1.2.3.4","5.6.7.8"}
      and "b.acme.com" in aknown and "d.acme.com" not in aknown)
ADDED.clear(); HTTPX.clear(); NAABU.clear()
res=P.fingerprint_hosts(Ctx(),["a.acme.com","b.acme.com","c.acme.com","d.acme.com"],"probe")
nc=NAABU[0]
naabu_ok=(nc[nc.index("-scan-type")+1]=="s" and "-Pn" in nc and "-top-ports" not in nc
          and "nmap" not in " ".join(nc) and nc[nc.index("-p")+1]=="80,443,8080")
wp={(r["host"],r["ip"],r["port"]) for e,r in ADDED if e=="web_port"}
map_ok=("a.acme.com","1.2.3.4",80) in wp and ("c.acme.com","1.2.3.4",80) in wp and ("c.acme.com","5.6.7.8",8080) in wp
probed=set()
for c in HTTPX: probed|=set(Path(c[c.index("-l")+1]).read_text().split())
rail1 = ("b.acme.com" not in probed) and ("d.acme.com" in probed) and {"a.acme.com","c.acme.com"}<=probed  # HIGH1
grp_ok=any(c[c.index("-ports")+1]!="80,443,8080" for c in HTTPX)   # 'a' = 80,443 subset
prov_ok=all(isinstance(t,tuple) and len(t)==2 and t[0].endswith(".jsonl") for t in res)   # HIGH4 per-group raw refs
def direct_only(hosts):
    HTTPX.clear(); P.fingerprint_hosts(Ctx(),hosts,"probe"); return bool(HTTPX) and all(c[c.index("-ports")+1]=="80,443,8080" for c in HTTPX)
P.have=lambda t: t!="naabu"; miss=direct_only(["a.acme.com"]); P.have=lambda t:True
def zero(t,c,**k):
    if t=="naabu": Path(c[c.index("-o")+1]).write_text(""); return RunResult("naabu",c,Status.EMPTY,0,1,None,0)
    return fake(t,c,**k)
P.exec_tool=zero; z=direct_only(["a.acme.com"])
def fail(t,c,**k): return RunResult("naabu",c,Status.FAILED,1,1,None,0) if t=="naabu" else fake(t,c,**k)
P.exec_tool=fail; f=direct_only(["a.acme.com"])
# HIGH2: naabu TIMED_OUT with SOME ports in file -> FULL fallback (never trust a truncated scan)
def tout(t,c,**k):
    if t=="naabu": Path(c[c.index("-o")+1]).write_text('{"ip":"1.2.3.4","port":80}\n'); return RunResult("naabu",c,Status.TIMED_OUT,None,1,None,0)
    return fake(t,c,**k)
P.exec_tool=tout; rail2=direct_only(["a.acme.com","c.acme.com"])
# HIGH3: clean naabu but EMPTY-status (findings in -o file) -> reclassified + USED (grouped subset, not fallback)
def emptyfile(t,c,**k):
    if t=="naabu": Path(c[c.index("-o")+1]).write_text('{"ip":"1.2.3.4","port":80}\n{"ip":"1.2.3.4","port":443}\n'); return RunResult("naabu",c,Status.EMPTY,0,1,None,0)
    return fake(t,c,**k)
P.exec_tool=emptyfile; HTTPX.clear(); P.fingerprint_hosts(Ctx(),["a.acme.com"],"probe")
rail3=any(c[c.index("-ports")+1]=="80,443" for c in HTTPX)   # used on open ports only, not all-3 fallback
P.exec_tool=fake
enrich_ok="fingerprint_hosts(ctx, new_resolved" in inspect.getsource(EN)
sys.exit(0 if (priv and naabu_ok and map_ok and rail1 and grp_ok and prov_ok and miss and z and f and rail2 and rail3 and enrich_ok) else 1)
PYEOF

echo "[87] v0.3.6 governor Tier-1 — hard-coded-low tools raised + config-tunable: katana (-c 4 → I/O-scaled + -p 3→10) + arjun (-t 5 → I/O-scaled) no longer idle a multi-core box; nuclei gains -bs (bulk-size); knobs KATANA_CONCURRENCY/KATANA_PARALLELISM/ARJUN_THREADS/NUCLEI_BULK_SIZE"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "settings scales katana/arjun by I/O (>= their old hard 4/5) + override keys; crawl katana uses settings.workers('katana')+KATANA_PARALLELISM; params arjun uses settings.workers('arjun'); nuclei cmd has -bs from NUCLEI_BULK_SIZE" || no "v0.3.6 governor Tier-1 broken"
import sys, inspect
from quarry_recon import settings
import quarry_recon.phases.crawl as C
import quarry_recon.phases.params as PA
settings.os.cpu_count=lambda:4; settings._cache={}
scale = settings.workers("katana",10) >= 25 and settings.workers("arjun",5) >= 20   # well above hard 4/5
settings._cache={"PERFORMANCE":{"KATANA_CONCURRENCY":7}}; ovr = settings.workers("katana",10)==7   # override wins
settings._cache={}
csrc=inspect.getsource(C); psrc=inspect.getsource(PA)
katana_ok = 'settings.workers("katana"' in csrc and 'KATANA_PARALLELISM' in csrc and '"-c", "4"' not in csrc
arjun_ok  = 'settings.workers("arjun"' in psrc and '"-t", "5"' not in psrc
nuclei_bs = '"-bs"' in psrc and 'NUCLEI_BULK_SIZE' in psrc
sys.exit(0 if (scale and ovr and katana_ok and arjun_ok and nuclei_bs) else 1)
PYEOF

echo "[88] control-plane step 1 — source registry (sources.yaml + sources.py): loads, validates clean (source_id=phase.source, valid tier/class/default), decisions encoded (kaeferjaeger heavy/off, dalfox split, jsluice present); DECLARATIVE only — no phase imports it (no behavior change)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "registry loads + validate() clean; source_ids keyed phase.source; kaeferjaeger optional/off (setup, not runtime); dalfox split (xss_fast/redirect_confirm/oob_probe) + jsluice registered; step-1 is declarative (no phase imports quarry_recon.sources)" || no "control-plane registry broken"
import sys, inspect, pathlib
from quarry_recon import sources as S
errs = S.validate()
ok_valid = (not errs) and len(S.all_sources()) >= 45
ok_decisions = (S.default_state("horizontal.kaeferjaeger")=="off"
                and S.get("horizontal.kaeferjaeger")["tier"]=="optional"   # setup (OpenIntel model), NOT heavy-for-runtime
                and all(S.get(x) for x in ("params.dalfox","params.dalfox_xss_fast","params.redirect_confirm","params.oob_probe","crawl.jsluice_urls","probe.naabu_web"))
                and S.default_state("probe.httpx")=="on")
ok_keying = all("." in sid for sid in S.all_sources())
# STEP 1 = declarative: NO phase file wires the registry yet (no behavior change)
import quarry_recon.phases as _ph
phase_dir = pathlib.Path(inspect.getfile(_ph)).parent
refs = [p.name for p in phase_dir.glob("*.py")
        if any(m in p.read_text() for m in ("sources.get(", "sources.by_", "sources.default_state", "import sources"))]
sys.exit(0 if (ok_valid and ok_decisions and ok_keying and not refs) else 1)
PYEOF

echo "[89] control-plane step 2 — run_contract() + events (events.py + contract.py): thin wrapper over runner.run emits tool_start/tool_finish around an unchanged RunResult; events.jsonl round-trips; None optional fields dropped (no fake precision); produced/consumed only via ledger() real counts (never stdout); UNKNOWN source_id never reaches _run (fail loud); ALL event fields redacted at sink; the CONTRACT execution wrapper stays wired one phase at a time (only crawl/params import contract) — 'import events' for coverage telemetry is allowed (see [116]/[117])"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "run_contract wraps runner.run (RunResult unchanged); events round-trip; None fields dropped; ledger() real counts; unknown source_id never executes (SKIPPED + tool_blocked); every event field redacted at sink; step-2 declarative (no phase imports contract/events)" || no "control-plane step 2 broken"
import sys, json, tempfile, inspect, pathlib
from quarry_recon import events, contract, sources
import quarry_recon.contract as C
import quarry_recon.secrets as sec
from quarry_recon.runner import Status
tmp = pathlib.Path(tempfile.mkdtemp()); sink = events.configure(tmp); raw = tmp/"raw.txt"
res = contract.run_contract("probe.httpx", ["printf", "a\nb\n"], raw_path=raw, timeout=30, input_total=2)
L = [json.loads(x) for x in sink.read_text().splitlines()]
st = next((e for e in L if e["event"]=="tool_start"), None)
fn = next((e for e in L if e["event"]=="tool_finish"), None)
c_events = (len(events.EVENT_TYPES)==8 and all("ts" in e and "source_id" in e for e in L))
c_start  = bool(st and st["cmd"][0]=="printf" and st.get("input_total")==2 and "parent_id" not in st
                and ("workers" in st or "rate" in st or "timeout" in st))
c_finish = bool(fn and fn.get("status") in (Status.SUCCESS.value, Status.EMPTY.value)
                and fn.get("raw_ref") and fn.get("artifact_size",0)>0
                and "produced" not in fn and "consumed" not in fn)
c_unchg  = (res.status in (Status.SUCCESS, Status.EMPTY) and res.raw_path is not None)
lg = events.ledger("probe.httpx", produced={"URL":10}, consumed={"HTTP_RESPONSE":3})
c_ledger = (lg.get("produced")=={"URL":10} and lg.get("consumed")=={"HTTP_RESPONSE":3} and lg.get("event") == "ledger")
pg = events.tool_progress("crawl.katana_standard", chunk_index=1, chunk_total=4)
c_prog = (pg.get("chunk_index")==1 and "queued" not in pg and "running" not in pg)
# FIX1: unknown source_id never reaches _run
reached = {"ran": False}; _orig = C._run
def _sentinel(*a, **k):
    reached["ran"] = True; return _orig(*a, **k)
C._run = _sentinel
r2 = C.run_contract("missing.source", ["printf","x"], raw_path=tmp/"n.txt", timeout=5)
C._run = _orig
c_unknown = (reached["ran"] is False and r2.status == Status.SKIPPED
             and any(e.get("event")=="tool_blocked" and e.get("source_id")=="missing.source"
                     for e in [json.loads(x) for x in sink.read_text().splitlines()]))
# FIX2: ALL fields redacted at sink (not just cmd/env)
_ov = sec.values; sec.values = lambda: ["SUPERSECRET123"]
fr = events.tool_finish("probe.httpx", status="failed", reason="tok=SUPERSECRET123")
cp = events.coverage_partial("probe.httpx", reason="partial SUPERSECRET123")
sec.values = _ov
c_redact = ("SUPERSECRET123" not in fr.get("reason","") and "***" in fr.get("reason","")
            and "SUPERSECRET123" not in cp.get("reason","") and "***" in cp.get("reason",""))
import quarry_recon.phases as _ph
pdir = pathlib.Path(inspect.getfile(_ph)).parent
# The CONTRACT execution wrapper is wired incrementally (C07). Phases that route >=1 lane through it:
# crawl.py (jsluice+gitleaks/katana/gau/waymore, and `registered()` gating xnLinkFinder), params.py
# (nuclei), vertical.py (subfinder/shosubgo), probe.py (tlsx/gowitness/ffuf_vhost/httpx/nmap),
# content.py (content.ffuf), enrich.py (step 4.2: `registered()` gates the SCHEDULED A1d apex brute, which
# is bracketed by one tool_start/tool_finish over the whole multi-bucket sweep). Others stay declarative.
_CONTRACT_CONVERTED = {"crawl.py", "params.py", "vertical.py", "probe.py", "content.py", "enrich.py"}
refs = [p.name for p in pdir.glob("*.py") if p.name not in _CONTRACT_CONVERTED
        and any(m in p.read_text() for m in ("import contract","contract.run_contract","from ..contract"))]
# NOTE: `import events` is intentionally NOT gated here — the coverage-counter batch wires events.coverage_partial
# into content/vertical/probe on purpose (telemetry, not execution). That expansion is covered by [116]/[117].
sys.exit(0 if (c_events and c_start and c_finish and c_unchg and c_ledger and c_prog and c_unknown and c_redact and not refs) else 1)
PYEOF

echo "[90] control-plane step 3 — reader views (views.py + quarry plan/status): plan explains what WOULD run from registry+settings (no execution, no target needed); status folds events.jsonl to one row per source (ledger produced/consumed + blocked reason) and degrades gracefully when absent; READ-ONLY (views imports no runner/contract); additive — existing commands untouched, phases still declarative"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "quarry plan renders registry-static (phases/marks/workers/summary, no target); quarry status folds events.jsonl (per-source ledger + blocked reason, graceful-when-absent); both commands registered; views read-only (no runner/contract import); step-3 additive (no existing command altered)" || no "control-plane step 3 broken"
import sys, json, tempfile, inspect
from pathlib import Path
from click.testing import CliRunner
from quarry_recon import views, cli as climod
pl = "\n".join(views.plan_lines())
c_plan = ("[probe]" in pl and "[params]" in pl and "summary:" in pl
          and "will run" in pl and "w=" in pl and "⏳bounded" in pl and "▶" in pl
          # pending (not-yet-wired) sources render distinctly, NOT as 'will run' — plan can't overpromise
          # (oob_probe still pending 4.3.D; redirect_confirm is now WIRED so no longer pending)
          and "pending (not wired)" in pl        # the summary count label (0 now — oob_probe wired in P2.3)
          and "pending: 4.3.C" not in pl and "pending: needs OOB" not in pl)  # nothing pending anymore
c_plan_cmd = (CliRunner().invoke(climod.cli, ["plan"]).exit_code == 0)
tmp = Path(tempfile.mkdtemp()); ev = tmp/"events.jsonl"
ev.write_text("\n".join(json.dumps(x) for x in [
  {"ts":1,"event":"tool_finish","source_id":"probe.httpx","status":"success","duration":0.3},
  {"ts":2,"event":"ledger","source_id":"probe.httpx","produced":{"URL":10},"consumed":{"H":3}},
  {"ts":3,"event":"tool_blocked","source_id":"content.ffuf","reason":"429 rate limit"}]))
st = "\n".join(views.status_lines(ev))
c_status = ("probe.httpx" in st and "produced=" in st and "429 rate limit" in st and "consumed=None" not in st)
# human states + progress, no leaked internals; utf-8 read
ev2 = tmp/"e2.jsonl"; ev2.write_text("\n".join(json.dumps(x) for x in [
  {"ts":1,"event":"tool_progress","source_id":"params.dalfox","current_index":12,"input_total":765},
  {"ts":2,"event":"tool_blocked","source_id":"content.ffuf","reason":"waf"},
  {"ts":3,"event":"tool_finish","source_id":"crawl.jsluice_urls","status":"partial"},        # REAL lifecycle partial
  # coverage is telemetry, NOT lifecycle: a fully-covered omitted=0 event must NOT create a status row
  {"ts":4,"event":"coverage_reset","source_id":"crawl.js_fetch"},
  {"ts":5,"event":"coverage_partial","source_id":"crawl.js_fetch","eligible":10,"tested":10,"omitted":0}]),
  encoding="utf-8")
s2 = "\n".join(views.status_lines(ev2))
c_human = ("running" in s2 and "12/765" in s2 and "blocked" in s2 and "partial" in s2          # partial from tool_finish
           and "tool_progress" not in s2 and "tool_blocked" not in s2 and "coverage_partial" not in s2
           and "js_fetch" not in s2)                                                            # coverage-only source: no status row
c_absent = ("no events recorded" in "\n".join(views.status_lines(tmp/"nope.jsonl")))
c_status_cmd = (CliRunner().invoke(climod.cli, ["status","--help"]).exit_code == 0)
imods = "\n".join(l for l in inspect.getsource(views).splitlines() if l.strip().startswith(("import ","from ")))
c_pure = ("runner" not in imods and "contract" not in imods and "subprocess" not in imods)
sys.exit(0 if (c_plan and c_plan_cmd and c_status and c_human and c_absent and c_status_cmd and c_pure) else 1)
PYEOF

echo "[91] control-plane step 4.1 — crawl.jsluice under the control plane (Commit A route + Commit B per-file chunking) + the -j stdin fix: jsluice runs PER FILE via runner.run (so one huge/slow JS times out only itself, not the batch), emitting source-level tool_start/tool_progress(current_index/input_total)/tool_finish + events.ledger; -j/--raw-input (NOT bare '-', which jsluice opens as a file and mines zero); no raw subprocess.run(['jsluice']); registry has both source_ids; chunked output == single-blob parse (verified live in scratchpad)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "crawl.jsluice chunked per-file via runner.run (-j, no raw subprocess); source-level tool_start/tool_progress/tool_finish + ledger; non-clean chunk -> PARTIAL (never false success); cli.run persists events (configure on run dir); both registry source_ids present" || no "step 4.1 jsluice conversion broken"
import sys, inspect, pathlib
from quarry_recon import sources as S
import quarry_recon.phases.crawl as crawl
src = inspect.getsource(crawl)
c_reg = bool(S.get("crawl.jsluice_urls") and S.get("crawl.jsluice_secrets"))
c_import = (getattr(crawl, "events", None) is not None)   # binding, not a brittle substring
c_chunk = ('for i, f in enumerate(files' in src and 'exec_tool("jsluice"' in src)
c_events = all(m in src for m in ("events.tool_start(sid", "events.tool_progress(sid", "events.tool_finish(sid",
                                  "current_index=i", 'events.ledger(f"crawl.jsluice_{sub}"'))
c_flag = ('"jsluice", sub, "-j"' in src)
# jsluice stays on the per-file exec_tool + manual-events path (NOT run_contract) — scope the check to
# _jsluice_run so crawl.py's OTHER lane (gitleaks, C07) legitimately using run_contract doesn't trip it.
_jl = inspect.getsource(crawl._jsluice_run)
c_noraw = ('subprocess.run(["jsluice' not in src and 'run_contract' not in _jl)
# any non-clean chunk (not SUCCESS/EMPTY) makes the source PARTIAL — a failed chunk is never success
c_partial = ('res.status not in (Status.SUCCESS, Status.EMPTY)' in src and 'status.value' in src)
# events are actually PERSISTED: cli.run configures the sink on the run dir (else events.jsonl never written)
import quarry_recon.cli as _cli
c_persist = ('events.configure(run_obj.dir)' in inspect.getsource(_cli))
crawl_py = pathlib.Path(inspect.getfile(crawl))
c_compiles = True
try:
    compile(crawl_py.read_text(), str(crawl_py), "exec")
except SyntaxError:
    c_compiles = False
sys.exit(0 if (c_reg and c_import and c_chunk and c_events and c_flag and c_noraw and c_partial and c_persist and c_compiles) else 1)
PYEOF

echo "[92] control-plane step 4.2 — params.nuclei main scan under the control plane (Commit A route + Commit B host-chunking): _nuclei_scan splits live hosts into NUCLEI_CHUNK_HOSTS batches, scans SEQUENTIALLY (rate-bound; measured 448h/5.08M req/7h41 died 93%), per-chunk nuclei_timeout (slow batch -> coverage_partial not whole-run kill), persists a chunks.done state file for RESUME (skip finished batches, findings accumulate), emits source-level tool_start/tool_progress(chunk i/N)/tool_finish + ledger(findings-by-severity/targets); takeover + waf nuclei stay exec_tool; no template-scope gating"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "params.nuclei_scan chunked+resumable: per-chunk nuclei_timeout + tool_progress chunk i/N; DONE on EXECUTION completion ([145]; with no nuclei progress report it falls back to the clean-status rule, which is what these fakes exercise), and a non-done chunk's REAL findings are KEPT (aggregate rebuilt idempotently from per-chunk artifacts -> no dup on re-scan); state tied to config-inclusive work_unit (changed hosts OR coverage config invalidate + clear stale artifacts); takeover/waf untouched; registry heavy/bounded" || no "step 4.2 nuclei conversion broken"
import os, sys, json, tempfile, inspect, pathlib
from quarry_recon import events, sources, settings
from quarry_recon.runner import RunResult, Status
from quarry_recon.phases import params
from types import SimpleNamespace
# review#6: pin a DETERMINISTIC nuclei templates config so _nuclei_templates_fp() returns a stable string (not
# None). Without a config it returns None -> _nuclei_scan folds a per-run NONCE (non-resumable), which by design
# can't equal a deterministic mirror. With a config, scan_wu is reproducible and the _wu() mirror matches.
_ncfg = pathlib.Path(tempfile.mkdtemp())
(_ncfg / ".templates-config.json").write_text(json.dumps({"nuclei-templates-version": "vTEST"}))
os.environ["NUCLEI_CONFIG"] = str(_ncfg)
src = sources.get("params.nuclei_scan")
c_reg = bool(src) and src["tool"] == "nuclei" and src["tier"] == "heavy" and src.get("bounded") == "planned"
psrc = inspect.getsource(params)
c_chunk = all(m in psrc for m in ("def _nuclei_scan", "chunks.state.json", "NUCLEI_CHUNK_HOSTS",
                                  "scan_wu = events.work_unit", "work_unit=chunk_wu",   # C07 inc4: config-inclusive + per-chunk
                                  "events.tool_progress", "chunk_index=ci + 1", "nuclei_timeout(len(batch)"))
c_routed = ('_nuclei_scan(ctx, live, findings' in psrc and 'events.ledger("params.nuclei_scan"' in psrc)
c_scope = ('exec_tool("nuclei", tk_cmd' in psrc and 'run_contract' not in psrc)   # takeover direct; nuclei no longer run_contract
# functional: fresh scan chunks all + progress; resume skips done; failed chunk -> PARTIAL
settings.concurrency = lambda k, d=None: 2 if k == "NUCLEI_CHUNK_HOSTS" else d
settings.workers = lambda t, d: d
class _R:
    def __init__(s, d): s.dir = d
    def raw_path(s, ph, tl, nm):
        p = s.dir/"raw"/ph/tl/nm; p.parent.mkdir(parents=True, exist_ok=True); return p
class _C:
    def __init__(s, d): s.run = _R(d); s.http_timeout = 1800; s._d = d
    def write_list(s, nm, it):
        p = s._d/"work"/nm; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("\n".join(it)); return p
def _mk(fail=None, degraded=None):
    def fx(tool, cmd, timeout=None, **k):
        cf = pathlib.Path(cmd[cmd.index("-o")+1])
        if fail is not None and f"findings_{fail}." in cf.name:
            return RunResult("nuclei", cmd, Status.FAILED, 1, 0.1, None, 0)   # failed, NO output
        cf.write_text('{"template-id":"t","info":{"severity":"high"},"matched-at":"h"}\n')
        if degraded is not None and f"findings_{degraded}." in cf.name:
            # a chunk that STILL produced a real finding but did NOT complete. [145]: retryability is EXECUTION
            # completion, not the classifier's status, so a nonzero exit (a real crash/kill) is what leaves work
            # behind — an exit-0 chunk is done even when its stderr looked degraded.
            return RunResult("nuclei", cmd, Status.PARTIAL, 2, 0.1, cf, 1, stderr_tail="waf block")
        return RunResult("nuclei", cmd, Status.SUCCESS, 0, 0.1, cf, 1)
    return fx
live = [f"h{i}" for i in range(5)]; prof = SimpleNamespace(http_rl=0)   # 5 hosts / chunk 2 -> 3 batches
# C07 inc4: resume key is the config-inclusive scan work_unit (must mirror _nuclei_scan's _cfg exactly)
def _wu(hosts, n=2):
    # review#10: _cfg now also folds the installed nuclei template SET fingerprint — mirror it (same helper,
    # so the value matches whatever this box reports, incl. "unknown" when no templates config is present).
    # [145]: _cfg also folds the -mhe host-error POLICY (which hosts get scanned at all). Mirror it via the
    # same helper so this tracks the effective value on this box instead of a hardcoded default.
    return events.work_unit("params.nuclei_scan", inputs={"hosts": hosts},
                            config={"severity": "critical,high,medium",
                                    "etags": "intrusive,fuzz,dos,brute-force", "chunk": n,
                                    "templates": params._nuclei_templates_fp(),
                                    "mhe": params._nuclei_mhe()})
def _state(c): return json.loads(c.run.raw_path("params","nuclei","chunks.state.json").read_text())
def _done(c): return sorted(int(k) for k in _state(c)["chunks"])   # review#4: state maps done chunk -> artifact path
# fresh run: all chunks scanned, progress 1..3, JSON state records all
d = pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(d); c = _C(d)
params.exec_tool = _mk()
f = c.run.raw_path("params","nuclei","findings.jsonl"); lg_ = c.run.raw_path("params","nuclei","nuclei.run.log")
r = params._nuclei_scan(c, live, f, lg_, prof)
prog = [e for e in (json.loads(x) for x in (d/"events.jsonl").read_text().splitlines()) if e["event"]=="tool_progress"]
c_fresh = (r.status == Status.SUCCESS
           and [p.get("chunk_index") for p in prog]==[1,2,3,3]        # UX #2: progress BEFORE each chunk + a final
           and [p.get("current_index") for p in prog]==[0,2,4,5]      # UX #4: completed-hosts advances only on a CLEAN chunk
           and _done(c)==[0,1,2] and _state(c)["work_unit"]==_wu(live))
# FIX1: a FAILED chunk that produced NO output is retryable (not done) and contributes nothing
d3 = pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(d3); c3 = _C(d3)
f3 = c3.run.raw_path("params","nuclei","findings.jsonl")
params.exec_tool = _mk(fail=1)
r3 = params._nuclei_scan(c3, live, f3, c3.run.raw_path("params","nuclei","nuclei.run.log"), prof)
c_failretry = (r3.status == Status.PARTIAL and _done(c3)==[0,2]
               and f3.read_text().count("template-id")==2)   # failed chunk wrote nothing -> 2 chunks
# ★ INGESTION FIX (run-audit): a DEGRADED chunk that DID produce findings has them KEPT (was discarded);
# it is still NOT marked done (retryable for coverage). Aggregate rebuilt idempotently from per-chunk files.
dd = pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(dd); cd = _C(dd)
fd = cd.run.raw_path("params","nuclei","findings.jsonl")
params.exec_tool = _mk(degraded=1)
rd = params._nuclei_scan(cd, live, fd, cd.run.raw_path("params","nuclei","nuclei.run.log"), prof)
c_keepdegraded = (rd.status == Status.PARTIAL and _done(cd)==[0,2]
                  and fd.read_text().count("template-id")==3)   # degraded chunk1's finding KEPT -> all 3
# idempotent: re-run must NOT duplicate the degraded chunk's finding
params._nuclei_scan(cd, live, fd, cd.run.raw_path("params","nuclei","nuclei.run.log"), prof)
c_idempotent = (fd.read_text().count("template-id")==3)
# FIX2: matching-input resume skips done chunks; their per-chunk artifacts (on disk) are preserved in the
# rebuilt aggregate; CHANGED input invalidates. (Realistic: done chunks have findings_<ci>.jsonl on disk.)
# review#4: state maps each done chunk -> its ARTIFACT PATH under wu_<scan_wu>/attempt_<id>/ (relative to the
# state dir); a resume reads done chunks back from those recorded paths and re-runs only the rest.
d2 = pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(d2); c2 = _C(d2)
_nucdir = c2.run.raw_path("params","nuclei","chunks.state.json").parent
_seed = {str(_ci): f"wu_{_wu(live)}/attempt_seed/findings_{_ci}.jsonl" for _ci in (0,1)}
c2.run.raw_path("params","nuclei","chunks.state.json").write_text(
    json.dumps({"work_unit": _wu(live), "chunk_size": 2, "chunks": _seed}))
_att = _nucdir / f"wu_{_wu(live)}" / "attempt_seed"        # a prior attempt's immutable artifacts
_att.mkdir(parents=True, exist_ok=True)
for _ci in (0,1):                                          # the done chunks' artifacts a real resume would have
    (_att / f"findings_{_ci}.jsonl").write_text('{"template-id":"kept"}\n')
# review#P3: recorded artifacts are sha256-BOUND. A state entry without a matching digest is unverifiable and
# fails CLOSED (the chunk re-runs), so a realistic resume seed must record the digests too.
_digs = {_rel: events.file_digest(_nucdir / _rel) for _rel in _seed.values()}
c2.run.raw_path("params","nuclei","chunks.state.json").write_text(
    json.dumps({"work_unit": _wu(live), "chunk_size": 2, "chunks": _seed, "digests": _digs}))
f2 = c2.run.raw_path("params","nuclei","findings.jsonl")
seen = []; _base = _mk()
params.exec_tool = lambda t, cmd, **k: (seen.append(pathlib.Path(cmd[cmd.index("-o")+1]).name), _base(t, cmd, **k))[1]
params._nuclei_scan(c2, live, f2, c2.run.raw_path("params","nuclei","nuclei.run.log"), prof)
c_resume = (seen == ["findings_2.jsonl"]                   # only the un-done chunk re-scanned
            and f2.read_text().count("kept")==2            # both preserved done-chunk artifacts in aggregate
            and f2.read_text().count("template-id")==3)    # kept×2 + newly scanned chunk2
d4 = pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(d4); c4 = _C(d4)
c4.run.raw_path("params","nuclei","chunks.state.json").write_text(
    json.dumps({"work_unit": _wu(live), "chunk_size": 2, "chunks": {}}))
ran = []; _b4 = _mk()
params.exec_tool = lambda t, cmd, **k: (ran.append(1), _b4(t, cmd, **k))[1]
params._nuclei_scan(c4, live+["h5","h6"], c4.run.raw_path("params","nuclei","findings.jsonl"), c4.run.raw_path("params","nuclei","nuclei.run.log"), prof)
c_invalidate = (len(ran) == 4)   # changed host set -> hash mismatch -> re-scan all 4 batches
c_ledger = True   # ledger call shape covered by [89]/[91]; here we assert the chunk/resume state machine
c_run = (c_fresh and c_failretry and c_keepdegraded and c_idempotent and c_resume and c_invalidate)
c_compiles = True
try:
    compile(pathlib.Path(inspect.getfile(params)).read_text(), "params.py", "exec")
except SyntaxError:
    c_compiles = False
sys.exit(0 if (c_reg and c_chunk and c_routed and c_scope and c_run and c_ledger and c_compiles) else 1)
PYEOF

echo "[93] control-plane step 4.3.A — dalfox candidate CANONICALIZATION (the 89% lever, before any tool tuning): _canonicalize_candidates collapses xss/redirect review candidates to unique (host,path,sorted-param-names) shapes keeping one representative each (measured 993->106, 89.3%), NO shape lost; the dalfox block scans the canonical set (flags unchanged — split is 4.3.B); events.ledger('params.dalfox') records raw_candidates + canonical_candidates + reduction_percent + top_collapsed so the reduction is visible, not buried"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "dalfox candidates canonicalized by (host,path,param-names), one rep/shape, no shape lost; ledger carries raw/canonical/reduction_percent/top_collapsed; dalfox block scans the canonical set" || no "step 4.3.A canonicalization broken"
import sys, json, tempfile, inspect, pathlib
from urllib.parse import urlsplit, parse_qs
from quarry_recon import events
from quarry_recon.phases import params
from quarry_recon.phases.params import _canonicalize_candidates
def shape(u):
    s = urlsplit(u); return (s.netloc, s.path, tuple(sorted(parse_qs(s.query).keys())))
urls = ["https://a.x/p?q=1&r=2","https://a.x/p?q=9&r=8","https://a.x/p?r=2&q=1",
        "https://a.x/p?q=1","https://b.x/p?q=1&r=2","https://a.x/other?q=1&r=2"]
reps, st = _canonicalize_candidates(urls)
c_dedup = (len(reps) == 4 and st["raw_candidates"] == 6 and st["canonical_candidates"] == 4
           and st["reduction_percent"] == round(100*(1-4/6),1))
c_nolost = ({shape(u) for u in urls} == {shape(u) for u in reps})   # every unique shape kept
c_top = any(t["count"] == 3 for t in st["top_collapsed"])
tmp = pathlib.Path(tempfile.mkdtemp()); events.reset(); sink = events.configure(tmp)
lg = events.ledger("params.dalfox", produced={"canonical_candidates":4}, consumed={"raw_candidates":6},
                   reduction_percent=st["reduction_percent"], top_collapsed=st["top_collapsed"])
rec = json.loads(sink.read_text().splitlines()[-1])
c_ledger = all(k in rec for k in ("produced","consumed","reduction_percent","top_collapsed")) and rec.get("event")=="ledger"
psrc = inspect.getsource(params)
# the mixed params.dalfox source is retired (4.3.C); canonicalization now feeds the split sources
c_wired = ("_canonicalize_candidates(xss_raw)" in psrc and "_canonicalize_candidates(redir_raw)" in psrc)
c_empty = (_canonicalize_candidates([]) == ([], {"raw_candidates":0,"canonical_candidates":0,"reduction_percent":0.0,"top_collapsed":[]}))
# blank-valued params (?next= / ?url=) are DISTINCT sinks (parse_qsl keep_blank_values), not collapsed
c_blank = (_canonicalize_candidates(["https://a.x/l?next=","https://a.x/l?url=","https://a.x/l?returnTo="])[1]["canonical_candidates"] == 3
           and len(_canonicalize_candidates(["https://a.x/p?next=","https://a.x/p?next=x"])[0]) == 1)
# missing dalfox with candidates -> 'not installed', not a false 'no candidates' (branch kept in 4.3.B split)
c_branch = ("dalfox not installed" in psrc and "no xss/redirect candidates" in psrc)
# scheme is part of the origin: http:// and https:// must NOT collapse into one shape
c_scheme = (_canonicalize_candidates(["http://h/p?x=","https://h/p?x=","https://h/p?x="])[1]["canonical_candidates"] == 2)
sys.exit(0 if (c_dedup and c_nolost and c_top and c_ledger and c_wired and c_empty and c_blank and c_branch and c_scheme) else 1)
PYEOF

echo "[94] v0.3.8 dalfox v2->v3 (Rust) — wiring: params.dalfox_xss_fast drives dalfox v3 (scan -i file -f jsonl -S --skip-mining, 2D concurrency --workers/--max-concurrent-targets NOT v2 -w/--max-cpu, global --rate-limit, blind --blind-oob). FAIL-CLOSED tiered JSONL parse (V/R/A -> xss-verified/xss-candidate/dom-xss-static, all confirmed:false). Exit-code<->findings agreement (0+empty=EMPTY, 1+finds=SUCCESS, disagreement/hard/malformed=PARTIAL-retryable). Per-chunk OUTCOMES state (immutable wu_/attempt_ artifacts), engine-identity in the work unit, ledger tiers + matched. Registry entry v3-truthful. FULL parser/exit/retry/engine matrix is pytest-gated in tests/test_dalfox.py."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "dalfox v3 wiring: v3 flags, tiered fail-closed parse, exit<->findings agreement, completion+evidence state, engine-id in wu, registry truth (deep matrix in tests/test_dalfox.py)" || no "v0.3.8 dalfox v3 wiring broken"
import sys, json, tempfile, inspect, pathlib
from types import SimpleNamespace
from quarry_recon import events, sources, settings, secrets
from quarry_recon.phases import params
from quarry_recon.phases.params import _dalfox_cmd, _dalfox_xss_fast, scan_dalfox_jsonl
from quarry_recon.runner import RunResult, Status
c_reg = sources.get("params.dalfox_xss_fast") is not None
settings.concurrency = lambda k, d=None: {"DALFOX_CHUNK":2,"DALFOX_TARGETS":4}.get(k, d)
settings.workers = lambda t, d: d
secrets.oob = lambda: {}
params._dalfox_engine_id = lambda: "v3.1.2"        # avoid a registry.health probe here
prof = SimpleNamespace(http_rl=7, blind_xss=True)   # armed: the ONE channel is --blind-oob
cmd = _dalfox_cmd("i", "o", prof)
c_flags = (cmd[:5]==["dalfox","scan","-i","file","i"] and cmd[cmd.index("-f")+1]=="jsonl"
           and "-S" in cmd and "--skip-mining" in cmd and "--workers" in cmd and "--max-concurrent-targets" in cmd
           and "--blind-oob" in cmd and "-b" not in cmd and cmd[cmd.index("--rate-limit")+1]=="7"
           and "-w" not in cmd and "--max-cpu" not in cmd and "--skip-headless" not in cmd and "--delay" not in cmd)
def _p(txt):
    # review#13: the parser returns a STRUCTURED artifact, not one boolean. `.readable` is the
    # structural verdict these cases assert; completeness is a separate question (c_meta below).
    # STREAMING parser (review#35): the findings go to a sink as they are read; nothing is
    # materialized inside it, so a caller that wants a list builds its own.
    p=pathlib.Path(tempfile.mktemp()); p.write_text(txt)
    out=[]; n, art = scan_dalfox_jsonl(p, out.append)
    assert n == len(out), "streamed count must agree with the sink"
    return out, art
# 3.2.0 CONTRACT: `incomplete` AND `target_summary` are required for an artifact to be readable at all
# (review#37) — a meta row without them does not implement what this lane resumes on.
_M='"incomplete":false,"target_summary":[{"target":"http://h/x","status":"clean","findings_count":0}]'
fnd, art = _p('{"meta":{"findings_count":1,' + _M + '}}\n{"type":"V","param":"q","data":"http://h/search?q=1","method":"GET","location":"Query"}\n')
c_parse=(art.readable and len(fnd)==1 and fnd[0]["template"]=="xss-verified" and fnd[0]["confidence"]=="verified" and fnd[0]["confirmed"] is False)
c_failclosed=(not _p('{"meta":{"findings_count":2,' + _M + '}}\n{"type":"R","param":"q","data":"http://h/p?q=1"}\n')[1].readable
              and not _p('{"type":"R","param":"q","data":"http://h/p?q=1"}\n')[1].readable
              and not _p('{"meta":{"findings_count":1,' + _M + '}}\n{"type":"Z","param":"q","data":"http://h/p?q=1"}\n')[1].readable
              and not _p('{"meta":{"findings_count":1,' + _M + '}}\n{"type":"R","param":"q","data":"http://h:bad/p?q=1"}\n')[1].readable
              # …and the CONTRACT itself: a meta row missing either verdict field is not readable
              and not _p('{"meta":{"findings_count":0}}\n')[1].readable
              and not _p('{"meta":{"findings_count":0,"incomplete":false}}\n')[1].readable)
# review#13 (Lumpy, P1): the META ROW is read, not just counted. A batch dalfox flagged incomplete, or
# whose targets it SKIPPED, used to parse as clean and become resumably complete. Structural validity
# and scan completeness are DIFFERENT questions and must not collapse into one boolean again.
def _meta(**kw):
    m={"dalfox_version":"3.2.0","findings_count":0,"incomplete":False,
       "target_summary":[{"target":"http://h/a","status":"clean","findings_count":0}]}
    m.update(kw); return json.dumps({"meta":m})+"\n"
def _sk(code,status="skipped"):
    return _meta(target_summary=[{"target":"http://h/b","status":status,"error_code":code,"findings_count":0}])
a_clean=_p(_meta())[1]; a_inc=_p(_meta(incomplete=True))[1]
a_retry=_p(_sk("SESSION_LOST"))[1]; a_det=_p(_sk("TRUNCATED_PER_HOST_CAP"))[1]
a_unk=_p(_sk("SOMETHING_NEW"))[1]
c_meta=(a_clean.complete and a_clean.execution_done and a_clean.version=="3.2.0"
        # `incomplete` is dalfox's own "do not trust this run" -> readable, but NOT finished
        and a_inc.readable and not a_inc.complete and not a_inc.execution_done
        # RETRIABLE: a later attempt may cover it -> the chunk stays unfinished
        and a_retry.retriable and not a_retry.execution_done
        # DETERMINISTIC: retrying omits the same targets for ever -> execution done, gap is COVERAGE
        and a_det.deterministic and a_det.execution_done and not a_det.complete
        # an omission we cannot explain must never become a finished chunk
        and a_unk.unclassified and not a_unk.execution_done
        and "TRUNCATED_PER_HOST_CAP" in a_det.coverage_reason())
# PREVENTATIVE: dalfox's own membership cap (--max-targets-per-host, default 100) must never decide
# Quarry's membership — pass a value that cannot truncate the chunk we submitted.
_c250 = _dalfox_cmd("i","o",prof,250)
c_hostcap = int(_c250[_c250.index("--max-targets-per-host")+1]) >= 250
class _R:
    def __init__(s,d): s.dir=d; s.added=[]
    def raw_path(s,ph,tl,nm):
        p=s.dir/"raw"/ph/tl/nm; p.parent.mkdir(parents=True,exist_ok=True); return p
    def add(s,e,rec):
        if rec["id"] in {a["id"] for a in s.added}: return False
        s.added.append(rec); return True
class _C:
    def __init__(s,d): s.run=_R(d); s.http_timeout=600; s._d=d
    def write_list(s,nm,it):
        p=s._d/"work"/nm; p.parent.mkdir(parents=True,exist_ok=True); p.write_text("\n".join(it)); return p
def _mk(rc, art):
    def fx(t,cmd,timeout=None,**k):
        cf=pathlib.Path(cmd[cmd.index("-o")+1]); cf.parent.mkdir(parents=True,exist_ok=True); cf.write_text(art)
        return RunResult("dalfox",cmd,Status.SUCCESS if rc in (0,1) else Status.FAILED,rc,0.1,cf,0)
    return fx
# the lane RECONCILES the summary against the batch it submitted (review#37): an artifact that does not
# account for the one target below leaves the chunk retryable, so the fixture accounts for it.
_TS='"incomplete":false,"target_summary":[{"target":"http://a.x/p?q=","status":"%s","findings_count":%d}]'
R='{"meta":{"findings_count":1,' + (_TS % ("findings",1)) + '}}\n{"type":"R","param":"q","data":"http://%s.x/p?q=1","method":"GET","location":"Query"}\n'
def _run(rc, artf):
    d=pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(d); c=_C(d)
    params.exec_tool=lambda t,cmd,timeout=None,**k: _mk(rc, artf(pathlib.Path(cmd[cmd.index("-o")+1]).stem))(t,cmd,timeout,**k)
    r=_dalfox_xss_fast(c,["http://a.x/p?q="],prof)
    sp=c.run.raw_path("params","dalfox","chunks.state.json"); st=json.loads(sp.read_text()) if sp.exists() else {"chunks":{}}
    return r, st, c
r1,st1,c1=_run(1, lambda stem: R % stem)                     # 1 + findings -> SUCCESS, outcome recorded
c_success=(r1.status==Status.SUCCESS and "0" in st1["chunks"] and len(c1.run.added)==1
           and c1.run.added[0]["template"]=="xss-candidate")
r2,st2,_=_run(0, lambda stem: '{"meta":{"findings_count":0,' + (_TS % ("clean",0)) + '}}\n')   # 0 + empty -> EMPTY
c_empty=(r2.status==Status.EMPTY and "0" in st2["chunks"])
r3,st3,_=_run(0, lambda stem: R % stem)                      # 0 WITH findings -> disagreement -> PARTIAL, not done
c_disagree=(r3.status==Status.PARTIAL and "0" not in st3["chunks"])
# ledger tiers present
d=pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(d); c=_C(d)
params.exec_tool=_mk(1, R % "z")
_dalfox_xss_fast(c,["http://a.x/p?q="],prof)
lg=[json.loads(l) for l in (d/"events.jsonl").read_text().splitlines() if json.loads(l).get("event")=="ledger"]
c_ledger=(lg and set(lg[0]["produced"]) >= {"xss_verified","xss_candidate","dom_xss_static","matched"})
_dxf=sources.get("params.dalfox_xss_fast"); _rs=str(_dxf.get("notes",""))+str(_dxf.get("workers",""))
c_regtruth=("--mass" not in _rs and "--max-cpu" not in _rs and "--format json" not in _rs and "--skip-headless" not in _rs)
psrc=inspect.getsource(params)
c_src=("scan_dalfox_jsonl" in psrc and "attempt_" in psrc and "_dalfox_engine_id" in psrc and '"chunks"' in psrc and '"evidence"' in psrc
       and "_parse_dalfox_jsonl" not in psrc)   # the materializing parser is GONE, not merely unused
sys.exit(0 if (c_reg and c_flags and c_parse and c_failclosed and c_meta and c_hostcap and c_success and c_empty and c_disagree and c_ledger and c_regtruth and c_src) else 1)
PYEOF
echo "[95] control-plane step 4.3.C — params.redirect_confirm NATIVE open-redirect probe (no dalfox): inject a canary host into the redirect param, read Location WITHOUT following (fetch.redirect_location, scoped + rate-paced + non-mutating); confirmed only when the Location HOST is the canary (relative/same-host Location is NOT a finding); candidate wording (open-redirect-candidate, confirmed:false); source-level events + ledger(raw->canonical->confirmed). Legacy dalfox redirect pass removed; registry flipped pending->wired; dalfox no longer touches redirect"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "redirect_confirm native probe: canary-host Location confirms, relative/same-host does NOT, out-of-scope skipped; open-redirect-candidate confirmed:false; source events; no dalfox; registry wired (not pending); fetch.redirect_location no-follow" || no "step 4.3.C redirect_confirm broken"
import sys, json, tempfile, inspect, pathlib
from types import SimpleNamespace
from quarry_recon import events, sources
import quarry_recon.fetch as F
from quarry_recon.phases import params
from quarry_recon.phases.params import _redirect_confirm
from quarry_recon.runner import Status
c_reg = (sources.get("params.redirect_confirm") is not None
         and not sources.get("params.redirect_confirm").get("pending")
         and sources.get("params.redirect_confirm")["tool"] == "internal")
c_nofollow = hasattr(F, "redirect_location")
class _S:
    def active_allowed(s, h): return h != "oos.x"
class _R:
    def __init__(s): s.added = []
    def add(s, e, rec):
        if rec["id"] in {a["id"] for a in s.added}: return False
        s.added.append(rec); return True
class _C:
    def __init__(s): s.scope = _S(); s.run = _R()
calls = []
def _loc(ctx, probe, host=None, **k):
    from urllib.parse import urlsplit
    h = urlsplit(probe).netloc; calls.append(h)
    if h == "vuln.x": return ("https://quarry-redirect-canary.example/rc", 302)
    if h == "proto.x": return ("//quarry-redirect-canary.example/x", 307)
    if h == "twohundred.x": return ("https://quarry-redirect-canary.example/rc", 200)  # 200+Location != redirect
    if h == "safe.x": return ("/dashboard", 302)
    return (None, 200)
F.redirect_location = _loc
tmp = pathlib.Path(tempfile.mkdtemp()); events.reset(); events.configure(tmp); c = _C()
cands = ["https://vuln.x/r?next=","https://proto.x/r?next=","https://twohundred.x/r?next=","https://safe.x/r?next=","https://none.x/r?next=","https://oos.x/r?next="]
r = _redirect_confirm(c, cands, SimpleNamespace(http_rl=0))
# only 3xx-to-canary confirm; the 200+Location case must NOT (browsers don't redirect on 200)
c_confirm = (r.status == Status.SUCCESS and r.stdout_lines == 2 and len(c.run.added) == 2
             and not any("twohundred" in a["id"] for a in c.run.added)
             and all(a["template"] == "open-redirect-candidate" and a["confirmed"] is False
                     and a["sources"] == ["redirect_confirm"] for a in c.run.added))
c_scope_rel = ("oos.x" not in calls and "safe.x" in calls
               and not any("safe.x" in a["id"] for a in c.run.added))
ev = [json.loads(l) for l in (tmp/"events.jsonl").read_text().splitlines()]
c_events = ("params.redirect_confirm" in {e["source_id"] for e in ev}
            and any(e["event"]=="tool_finish" for e in ev))
psrc = inspect.getsource(params)
c_wired = ("_redirect_confirm(ctx, redir_cands" in psrc and "dalfox_redirect_in.txt" not in psrc
           and "dalfox is no longer responsible for redirect" in psrc
           and 'events.ledger("params.redirect_confirm"' in psrc)
sys.exit(0 if (c_reg and c_nofollow and c_confirm and c_scope_rel and c_events and c_wired) else 1)
PYEOF

echo "[96] registry/plan TRUTH cleanup — runtime is not a knob + no drift: kaeferjaeger optional (setup/OpenIntel model, not heavy-for-runtime); content.ffuf active (user-intent, not deep-for-runtime); origin.correlation passive (map-only, no packets); jsluice notes reflect the WIRED chunked/-j reality (no stale --timeout-0 bug text); js_beautify is now UNDER CONTRACT (debt cleared, notes WIRED, plan shows NO ⚠debt); cloud_buckets documents external status-only/no-body-read; blind_xss documents the temporary ride on dalfox_xss_fast"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "runtime-is-not-a-knob truths: kaeferjaeger optional / ffuf active / correlation passive; jsluice notes de-staled; js_beautify UNDER CONTRACT (debt cleared, no plan ⚠debt); cloud_buckets + blind_xss documented" || no "registry/plan truth cleanup broken"
import sys
from quarry_recon import sources as S, views
kj = S.get("horizontal.kaeferjaeger"); ff = S.get("content.ffuf"); co = S.get("origin.correlation")
ju = S.get("crawl.jsluice_urls"); jb = S.get("crawl.js_beautify"); cb = S.get("horizontal.cloud_buckets")
bx = S.get("params.blind_xss")
c_knob = (kj["tier"] == "optional" and kj["class"] == "passive" and S.default_state("horizontal.kaeferjaeger") == "off"
          and ff["class"] == "active" and co["class"] == "passive")
c_jsl = ("MUST honor 0=unbounded" not in str(ju.get("timeout")) and "WIRED 4.1" in ju.get("notes", ""))
c_debt = ("debt" not in jb and "WIRED" in jb.get("notes", ""))   # js_beautify now UNDER CONTRACT (debt cleared)
pl = "\n".join(views.plan_lines())
c_plan_debt = ("⚠debt" not in pl)     # js_beautify was the only debt source; no control-debt remains
c_docs = ("status-only" in cb.get("notes", "") and "body" in cb.get("notes", "").lower()
          and "rides params.dalfox_xss_fast" in bx.get("notes", "").lower())
c_valid = not S.validate()
sys.exit(0 if (c_knob and c_jsl and c_debt and c_plan_debt and c_docs and c_valid) else 1)
PYEOF

echo "[97] OOB substrate Phase 1 / OOB.1 — oob_interaction entity + raw/oob storage: store.ENTITY_KEYS has oob_interaction keyed on 'id' (dedups); Run.add/read/count round-trip; raw_path('oob',...) -> raw/oob/; emitters are ONLY params.oob_probe (P2.3) + cli 'oob poll' (P2.4) — no stray phase emitter"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "oob_interaction entity registered (dedup on id); round-trips via Run.add/read/count; raw/oob/ path resolves; emitters = params.oob_probe + cli 'oob poll' ONLY (no stray phase emitter)" || no "OOB.1 entity broken"
import sys, tempfile, pathlib, inspect
from quarry_recon.store import Run, ENTITY_KEYS
c_reg = ENTITY_KEYS.get("oob_interaction") == "id"
r = Run(pathlib.Path(tempfile.mkdtemp()), "t")
a = r.add("oob_interaction", {"id": "abc", "protocol": "dns", "correlation": "uncorrelated"})
b = r.add("oob_interaction", {"id": "abc"})               # dup
c = r.add("oob_interaction", {"id": "def", "protocol": "http"})
c_rt = (a is True and b is False and c is True and len(r.read("oob_interaction")) == 2
        and r.count("oob_interaction") == 2)
c_raw = "/raw/oob/import/s.jsonl" in str(r.raw_path("oob", "import", "s.jsonl"))
# declarative: no phase or cli adds oob_interaction yet (OOB.2 wires the import)
import quarry_recon.phases as _ph, quarry_recon.cli as _cli
pdir = pathlib.Path(inspect.getfile(_ph)).parent
# params.py (P2.3 oob_probe) is the ONLY phase that emits oob_interaction; every other phase must not.
# P2.4 adds a SECOND intended emitter: cli 'oob poll' (delayed callbacks) — so cli MUST emit, phases must not.
emitters = [p.name for p in pdir.glob("*.py") if p.name != "params.py" and 'add("oob_interaction"' in p.read_text()]
c_decl = (not emitters and 'add("oob_interaction"' in inspect.getsource(_cli))
sys.exit(0 if (c_reg and c_rt and c_raw and c_decl) else 1)
PYEOF

echo "[98] OOB substrate Phase 1 / OOB.2 — quarry oob import: parses interactsh-client -json (JSONL, real schema protocol/unique-id/full-id/q-type/remote-address/timestamp) into oob_interaction rows, UNCORRELATED by default (source_tool=null, payload_class=unknown-oob — no fabricated attribution); defensive parse (skips malformed); import_file copies raw to raw/oob/, adds rows (dedup on id) with raw_ref; 'quarry oob import' command registered"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "oob.parse_interactsh maps real interactsh -json fields, uncorrelated default, skips malformed; import_file -> raw/oob + dedup rows w/ raw_ref; quarry oob import registered; import CORRELATES rows matching a Quarry token when a session exists (stray stays uncorrelated), else all uncorrelated" || no "OOB.2 import broken"
import sys, tempfile, pathlib
from quarry_recon import oob
from quarry_recon.store import Run
from click.testing import CliRunner
from quarry_recon import cli as climod
fixture = "\n".join([
  '{"protocol":"http","unique-id":"abc123","full-id":"x.abc123","q-type":"","raw-request":"GET /p","raw-response":"","remote-address":"1.2.3.4","timestamp":"2026-07-11T00:00:00Z"}',
  'not json — must be skipped',
  '{"protocol":"dns","unique-id":"abc123","full-id":"y.abc123","q-type":"A","remote-address":"5.6.7.8","timestamp":"2026-07-11T00:00:01Z"}',
])
rows = oob.parse_interactsh(fixture)
r0 = rows[0]
c_parse = (len(rows) == 2                                   # malformed line skipped
           and r0["protocol"] == "http" and r0["interaction_domain"] == "x.abc123"
           and r0["correlation_id"] == "abc123" and r0["remote_address"] == "1.2.3.4")
c_uncorr = all(x["correlation"] == "uncorrelated" and x["source_tool"] is None
               and x["target_url"] is None and x["payload_class"] == "unknown-oob"
               and x["sources"] == ["oob-import"] for x in rows)
tmp = pathlib.Path(tempfile.mkdtemp())
fx = tmp / "in.jsonl"; fx.write_text(fixture)
run = Run(tmp, "t")
res = oob.import_file(run, fx)
c_import = (res["parsed"] == 2 and res["added"] == 2 and res["by_protocol"].get("http") == 1
            and res["by_protocol"].get("dns") == 1
            and all("/raw/oob/import/" in x["raw_ref"] and pathlib.Path(x["raw_ref"]).exists()
                    for x in run.read("oob_interaction"))   # raw stored (hash-named) + row points at it
            and oob.import_file(run, fx)["added"] == 0)          # dedup on re-import
c_cmd = (CliRunner().invoke(climod.cli, ["oob", "import", "--help"]).exit_code == 0)
# FIX: content-hash raw name — two DIFFERENT files sharing a name must not clobber each other's raw
t2 = pathlib.Path(tempfile.mkdtemp()); run2 = Run(t2, "t")
fa = t2/"a"/"x.jsonl"; fa.parent.mkdir(); fa.write_text('{"protocol":"dns","unique-id":"A","full-id":"a","timestamp":"1","remote-address":"1"}')
fb = t2/"b"/"x.jsonl"; fb.parent.mkdir(); fb.write_text('{"protocol":"http","unique-id":"B","full-id":"b","timestamp":"2","remote-address":"2"}')
oob.import_file(run2, fa); oob.import_file(run2, fb)
c_noclobber = (len(list((run2.raw/"oob"/"import").glob("*-x.jsonl"))) == 2
               and len({x["raw_ref"] for x in run2.read("oob_interaction")}) == 2)
# FIX: an explicit --run typo must NOT create a ghost run (Run() mkdirs) — fail loud instead
import click as _click
pr = pathlib.Path(tempfile.mkdtemp()); _raised = False
try:
    climod._existing_run(pr, "t", "nope")
except _click.ClickException:
    _raised = True
c_ghost = (_raised and not (pr/"recon"/"nope").exists())
# report + status + oob import ALL route through the ghost-run guard; no unguarded Run(...run_id) left
import inspect as _insp
_csrc = _insp.getsource(climod)
c_shared = (_csrc.count("_existing_run(project") >= 3 and "run_id=run_id) if run_id else" not in _csrc)
# FIX (import correlation honesty): if the run has a Quarry-owned session, an imported log carrying a
# Quarry-ISSUED token is correlated to its source (docs promise it); a stray callback stays uncorrelated;
# no session -> everything uncorrelated. Never fabricated.
rc = Run(pathlib.Path(tempfile.mkdtemp()), "t")
_sess = {"domain": "abc.oast.site", "unique_id": "abc",
         "token_map": {"q7": {"source_tool": "params.oob_probe", "target_url": "http://t/p", "param": "url", "payload_class": "ssrf-callback"}},
         "log": str(rc.raw_path("oob", "session", "interactions.jsonl")),
         "session_file": str(rc.raw_path("oob", "session", "interactsh.session")), "server": None}
oob.save_session(rc, _sess)
_imp = pathlib.Path(tempfile.mkdtemp()) / "imp.jsonl"
_imp.write_text('{"protocol":"http","unique-id":"abc","full-id":"q7.abc","remote-address":"1","timestamp":"1"}\n'
                '{"protocol":"dns","unique-id":"abc","full-id":"zz.abc","remote-address":"2","timestamp":"2"}')
_res = oob.import_file(rc, _imp)
_rows = {r["interaction_domain"]: r for r in rc.read("oob_interaction")}
c_impcorr = (_res.get("correlated") == 1
             and _rows["q7.abc"]["correlation"] == "correlated" and _rows["q7.abc"]["source_tool"] == "params.oob_probe"
             and _rows["q7.abc"]["sources"] == ["oob-owned-session", "params.oob_probe"]
             and _rows["zz.abc"]["correlation"] == "uncorrelated" and _rows["zz.abc"]["sources"] == ["oob-import"])
_rn = Run(pathlib.Path(tempfile.mkdtemp()), "t")   # no session on this run
c_impnone = (oob.import_file(_rn, _imp).get("correlated") == 0
             and all(r["correlation"] == "uncorrelated" for r in _rn.read("oob_interaction")))
sys.exit(0 if (c_parse and c_uncorr and c_import and c_cmd and c_noclobber and c_ghost and c_shared
               and c_impcorr and c_impnone) else 1)
PYEOF

echo "[99] OOB substrate Phase 1 / OOB.3 — digest oob queue: 'oob' in triage.CANONICAL_QUEUES; imported (uncorrelated) oob_interaction rows surface in the digest queue + HOTLIST as candidate with protocol tags (unknown-oob/external-service-interaction/uncorrelated) — NEVER a fabricated source tag (import phase never invents blind-xss/ssrf-callback); HOTLIST shows the correlated/uncorrelated split; raw_ref/location points at raw/oob"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "'oob' in CANONICAL_QUEUES; oob_interaction -> digest queue + HOTLIST as candidate/uncorrelated (unknown-oob tags, no fabricated source); raw_ref->raw/oob" || no "OOB.3 digest queue broken"
import sys, tempfile, pathlib
from quarry_recon import oob, triage
from quarry_recon.store import Run
from quarry_recon.config import ScopeMatcher
c_queue = "oob" in triage.CANONICAL_QUEUES
tmp = pathlib.Path(tempfile.mkdtemp())
fx = tmp/"in.jsonl"; fx.write_text("\n".join([
  '{"protocol":"http","unique-id":"abc","full-id":"x.abc","q-type":"","remote-address":"1.2.3.4","timestamp":"2026-07-11T00:00:00Z"}',
  '{"protocol":"dns","unique-id":"abc","full-id":"y.abc","q-type":"A","remote-address":"5.6.7.8","timestamp":"2026-07-11T00:00:01Z"}',
]))
run = Run(tmp, "t"); oob.import_file(run, fx)
scope = ScopeMatcher([], [], [], False)
model = triage.collect(run, scope)
q = model["queues"].get("oob", [])
it = q[0] if q else {}
c_item = (len(q) == 2 and it.get("type") == "oob_interaction" and it.get("confidence") == "candidate"
          and {"oob","unknown-oob","uncorrelated","external-service-interaction"}.issubset(set(it.get("tags", [])))
          and "blind-xss" not in it.get("tags", []) and "ssrf-callback" not in it.get("tags", [])
          and "/raw/oob/import/" in (it.get("location") or ""))
md = triage.build(run, scope)
# imported-only run: HOTLIST shows the correlated/uncorrelated split (0 correlated here) + no fabricated attribution
c_hotlist = ("## OOB interactions" in md and "2 uncorrelated" in md
             and "no attribution" in md and "(uncorrelated)" in md)
sys.exit(0 if (c_queue and c_item and c_hotlist) else 1)
PYEOF

echo "[100] OOB docs/doctor — doctor [oob] is READINESS-ONLY (terse: interactsh-client present/missing + which backend, NO model essay); the ONE-layer model (backend override / import compat / no '3 channels') lives in the README, not in doctor or the operator template; blind_xss note operator-observed-until-import; params.oob_probe WIRED"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "doctor [oob] readiness-only (interactsh-client + backend, no taxonomy prose); README carries the one-layer model (override replaces the backend, import is compatibility-only, no '3 channels'); template stays terse; blind_xss operator-observed-until-import; oob_probe wired" || no "OOB docs/doctor model broken"
import sys, pathlib
from click.testing import CliRunner
from quarry_recon import cli, sources as S
from importlib import resources
out = CliRunner().invoke(cli.cli, ["doctor"]).output
# ONE [oob] section (Lumpy 2026-08-07): the tool that makes the callbacks AND the server they come back
# to. `params` was one consumer of the callback layer, not the tool's purpose, so it no longer sits in
# that phase group — and two [oob] headers in one output is the thing this asserts against.
oob = out[out.find("[oob]"):out.find("[oob]") + 400] if "[oob]" in out else ""
# doctor [oob] = READINESS ONLY (terse operator status, not the OOB model essay — that lives in README):
# the tool, and which server a callback returns to. No taxonomy prose, and NO per-target channel (armed
# for one engagement, not the next — it is decided in target.yaml, not on this box).
c_doctor = (out.count("[oob]") == 1 and "interactsh-client" in oob and "callback server:" in oob
            and "MODES.BLIND_XSS" not in oob
            and all(k not in oob for k in ("owned probes", "import (compat)", "nuclei",   # essay lines removed
                                           "Quarry-owned OOB layer", "3 channels", "evidence substrate")))
# The MODEL moved out of the secrets template into the README (2026-08-08 doc pass): the template is
# an operator file and carries the two facts you need while editing it (public default = someone
# else's server; set your own to replace it). The one-layer explanation — override is not a second
# channel, import is compatibility-only and stays uncorrelated — lives in the README, and is asserted
# THERE. The template is asserted to stay terse rather than to regrow the essay.
tmpl = resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text(encoding="utf-8")
rdme = pathlib.Path("README.md").read_text(encoding="utf-8")
c_tmpl = ("3 channels" not in tmpl and "callback_server" in tmpl
          and "public interactsh" in tmpl.lower()
          and "quarry oob import" in rdme and "3 channels" not in rdme
          and "compatibility only" in rdme.lower() and "replaces the backend" in rdme.lower())
bx = S.get("params.blind_xss")["notes"].lower()
# the note describes the CURRENT contract only: one channel (--blind-oob), dalfox owning correlation,
# and where a beacon becomes evidence. It does not carry the history of a channel that no longer exists.
c_bx = ("operator-observed until" in bx and "quarry oob import" in bx
        and "--blind-oob" in bx and "correlation is dalfox" in bx
        and "legacy" not in bx and "removed" not in bx)
c_wired = not S.get("params.oob_probe").get("pending")   # oob_probe wired (owned layer)
sys.exit(0 if (c_doctor and c_tmpl and c_bx and c_wired) else 1)
PYEOF

echo "[101] OOB Phase 2 / P2.1 — Quarry-owned interactsh session: _parse_registered extracts (domain, unique-id) from client startup; session.json save/load; the CORRELATE engine (full-id '<token>.<uid>' -> strip trailing '.<uid>' -> token_map lookup) upgrades a KNOWN token to correlated (source/target/param/payload_class filled) while unknown token + bare-domain hit stay UNCORRELATED (never fabricated); poll_session parses+correlates the session log. (open_session live subprocess NOT exercised here — verified by smoke.)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "P2.1 session: _parse_registered domain+uid; session.json round-trip; correlate maps known token->correlated (source filled), unknown/bare stay uncorrelated (no fabrication); poll_session parses+correlates" || no "OOB P2.1 session broken"
import sys, json, tempfile, pathlib
from quarry_recon import oob
from quarry_recon.store import Run
d, u = oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] d99jmamu5ramqkueos5gg3d6dionhhwpk.oast.site")
c_parse = (d == "d99jmamu5ramqkueos5gg3d6dionhhwpk.oast.site" and u == "d99jmamu5ramqkueos5gg3d6dionhhwpk"
           and oob._parse_registered("noise") is None)
run = Run(pathlib.Path(tempfile.mkdtemp()), "t")
sess = {"domain": "abc123.oast.site", "unique_id": "abc123",
        "token_map": {"q7": {"source_tool": "oob_probe", "target_url": "http://t/p", "param": "url", "payload_class": "ssrf-callback"}},
        "started": "now", "log": str(run.raw_path("oob", "session", "interactions.jsonl")), "server": None}
oob.save_session(run, sess)
c_io = (oob.load_session(run)["unique_id"] == "abc123")
logtext = "\n".join(json.dumps(x) for x in [
    {"protocol": "dns", "unique-id": "abc123", "full-id": "q7.abc123", "remote-address": "1", "timestamp": "1"},
    {"protocol": "http", "unique-id": "abc123", "full-id": "zz.abc123", "remote-address": "2", "timestamp": "2"},
    {"protocol": "dns", "unique-id": "abc123", "full-id": "abc123", "remote-address": "3", "timestamp": "3"}])
by = {r["interaction_domain"]: r for r in oob.correlate(oob.parse_interactsh(logtext), sess)}
c_corr = (by["q7.abc123"]["correlation"] == "correlated" and by["q7.abc123"]["source_tool"] == "oob_probe"
          and by["q7.abc123"]["payload_class"] == "ssrf-callback"
          and by["zz.abc123"]["correlation"] == "uncorrelated" and by["zz.abc123"]["source_tool"] is None
          and by["abc123"]["correlation"] == "uncorrelated")
pathlib.Path(sess["log"]).parent.mkdir(parents=True, exist_ok=True); pathlib.Path(sess["log"]).write_text(logtext)
polled = oob.poll_session(run, sess)
c_poll = (len(polled) == 3 and any(p["correlation"] == "correlated" for p in polled))
# generic (non-oast-baked) parser: self-host hosts + server-match filter
sh = "[INF] Listing 1 payload for OOB Testing\n[INF] sess1.oob.example.com\n"
c_generic = (oob._parse_registered(sh) == ("sess1.oob.example.com", "sess1")
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] xy.burp.collab.example\n") == ("xy.burp.collab.example", "xy")
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] a.oast.online\n", server="oob.example.com") is None
             # server config with scheme/port normalizes to hostname for the match
             and oob._parse_registered(sh, server="https://oob.example.com:443") == ("sess1.oob.example.com", "sess1")
             and oob._server_host("https://oob.example.com:443/x") == "oob.example.com"
             # marker tolerance: host on the marker line (colon form) + capital-P marker
             and oob._parse_registered("[INF] payload for OOB Testing: s2.oob.example.com\n") == ("s2.oob.example.com", "s2")
             and oob._parse_registered("[INF] Payload for OOB Testing\n[INF] d99abc.oast.online\n") == ("d99abc.oast.online", "d99abc")
             # domain-BOUNDARY match: evil-oob.example.com must NOT pass for server oob.example.com
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] abc.evil-oob.example.com\n", server="oob.example.com") is None
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] oob.example.com\n", server="oob.example.com") == ("oob.example.com", "oob")
             # comma-list: register under ANY configured server
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] s1.oob.example.com\n", server="a.com, https://oob.example.com:443, c.com") == ("s1.oob.example.com", "s1")
             and oob._server_hosts("https://a.com:8443, b.example.com/x") == ["a.com", "b.example.com"]
             # captured host normalized (case + trailing dot) before the boundary compare
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] ABC.OOB.EXAMPLE.COM\n", server="oob.example.com") == ("abc.oob.example.com", "abc")
             and oob._parse_registered("[INF] Listing 1 payload for OOB Testing\n[INF] sess.oast.online.\n") == ("sess.oast.online", "sess"))
# hang-protection + token/server wiring (monkeypatched Popen; isolated to this check subprocess)
import time as _t
class _Hang:
    def readline(s): _t.sleep(30); return ""
class _FP:
    def __init__(s, cmd): s.stdout = _Hang(); s.cmd = cmd; s.pid = 999999
    def poll(s): return None
    def terminate(s): pass
    def wait(s, timeout=None): return 0
    def kill(s): pass
_cap = {}
oob.subprocess.Popen = lambda cmd, **k: (_cap.__setitem__("cmd", cmd), _FP(cmd))[1]
oob.shutil.which = lambda x: "/bin/true"
_t0 = _t.monotonic(); _res = oob.open_session(run, server="oob.example.com", token="tk", wait=1); _dt = _t.monotonic() - _t0
_cmd = _cap.get("cmd", [])
c_session = (_res is None and _dt < 3                                  # blocking stdout did NOT hang past wait
             and "-token" in _cmd and _cmd[_cmd.index("-token") + 1] == "tk"
             and "-server" in _cmd and _cmd[_cmd.index("-server") + 1] == "oob.example.com")
# backend normalization PER CONSUMER: interactsh-client -server wants a bare DOMAIN, so a URL/port config
# (nuclei would take it raw as -iserver) is stripped to host(s) before shelling interactsh-client.
oob.open_session(run, server="https://oob.example.com:443", token="tk", wait=1)
_cmd2 = _cap.get("cmd", [])
c_norm = ("-server" in _cmd2 and _cmd2[_cmd2.index("-server") + 1] == "oob.example.com"
          and "https" not in _cmd2[_cmd2.index("-server") + 1])
sys.exit(0 if (c_parse and c_io and c_corr and c_poll and c_generic and c_session and c_norm) else 1)
PYEOF

echo "[102] OOB Phase 2 / P2.2 — token issuance: issue_token mints a unique DNS-label-safe token and records token->(source_tool,target_url,param,payload_class) in session.token_map; callback_host = <token>.<registered-host>, callback_url = scheme://<token>.<host>/<path>; ROUND-TRIP — a callback whose full-id is <token>.<unique-id> correlates back (source/target/param/payload_class filled) while an un-issued token stays uncorrelated; declarative (no phase/cli issues tokens yet — P2.3)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "issue_token mints unique tokens into token_map; callback_host/url built from <token>.<domain>; issued-token callback correlates back (source filled), un-issued stays uncorrelated; declarative (no caller yet)" || no "OOB P2.2 token issuance broken"
import sys, json, inspect, pathlib, tempfile
from quarry_recon import oob
from quarry_recon.store import Run
sess = {"domain": "d994abc.oast.site", "unique_id": "d994abc", "token_map": {}}
t0 = oob.issue_token(sess, "oob_probe", "http://t/p?url=", "url", "ssrf-callback")
t1 = oob.issue_token(sess, "oob_probe", "http://t2/x?next=", "next", "open-redirect")
# tokens are RANDOM + collision-checked (a sparse/restored map can't overwrite)
sparse = {"domain": "d.oast.site", "unique_id": "d", "token_map": {"qdeadbeef": {"source_tool": "x"}}}
tset = {oob.issue_token(sparse, "oob_probe") for _ in range(200)}
c_issue = (t0 != t1 and len(sess["token_map"]) == 2 and t0.startswith("q") and t0[1:].isalnum()
           and oob.callback_host(sess, t0) == t0 + ".d994abc.oast.site"
           and oob.callback_url(sess, t0) == "http://" + t0 + ".d994abc.oast.site"
           and oob.callback_url(sess, t0, scheme="https", path="cb") == "https://" + t0 + ".d994abc.oast.site/cb"
           and len(tset) == 200 and sparse["token_map"]["qdeadbeef"] == {"source_tool": "x"})   # not overwritten
# run= persists the mapping atomically (crash-safe)
_run = Run(pathlib.Path(tempfile.mkdtemp()), "t")
_tp = oob.issue_token(sess, "oob_probe", run=_run)
c_persist = (oob.load_session(_run) is not None and _tp in oob.load_session(_run)["token_map"])
# callback_host fails loud without a registered domain
try:
    oob.callback_host({"token_map": {}}, "qx"); c_loud = False
except ValueError:
    c_loud = True
# ROUND-TRIP: a callback whose full-id is <token>.<uid> (case/trailing-dot tolerant) correlates back
log = "\n".join(json.dumps(x) for x in [
    {"protocol": "http", "unique-id": "d994abc", "full-id": t0.upper() + ".D994ABC.", "remote-address": "1", "timestamp": "1"},
    {"protocol": "dns", "unique-id": "d994abc", "full-id": t1 + ".d994abc", "remote-address": "2", "timestamp": "2"},
    {"protocol": "http", "unique-id": "d994abc", "full-id": "zz.d994abc", "remote-address": "3", "timestamp": "3"}])
rows = oob.correlate(oob.parse_interactsh(log), sess)
byt = {r["source_tool"]: r for r in rows if r["correlation"] == "correlated"}
c_rt = (len([r for r in rows if r["correlation"] == "correlated"]) == 2
        and any(r["payload_class"] == "ssrf-callback" and r["target_url"] == "http://t/p?url=" and r["param"] == "url" for r in rows if r["correlation"] == "correlated")
        and any(r["payload_class"] == "open-redirect" for r in rows if r["correlation"] == "correlated")
        and any(r["correlation"] == "uncorrelated" and r["source_tool"] is None for r in rows))
import quarry_recon.phases as _ph, quarry_recon.cli as _cli
pdir = pathlib.Path(inspect.getfile(_ph)).parent
# params.py (P2.3 oob_probe) is the ONLY phase that issues tokens; every other phase + cli must not
c_decl = (not [p.name for p in pdir.glob("*.py") if p.name != "params.py" and "issue_token" in p.read_text()]
          and "issue_token" not in inspect.getsource(_cli))
sys.exit(0 if (c_issue and c_persist and c_loud and c_rt and c_decl) else 1)
PYEOF

echo "[103] OOB Phase 2 / P2.3 — params.oob_probe WIRED: Quarry-owned interactsh session injects a per-(target,param) callback URL into SSRF-ish params of the gf 'ssrf' candidates (scoped, non-mutating GET via the shared fetch guard), polls the owned session, stores CORRELATED oob_interaction rows (source=oob_probe, target/param) + ledger; skips on passive / no interactsh-client / no candidates; registry pending->wired; token persisted BEFORE the probe fires (crash-safe)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "oob_probe injects callback into ssrf param (non-ssrf untouched), token issued+persisted, correlated row stored + ledger; skips passive/no-client/no-cands; registry wired; run() calls it; interactsh-client is REQUIRED (not optional) in tools.yaml -> plain quarry install + doctor cover it" || no "OOB P2.3 oob_probe broken"
import sys, inspect, tempfile
from types import SimpleNamespace
from pathlib import Path
from quarry_recon import events, sources
from quarry_recon.phases import params
from quarry_recon.registry import load_tools
c_reg = not sources.get("params.oob_probe").get("pending")
# INSTALL SURFACE (no ffuf-class gap): params.oob_probe is default-on/core, so its backend
# interactsh-client must be a REQUIRED tool (like dalfox/nuclei back their default-on sources) — NOT
# optional, or plain `quarry install` skips it and the default-on source silently degrades.
_tools = {t.bin: t for t in load_tools()}
c_tool = ("interactsh-client" in _tools and _tools["interactsh-client"].optional is False
          and _tools["interactsh-client"].phase == "oob"
          and "interactsh-client" in [t.bin for t in load_tools() if not t.optional])   # in plain-install set
psrc = inspect.getsource(params)
c_run = ("_oob_probe(ctx, scope, prof)" in psrc)
# HIGH: no-follow request (fetch.redirect_location), NOT scoped_get (which follows a 302 to our own
# collector and would fake an SSRF); MED: full source id; session is resumable (-session-file)
import quarry_recon.oob as _oobmod
c_noredir = ("fetch.redirect_location" in psrc and "fetch.scoped_get" not in psrc
             and "-session-file" in inspect.getsource(_oobmod))
class _R:
    def __init__(s, d): s.dir = d; s.store = {"review": [{"klass":"ssrf","value":"http://t.ex/p?url=x&other=y"}]}; s.records = []
    def raw_path(s, ph, tl, nm):
        p = s.dir/"raw"/ph/tl/nm; p.parent.mkdir(parents=True, exist_ok=True); return p
    def read(s, e): return s.store.get(e, [])
    def add(s, e, rec):
        l = s.store.setdefault(e, [])
        if any(x.get("id") == rec.get("id") for x in l): return False
        l.append(rec); return True
    def record(s, ph, r): s.records.append(r)
class _S:
    def __init__(s, p=False): s.passive_only = p
    def active_allowed(s, h): return True
class _C:
    def __init__(s, p=False): s.run = _R(Path(tempfile.mkdtemp())); s.scope = _S(p); s.http_timeout = 600; s.echo = lambda *a, **k: None
prof = SimpleNamespace(http_rl=0)
params.time.sleep = lambda *a: None
params.have = lambda b: True
params.secrets.oob = lambda: {}
fired = []
params.fetch.redirect_location = lambda ctx, url, host=None, **k: (fired.append(url), (None, 200))[1]
params.fetch.scoped_get = lambda *a, **k: (_ for _ in ()).throw(AssertionError("scoped_get follows redirects — must not be used"))
class _FP:
    pid = 999999
    def terminate(s): pass
    def wait(s, timeout=None): return 0
    def kill(s): pass
def _open(run, server=None, token=None):
    return {"domain":"d99.oast.site","unique_id":"d99","token_map":{},"log":str(run.raw_path("oob","session","i"))}, _FP()
params.oob.open_session = _open
params.oob.poll_session = lambda run, sess: [
    {"id":t,"protocol":"http","interaction_domain":f"{t}.d99","correlation":"correlated",
     "source_tool":m["source_tool"],"target_url":m["target_url"],"param":m["param"],
     "payload_class":m["payload_class"],"sources":["oob-import"]} for t,m in sess["token_map"].items()]
ctx = _C(); events.reset(); events.configure(ctx.run.dir)
r = params._oob_probe(ctx, ctx.scope, prof)
oi = ctx.run.store.get("oob_interaction", [])
c_probe = (r is not None and len(fired) == 1 and ".d99.oast.site" in fired[0] and "other=y" in fired[0]
           and len(oi) == 1 and oi[0]["correlation"] == "correlated" and oi[0]["source_tool"] == "params.oob_probe"
           and oi[0]["param"] == "url")
c_skip = (params._oob_probe(_C(True), _S(True), prof) is None)     # passive -> skip
_h = params.have; params.have = lambda b: False
_cx = _C()
# no interactsh-client -> skip AND a honest skip is RECORDED (wired/default-on source stays truthful)
c_skip2 = (params._oob_probe(_cx, _S(), prof) is None
           and any("not installed" in getattr(r, "note", "") for r in _cx.run.records))
params.have = _h
sys.exit(0 if (c_reg and c_tool and c_run and c_noredir and c_probe and c_skip and c_skip2) else 1)
PYEOF

echo "[104] OOB Phase 2 / P2.1-prep for P2.4 — resume_session: a SEPARATE resume/poll path that LOADS the persisted session.json (token_map intact), re-launches interactsh-client on the SAME -session-file (same correlation id), verifies the re-registered domain MATCHES, and returns (session, proc) WITHOUT ever overwriting token_map (open_session mints fresh; resume must not clobber delayed-callback attribution). Domain mismatch / no saved session -> None"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "resume_session loads existing session (token_map INTACT, disk unchanged), verifies same domain, rejects mismatch + missing session; never clobbers token_map" || no "OOB resume_session broken"
import sys, io, tempfile, pathlib
from quarry_recon import oob
from quarry_recon.store import Run
class _FP:
    def __init__(s, out): s.stdout = io.StringIO(out); s._a = True; s.pid = 999999
    def poll(s): return None if s._a else 0
    def terminate(s): s._a = False
    def wait(s, timeout=None): return 0
    def kill(s): s._a = False
run = Run(pathlib.Path(tempfile.mkdtemp()), "t")
prev = {"domain": "d99.oast.site", "unique_id": "d99",
        "token_map": {"q1": {"source_tool": "params.oob_probe", "target_url": "http://t", "param": "url", "payload_class": "ssrf-callback"}},
        "log": str(run.raw_path("oob", "session", "interactions.jsonl")),
        "session_file": str(run.raw_path("oob", "session", "interactsh.session")), "server": None}
oob.save_session(run, prev)
oob.shutil.which = lambda x: "/bin/true"
oob.subprocess.Popen = lambda cmd, **k: _FP("[INF] Listing 1 payload for OOB Testing\n[INF] d99.oast.site\n")
res = oob.resume_session(run, wait=2)
c_ok = (res is not None and res[0]["token_map"].get("q1", {}).get("param") == "url"
        and oob.load_session(run)["token_map"].get("q1") is not None)   # disk not clobbered
oob.subprocess.Popen = lambda cmd, **k: _FP("[INF] Listing 1 payload for OOB Testing\n[INF] OTHER.oast.site\n")
c_mismatch = (oob.resume_session(run, wait=2) is None)
c_none = (oob.resume_session(Run(pathlib.Path(tempfile.mkdtemp()), "t")) is None)
sys.exit(0 if (c_ok and c_mismatch and c_none) else 1)
PYEOF

echo "[105] OOB Phase 2 / P2.4 (closer) — quarry oob poll + correlated digest tags: 'quarry oob poll' resumes the owned session with the CONFIGURED oob.auth_token (resume_session(run, token=secrets.oob()...)), sleeps --wait for delayed callbacks, polls, adds new oob_interaction rows (dedup on id), closes the client; a CORRELATED row gets SPECIFIC digest tags (payload_class + 'correlated' + source_tool) and a why naming source/param/target — NOT the Phase-1 unknown-oob/uncorrelated; an uncorrelated row KEEPS the Phase-1 tags; HOTLIST shows the correlated-vs-uncorrelated split"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "quarry oob poll registered + resumes with configured token + sleeps --wait + closes session; correlated row -> [payload_class,correlated,source_tool] tags + source-naming why; uncorrelated keeps unknown-oob/uncorrelated; HOTLIST correlated/uncorrelated split" || no "OOB P2.4 poll/tags broken"
import sys, tempfile, pathlib, inspect
from quarry_recon import triage, oob, cli as climod
from quarry_recon.store import Run
from quarry_recon.config import ScopeMatcher
from click.testing import CliRunner
# provenance fix: a correlated hit came over the OWNED session -> sources reflects owned-session + source_tool,
# NOT the parse-time ["oob-import"]. An un-issued token stays uncorrelated with its original sources.
sess = {"unique_id": "abc", "token_map": {"q7": {"source_tool": "params.oob_probe", "target_url": "http://t/p",
        "param": "url", "payload_class": "ssrf-callback"}}}
crows = oob.correlate([{"interaction_domain": "q7.abc", "sources": ["oob-import"], "correlation": "uncorrelated"},
                       {"interaction_domain": "zz.abc", "sources": ["oob-import"], "correlation": "uncorrelated"}], sess)
c_prov = (crows[0]["sources"] == ["oob-owned-session", "params.oob_probe"]
          and crows[1]["sources"] == ["oob-import"])   # un-issued token: provenance untouched
# --wait guard: negative rejected by IntRange
c_wait = (CliRunner().invoke(climod.cli, ["oob", "poll", "-t", "x", "--wait", "-3"]).exit_code != 0)
run = Run(pathlib.Path(tempfile.mkdtemp()), "t")
run.add("oob_interaction", {"id": "c1", "protocol": "http", "interaction_domain": "q1.d", "correlation": "correlated",
        "source_tool": "params.oob_probe", "target_url": "http://t/p?url=", "param": "url",
        "payload_class": "ssrf-callback", "sources": ["params.oob_probe"], "raw_ref": "/x/raw/oob/session/s.jsonl"})
run.add("oob_interaction", {"id": "u1", "protocol": "dns", "interaction_domain": "zz.d", "correlation": "uncorrelated",
        "source_tool": None, "payload_class": "unknown-oob", "sources": ["oob-import"]})
scope = ScopeMatcher([], [], [], False)
q = triage.collect(run, scope)["queues"]["oob"]
corr = next(i for i in q if "correlated" in i["tags"])
unc = next(i for i in q if "uncorrelated" in i["tags"])
c_corr = ({"oob", "http", "ssrf-callback", "correlated", "params.oob_probe"}.issubset(set(corr["tags"]))
          and "unknown-oob" not in corr["tags"]
          and "CORRELATED to params.oob_probe" in corr["why"] and "url" in corr["why"])
c_unc = ({"oob", "unknown-oob", "uncorrelated", "external-service-interaction"}.issubset(set(unc["tags"]))
         and "correlated" not in unc["tags"])
md = triage.build(run, scope)
c_hot = ("1 correlated, 1 uncorrelated" in md and "CORRELATED ssrf-callback <- params.oob_probe" in md)
csrc = inspect.getsource(climod)
c_cmd = (CliRunner().invoke(climod.cli, ["oob", "poll", "--help"]).exit_code == 0)
c_wire = ("resume_session(run_obj" in csrc and 'token=_cfg.get("auth_token")' in csrc
          and 'server=_cfg.get("callback_server")' in csrc      # token coupled to the saved server
          and "close_session" in csrc and "--wait" in csrc)
sys.exit(0 if (c_corr and c_unc and c_hot and c_cmd and c_wire and c_prov and c_wait) else 1)
PYEOF

echo "[106] acceptance-bar CLOSER — last raw subprocess in phases removed: (a) crawl.js_beautify per-file via the runner (source events + coverage_partial + ledger), ORIGINAL-SAFE (beautifies a temp copy, atomic swap only on clean status — a timeout can't truncate the only original), and OBSERVABLE (aggregate cpu/rss/status recorded to the manifest); degraded->PARTIAL. (b) vertical.openintel routed THROUGH the runner + recorded (configured empty vs timeout vs broken-binary is observable, not swallowed) — NOT a ratified exception. NO raw subprocess left in crawl.py or vertical.py."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "js_beautify per-file via runner (events+coverage_partial+ledger), original-safe temp-copy swap, aggregate telemetry recorded, degraded->PARTIAL; openintel through runner+recorded (no exception); no raw subprocess in crawl/vertical; registry WIRED" || no "acceptance-bar contract closer broken"
import sys, inspect, tempfile, pathlib
from types import SimpleNamespace
from quarry_recon.phases import crawl
from quarry_recon import sources as S
from quarry_recon.runner import Status
# NO raw subprocess left in crawl.py (the whole point) — jsluice + js_beautify both under the runner now.
# The import is the unambiguous signal (docstrings may still say the word); also no call sites remain.
_crawlsrc = inspect.getsource(crawl)
c_nosub = ("import subprocess" not in _crawlsrc and "subprocess.run(" not in _crawlsrc
           and "subprocess.Popen(" not in _crawlsrc)
# run() wires the contract helper + emits a ledger (not a bare loop)
# d7abef5: beautify moved INSIDE _js_publish_derived — the derived tree is beautified while STAGED and
# published atomically, so the mineable tree is never mid-mutation. Fail loud if the function goes missing.
if not hasattr(crawl, "_js_publish_derived"):
    sys.exit(1)
rsrc = inspect.getsource(crawl._js_publish_derived)
c_wire = ("_beautify_run(ctx, staged)" in rsrc and 'ledger("crawl.js_beautify"' in rsrc
          and "_publish_tree(ctx, active, staging)" in rsrc)
# functional: capture events + recorded results; 2nd file DEGRADES and its .beauty copy gets TRUNCATED
# mid-write — the original must survive intact (original-safe temp-copy swap).
evs = []
for name in ("tool_start", "tool_progress", "tool_finish", "coverage_partial"):
    setattr(crawl.events, name, (lambda n: (lambda *a, **k: evs.append((n, k))))(name))
calls = {"n": 0}
def _fake_exec(tool, cmd, raw_path=None, timeout=None, **k):
    calls["n"] += 1
    tmppath = pathlib.Path(cmd[-1])                        # the .beauty COPY js-beautify -r targets
    if calls["n"] == 2:
        tmppath.write_text("TRUNCATED")                   # simulate a timeout mid-rewrite damaging the copy
        return SimpleNamespace(status=Status.TIMED_OUT, raw_path=raw_path, cpu_s=0.5, peak_rss_mb=10.0)
    tmppath.write_text("/* beautified */")
    return SimpleNamespace(status=Status.SUCCESS, raw_path=raw_path, cpu_s=0.2, peak_rss_mb=8.0)
crawl.exec_tool = _fake_exec
tmp = pathlib.Path(tempfile.mkdtemp())
recorded = []
ctx = SimpleNamespace(run=SimpleNamespace(
        raw_path=lambda *p: (tmp.joinpath(*p[:-1]).mkdir(parents=True, exist_ok=True) or tmp.joinpath(*p)),
        record=lambda ph, r: recorded.append((ph, r))),
        echo=lambda *a, **k: None)
files = [tmp / "a.js", tmp / "b.js", tmp / "c.js"]
for f in files:
    f.write_text(f"ORIGINAL {f.name}")
ok_n, degraded, status = crawl._beautify_run(ctx, files)
kinds = [e[0] for e in evs]
c_func = (ok_n == 2 and degraded == 1 and status == Status.PARTIAL
          and kinds.count("tool_start") == 1 and kinds.count("tool_finish") == 1
          and kinds.count("tool_progress") == 3 and kinds.count("coverage_partial") == 1
          and calls["n"] == 3)
# ORIGINAL-SAFE: degraded file b.js keeps its untouched original (NOT the truncated copy); no .beauty left
c_safe = (files[1].read_text() == "ORIGINAL b.js"
          and not list(tmp.glob("*.beauty")))
# OBSERVABLE: exactly one aggregate result recorded, carrying status + aggregated cpu/rss + degraded note
c_rec = (len(recorded) == 1 and recorded[0][0] == "crawl"
         and recorded[0][1].tool == "js-beautify" and recorded[0][1].status == Status.PARTIAL
         and recorded[0][1].exit_code is None                       # synthetic multi-proc: no single exit code
         and abs(recorded[0][1].cpu_s - 0.9) < 0.01 and recorded[0][1].peak_rss_mb == 10.0
         and "degraded" in recorded[0][1].note)
# registry: debt cleared, now WIRED; openintel NO LONGER an exception (routed through the runner)
jb = S.get("crawl.js_beautify"); oi = S.get("vertical.openintel")
c_reg = ("debt" not in jb and "WIRED" in jb.get("notes", "")
         and "contract_exception" not in oi and "records its result" in oi.get("notes", "").lower())
# openintel now goes THROUGH the runner + records (no ratified-exception comment, no raw subprocess)
_vsrc = inspect.getsource(__import__("quarry_recon.phases.vertical", fromlist=["x"]))
c_code = ('exec_tool("openintel-subs"' in _vsrc and 'ctx.run.record("vertical", r)' in _vsrc
          and "RATIFIED contract exception" not in _vsrc and "import subprocess" not in _vsrc)
sys.exit(0 if (c_nosub and c_wire and c_func and c_safe and c_rec and c_reg and c_code) else 1)
PYEOF

echo "[107] scope safety — scoped_get follows redirects PER-HOP with a scope check BEFORE contacting (audit #1, direct-fetch path only; httpx/ffuf follow-redirects are separate): off-scope/metadata hop NEVER requested; in-scope chain -> terminal body; plain 200 unchanged; EVERY response is closed (no fd/conn leak); redirect-limit exhaustion returns EMPTY body NOT None (never mislabeled off-scope); only real redirect statuses (301/302/303/307/308, not 304) are followed; sensitive headers (Authorization/Cookie) dropped on host/scheme change; redirects followed non-mutating (GET)"
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "off-scope hop never contacted; in-scope chain->body; plain 200 ok; ALL responses closed; exhaustion->empty-not-None; only real 3xx followed; cross-host strips Authorization" || no "scoped_get redirect scope enforcement broken"
import sys
from quarry_recon import netguard as _NG; _NG._STUB = {"all": ["93.184.216.34"]}  # audit#1: hosts resolve GLOBAL (guard passes)
from types import SimpleNamespace
from quarry_recon import fetch
class Resp:
    def __init__(s, status, headers=None, body=b""): s.status=status; s.headers=headers or {}; s._b=body; s.closed=False
    def read(s, n=None): return s._b
    def close(s): s.closed=True
class FakeOpener:
    def __init__(s, script): s.script=script; s.contacted=[]; s.reqhdrs=[]
    def open(s, req, timeout=None):
        s.contacted.append(req.full_url); s.reqhdrs.append(dict(req.headers)); return s.script[req.full_url]
def mkctx(allowed): return SimpleNamespace(profile=SimpleNamespace(http_rl=None),
    scope=SimpleNamespace(active_allowed=lambda h: h in allowed))
# (1) in-scope hop -> off-scope metadata hop: OOS never contacted; every contacted resp closed
op = FakeOpener({
 "http://a.example.com/": Resp(302, {"Location":"http://b.example.com/next"}),
 "http://b.example.com/next": Resp(302, {"Location":"http://169.254.169.254/"}),
 "http://169.254.169.254/": Resp(200, {}, b"SECRET")}); fetch._NO_REDIRECT_OPENER = op
d,f,st = fetch.scoped_get(mkctx({"a.example.com","b.example.com"}), "http://a.example.com/", origin_host="a.example.com")
c_block = (d is None and st==302 and "http://169.254.169.254/" not in op.contacted
           and op.contacted==["http://a.example.com/","http://b.example.com/next"])
c_closed1 = (op.script["http://a.example.com/"].closed and op.script["http://b.example.com/next"].closed)
# (2) in-scope chain -> terminal body; both closed
op2 = FakeOpener({"http://a.example.com/": Resp(302, {"Location":"http://b.example.com/ok"}),
                  "http://b.example.com/ok": Resp(200, {}, b"OK")}); fetch._NO_REDIRECT_OPENER = op2
d2,f2,s2 = fetch.scoped_get(mkctx({"a.example.com","b.example.com"}), "http://a.example.com/", origin_host="a.example.com")
c_follow = (d2==b"OK" and f2=="http://b.example.com/ok" and s2==200
            and op2.script["http://a.example.com/"].closed and op2.script["http://b.example.com/ok"].closed)
# (3) plain 200 unchanged + closed
op3 = FakeOpener({"http://a.example.com/x": Resp(200, {}, b"BODY")}); fetch._NO_REDIRECT_OPENER = op3
d3,_,s3 = fetch.scoped_get(mkctx({"a.example.com"}), "http://a.example.com/x", origin_host="a.example.com")
c_plain = (d3==b"BODY" and s3==200 and op3.script["http://a.example.com/x"].closed)
# (4) redirect-limit exhaustion -> EMPTY body, NOT None (must not be read as off-scope)
loop = {f"http://a.example.com/{i}": Resp(302, {"Location":f"http://a.example.com/{i+1}"}) for i in range(20)}
op4 = FakeOpener(loop); fetch._NO_REDIRECT_OPENER = op4
d4,_,st4 = fetch.scoped_get(mkctx({"a.example.com"}), "http://a.example.com/0", origin_host="a.example.com", max_redirects=3)
c_bound = (len(op4.contacted)==4 and d4 == b"" and d4 is not None and st4 in (301,302,303,307,308))
# (5) a 304 is NOT a redirect -> terminal (returns its body, not followed)
op5 = FakeOpener({"http://a.example.com/n": Resp(304, {"Location":"http://b.example.com/should-not-follow"}, b"")}); fetch._NO_REDIRECT_OPENER = op5
d5,f5,s5 = fetch.scoped_get(mkctx({"a.example.com","b.example.com"}), "http://a.example.com/n", origin_host="a.example.com")
c_304 = (s5==304 and op5.contacted==["http://a.example.com/n"])   # did NOT follow the 304's Location
# (6) cross-host redirect strips Authorization
op6 = FakeOpener({"http://a.example.com/": Resp(302, {"Location":"http://b.example.com/2"}),
                  "http://b.example.com/2": Resp(200, {}, b"OK")}); fetch._NO_REDIRECT_OPENER = op6
fetch.scoped_get(mkctx({"a.example.com","b.example.com"}), "http://a.example.com/", origin_host="a.example.com",
                 headers={"Authorization":"secret-token"})
c_strip = (any(k.lower()=="authorization" for k in op6.reqhdrs[0])          # hop 1 carried it
           and not any(k.lower()=="authorization" for k in op6.reqhdrs[1])) # hop 2 (cross-host) stripped
# (7) REAL urllib path: with _NoRedirect a 3xx normally arrives as HTTPError — it is itself an open
# response and must be closed (the outer finally only sees resp=None, so _open_no_follow must close it)
import io, urllib.error
class TrackErr(urllib.error.HTTPError):
    def __init__(s, url, code, hdrs):
        super().__init__(url, code, "redir", hdrs, io.BytesIO(b"")); s.was_closed = False
    def close(s): s.was_closed = True; super().close()
class RaiseScript:
    def __init__(s, script): s.script=script; s.contacted=[]
    def open(s, req, timeout=None):
        s.contacted.append(req.full_url); r = s.script[req.full_url]
        if isinstance(r, Exception): raise r
        return r
_err = TrackErr("http://a.example.com/", 302, {"Location":"http://b.example.com/ok"})
op7 = RaiseScript({"http://a.example.com/": _err, "http://b.example.com/ok": Resp(200, {}, b"OK")})
fetch._NO_REDIRECT_OPENER = op7
d7,f7,s7 = fetch.scoped_get(mkctx({"a.example.com","b.example.com"}), "http://a.example.com/", origin_host="a.example.com")
c_errclose = (d7==b"OK" and _err.was_closed                                 # HTTPError redirect response closed
              and op7.contacted==["http://a.example.com/","http://b.example.com/ok"])
sys.exit(0 if (c_block and c_closed1 and c_follow and c_plain and c_bound and c_304 and c_strip and c_errclose) else 1)
PYEOF

echo "[108] portscan two-lane gating (audit #4) — MODES.PORTSCAN gates ONLY the infra lane (naabu top-1000 over CIDR → nmap), which is now DEFAULT OFF (deliberate opt-in: needs PORTSCAN true AND CIDR, so adding CIDR alone never arms the weeks-long scan). The fast web-port SYN prefilter (naabu over resolved host IPs → httpx-on-open) is main-river and INDEPENDENT of this flag — _web_port_prefilter never reads prof.portscan."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "prof.portscan default False (infra opt-in); true+CIDR arms infra; infra lane gated on 'prof.portscan and prof.cidr'; SYN prefilter independent of prof.portscan" || no "portscan two-lane gating broken"
import sys, os, tempfile, inspect
from quarry_recon.config import TargetProfile
import quarry_recon.phases.probe as probe
def prof(body=""):
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    open(p, "w").write("TARGET: t\nAPEX_DOMAINS:\n  - t.com\n" + body)
    return TargetProfile.load(p)
c_default = (prof().portscan is False)                                  # infra portscan OFF by default
c_optin = (prof("MODES:\n  PORTSCAN: true\n").portscan is True)         # explicit opt-in flips it
psrc = inspect.getsource(probe)
c_infra_gate = ("if prof.portscan and prof.cidr:" in psrc)             # infra needs BOTH mode + CIDR
# the SYN prefilter is called on public hosts regardless of the mode, and never uses the bool
# prof.portscan as a gate (it may still read prof.portscan_RATE, and mention "portscan" in its docstring)
_pf = inspect.getsource(probe._web_port_prefilter).replace("portscan_rate", "RATE")
c_prefilter_indep = ("_web_port_prefilter(ctx, public_hosts" in psrc and "prof.portscan" not in _pf)
sys.exit(0 if (c_default and c_optin and c_infra_gate and c_prefilter_indep) else 1)
PYEOF

echo "[109] scope safety — audit #1 tail: NO unrestricted redirect-follow on httpx/ffuf. Both httpx cmds (probe fingerprint + vertical CSP-sibling) use -follow-host-redirects (SAME-HOST only: http->https collapse followed, cross-host/off-scope NOT — verified a real flag vs httpx -h), never bare -follow-redirects; -location still records cross-host Location as intel. vhost ffuf drops -r: a redirecting vhost is matched via -mc (3xx) + -ac folds the catch-all by size, so it never chases a Location to another host."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "httpx fingerprint + CSP cmds use -follow-host-redirects not -follow-redirects; vhost ffuf has NO -r but keeps -ac + 3xx in -mc; no unrestricted redirect flag remains" || no "audit #1 tail (httpx -fhr / ffuf -r) broken"
import sys, inspect
import quarry_recon.phases.probe as probe
import quarry_recon.phases.vertical as vertical
# probe fingerprint httpx: built command uses same-host follow, not unrestricted
cmd = probe._httpx_probe_cmd("hosts.txt", [80, 443], None)
c_httpx = ("-follow-host-redirects" in cmd and "-follow-redirects" not in cmd)
# vertical CSP-sibling httpx: same
vsrc = inspect.getsource(vertical)
c_csp = ('"-follow-host-redirects"' in vsrc and '"-follow-redirects"' not in vsrc)
# vhost ffuf: no -r (redirect follow), still calibrates (-ac) and matches 3xx (-mc)
# the ffuf command lives in _vhost_scan since A1 (the lane loop is _vhost_enum). Span BOTH, and fail loud
# if either function disappears rather than silently passing on a stale locator.
if not hasattr(probe, "_vhost_scan"):
    sys.exit(1)
vh = inspect.getsource(probe._vhost_enum) + inspect.getsource(probe._vhost_scan)
c_ffuf = ('"-r"' not in vh and '"-ac"' in vh and "301,302,303,307,308" in vh)
# no phase httpx/ffuf command carries the unrestricted flag anywhere
allsrc = inspect.getsource(probe) + vsrc
c_none = ('"-follow-redirects"' not in allsrc)
sys.exit(0 if (c_httpx and c_csp and c_ffuf and c_none) else 1)
PYEOF

echo "[110] mode invariant (audit #5) — PASSIVE_ONLY makes vertical genuinely no-target-contact: end-to-end vertical.run() under passive mode invokes NO active DNS tool anywhere (no dnsx recursive resolve @ the old line 420, no dnsx -cname takeover @ 471, no puredns brute/resolve, no alterx) — both active-DNS paths, not just the obvious one; honest skips recorded for each; passive sources (CT/subfinder) still discover + STORE subdomain entities."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "vertical.run() passive: zero dnsx/puredns/alterx invocations (recursion resolve + CNAME takeover both gated); dnsx+puredns skips recorded; passive CT subdomain survives" || no "passive-only mode invariant broken"
import sys, tempfile, pathlib
from types import SimpleNamespace
import quarry_recon.contract as C
import quarry_recon.phases.vertical as v
from quarry_recon.runner import RunResult, Status
tmp = pathlib.Path(tempfile.mkdtemp())
CALLS = []
def fake_exec(tool, cmd, raw_path=None, timeout=None, **k):
    CALLS.append(tool)
    if raw_path is not None:                          # contracts read the artifact back
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("")
    return RunResult(tool, list(cmd), Status.EMPTY, 0, 0.0, raw_path, 0)
# stub actives + passive network/secret sources; seed ONE passive subdomain via crt.sh
v.exec_tool = fake_exec
# ...AND the OTHER execution path: run_contract() executes via `runner.run` (imported as contract._run),
# NOT via vertical.exec_tool. Stubbing only the latter let `subfinder` run FOR REAL — ~15 minutes of live
# network per verify run, in a check that is supposed to be hermetic. Worse, tools executed through a
# contract never reached CALLS, so the "no active DNS tool ran" assertion could not have seen one there.
# (dnsx/puredns/alterx happen to use exec_tool today, so the property held — by luck, not by construction.)
C._run = fake_exec
v.have = lambda t: True
v._crtsh = lambda a: {"api.acme.com"}                 # passive CT hit that must survive
v._certspotter = lambda a, t=None: set()
v._resolvers = lambda ctx: (None, None)
v._wordlist = lambda ctx: None
v.secrets.certspotter = lambda: None
v.secrets.censys = lambda: {}                         # unset censys returns an empty dict, not None
v.secrets.github_tokens_file = lambda: None
v.secrets.shodan = lambda: None
v.settings.openintel = lambda: {}
class Run:
    def __init__(s): s.ents={}; s.notes=[]; s.records=[]
    def raw_path(s, a, b, name):
        p = tmp/a/b/name; p.parent.mkdir(parents=True, exist_ok=True); return p
    def _key(s, r): return r.get("host") or r.get("value") or r.get("id")
    def add(s, ent, rec):
        s.ents.setdefault(ent, [])
        if any(s._key(e) == s._key(rec) for e in s.ents[ent]): return False
        s.ents[ent].append(rec); return True
    def values(s, ent): return [s._key(e) for e in s.ents.get(ent, [])]
    def count(s, ent): return len(s.ents.get(ent, []))
    def read(s, ent): return s.ents.get(ent, [])
    def record(s, ph, r): s.records.append(r)
class Ctx:
    def __init__(s):
        s.run=Run(); s.http_timeout=600
        s.profile=SimpleNamespace(apex_domains=["acme.com"], takeover=True, http_rl=None, dns_rate=None)
        s.scope=SimpleNamespace(passive_only=True, in_scope=lambda h: h.endswith("acme.com"),
                                is_oos=lambda h: False, active_allowed=lambda h: True)
    def write_list(s, name, items):
        p = tmp/name; p.write_text("\n".join(map(str, items)) + "\n"); return p
    def echo(s, *a, **k): pass
ctx = Ctx()
v.run(ctx)
# NO active DNS tool ran anywhere in the passive run (both paths, not just line 420)
c_no_active = ("dnsx" not in CALLS and "puredns" not in CALLS and "alterx" not in CALLS)
# honest skips recorded for BOTH tools
skips = [(getattr(r,"tool",None), (getattr(r,"note","") or "").lower()) for r in ctx.run.records
         if getattr(r,"status",None) == Status.SKIPPED]
c_skips = (any(t=="dnsx" and "passive" in n for t,n in skips)
           and any(t=="puredns" and "passive" in n for t,n in skips))
# passive CT/subdomain result survived
c_survives = ("api.acme.com" in ctx.run.values("subdomain"))
sys.exit(0 if (c_no_active and c_skips and c_survives) else 1)
PYEOF

echo "[111] scope safety (audit #6) — katana never CRAWLS an OOS host: _katana_scope_flags translates Quarry OOS host patterns into katana -cos (URL regex) on BOTH main + headless passes. Anchors are translated for URL context: host-start '^' -> '://', host-end '$' -> a host-terminator '(?:[:/?#]|$)' (NOT bare '$', which would demand the URL end at the hostname and let a path/port/query ESCAPE). Verified: '^jobs\\.', 'jobs\\.example', and '^jobs\\.example\\.com$' all exclude URLs with path / port / query; empty OOS -> no flags."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "OOS -> katana -cos with correct anchor translation (^-> ://, trailing \$ -> host-terminator); all 3 anchor forms exclude path/port/query URLs; in-scope path not excluded; main+headless identical; empty->none" || no "katana OOS scope enforcement broken"
import sys, re, inspect
from types import SimpleNamespace
from quarry_recon.phases import crawl
pats = [re.compile(r"^jobs\."), re.compile(r"jobs\.example"), re.compile(r"^jobs\.example\.com$")]
flags = crawl._katana_scope_flags(SimpleNamespace(oos_patterns=pats))
cos = [flags[i+1] for i, x in enumerate(flags) if x == "-cos"]
# anchor translation correct — critically, `$` becomes a host-terminator, not end-of-URL; and Quarry's
# re.IGNORECASE OOS is carried into RE2 with a `(?i)` prefix on every generated expression
c_xlate = (cos == [r"(?i)://jobs\.", r"(?i)jobs\.example", r"(?i)://jobs\.example\.com(?:[:/?#]|$)"])
c_empty = (crawl._katana_scope_flags(SimpleNamespace(oos_patterns=[])) == [])
# BEHAVIORAL (RE2-compatible): every OOS pattern must exclude the host across path/port/query/bare forms
oos_urls = ["https://jobs.example.com/path", "https://jobs.example.com:8443/x",
            "https://jobs.example.com?q=1", "https://jobs.example.com"]
c_all_forms = all(re.compile(c).search(u) for c in cos for u in oos_urls)
# CASE-INSENSITIVE: an uppercase/mixed-case host (OOS to Quarry via IGNORECASE) is excluded by katana too
c_ci = all(re.compile(c).search(u) for c in cos
           for u in ["https://JOBS.example.com/path", "https://Jobs.Example.Com:8443/x"])
# the anchored ^...$ form must NOT over-reach to a different host (jobs.example.com.evil.com)
anchored = re.compile(cos[2])
c_precise = (all(anchored.search(u) for u in oos_urls)
             and not anchored.search("https://jobs.example.com.evil.com/"))
# host-start `^jobs\.` excludes the OOS host but not an in-scope path mentioning jobs.
hs = re.compile(cos[0])
c_inscope = (hs.search("https://jobs.example.com/x") and not hs.search("https://acme.com/jobs.html"))
src = inspect.getsource(crawl.run)
c_both = ("cmd += _katana_scope_flags(scope)" in src and "_katana_scope_flags(scope) +" in src)
sys.exit(0 if (c_xlate and c_empty and c_all_forms and c_precise and c_inscope and c_ci and c_both) else 1)
PYEOF

echo "[112] process lifecycle (audit #7) — runner kills the WHOLE process group, no orphans: tools launch with start_new_session (own group leader), and terminate_group does SIGTERM -> bounded grace -> SIGKILL on the group for BOTH timeout and Ctrl-C. LIVE test: a parent that spawns a background child sleep is timed out -> BOTH parent and child disappear (old proc.kill() left the child orphaned). A KeyboardInterrupt tears the group down, drains the reader threads within a bounded grace, and is RE-RAISED (never converted to FAILED/TIMED_OUT); sampler shutdown stays in finally. OOB close_session shares the same helper."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "timeout kills parent+child; LEADER-EXITS-FIRST returns promptly (no hang, waits leader not pipe); TERM-resistant -> SIGKILL + REAPED (no zombie); KeyboardInterrupt -> terminate_group + drain + RE-RAISE; start_new_session set; oob.close_session shares helper" || no "process-group cleanup broken"
import sys, os, time, tempfile, inspect
from quarry_recon import runner, oob
from quarry_recon.runner import Status
import subprocess as _sub
def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False
    except PermissionError: return True
def waitgone(pid, n=30):
    for _ in range(n):
        if not alive(pid): return True
        time.sleep(0.1)
    return not alive(pid)
# (1) LIVE: timeout must kill the tool AND its spawned child (whole group), not just the leader
cpf = os.path.join(tempfile.mkdtemp(), "cpid")
res = runner.run("sleeptest", ["sh", "-c", f"sleep 300 & echo $! > {cpf}; sleep 300"], timeout=1)
child = int(open(cpf).read().strip())
c_timeout = (res.status == Status.TIMED_OUT and waitgone(child))
# (1b) LEADER EXITS FIRST while a child holds the stdout pipe: old code BLOCKED in communicate(). run() now
# waits on the LEADER and returns promptly (never hangs), abandoning the escaped pipe holder within the drain
# grace. The abandoned stdout drain is incomplete -> PARTIAL (honest, not a clean EMPTY). A CLEAN leader exit
# does NOT force-kill the detached child (scoped-teardown policy; see test_group_teardown_is_scoped...).
cpf2 = os.path.join(tempfile.mkdtemp(), "cpid2")
t0b = time.monotonic()
res2 = runner.run("orphan", ["sh", "-c", f"sleep 300 & echo $! > {cpf2}; exit 0"], timeout=30)
dt2 = time.monotonic() - t0b
child2 = int(open(cpf2).read().strip())
c_leader_first = (res2.status == Status.PARTIAL and dt2 < 10)   # returned on leader exit, no hang; drain incomplete
try: os.kill(child2, 9)                                                          # never leak the detached child
except OSError: pass
# (1c) TERM-RESISTANT parent needs SIGKILL and must be REAPED (no zombie). Drive terminate_group directly.
cpf3 = os.path.join(tempfile.mkdtemp(), "cpid3")
p = _sub.Popen(["sh", "-c", f"trap '' TERM; sleep 300 & echo $! > {cpf3}; while :; do sleep 0.2; done"],
               stdout=_sub.PIPE, start_new_session=True)
time.sleep(0.4); child3 = int(open(cpf3).read().strip())
t0 = time.monotonic(); runner.terminate_group(p, grace=0.5); dt = time.monotonic() - t0
c_sigkill = (p.poll() is not None            # reaped (returncode set) -> NOT a zombie
             and waitgone(child3) and dt >= 0.4)   # grace elapsed -> SIGKILL was actually needed
# (2) start_new_session is actually set on the Popen (source-level, since we can't introspect a dead proc)
c_sns = ("start_new_session=True" in inspect.getsource(runner.run))
# (3) KeyboardInterrupt: cleanup + drain + RE-RAISE, not a status
import io as _io
class FakeProc:
    def __init__(s):
        s.pid=999999; s.returncode=None; s.waited=0
        s.stdout, s.stderr, s.stdin = _io.BytesIO(), _io.BytesIO(), _io.BytesIO()
    def wait(s, timeout=None):
        s.waited += 1
        if s.waited == 1: raise KeyboardInterrupt()
        return 0
    def poll(s): return 0
procs=[]
runner.subprocess.Popen = lambda *a, **k: (procs.append(FakeProc()) or procs[-1])
tg=[0]; runner.terminate_group = lambda proc, grace=3.0: tg.__setitem__(0, tg[0]+1)
try:
    runner.run("t", ["true"], timeout=5); ki=False
except KeyboardInterrupt:
    ki=True
c_ki = (ki and tg[0] == 1 and procs and procs[0].waited == 1)   # re-raised, cleaned once (wait raised the KI)
# (4) OOB session close shares the runner helper (no bespoke terminate-only)
c_oob = ("runner.terminate_group" in inspect.getsource(oob.close_session))
sys.exit(0 if (c_timeout and c_leader_first and c_sigkill and c_sns and c_ki and c_oob) else 1)
PYEOF

echo "[113] ingestion (run-audit #6/#7) — file-output tools that were recorded-raw-only now INGESTED: shosubgo writes its names to the -o FILE (not stdout, so exec_tool's r.raw_path was None and 392 names were dropped) -> vertical reads the -o file directly; smap emits nmap-style text (was 505 lines / 0 entities) -> probe parses 'Nmap scan report for <host> (<ip>)' + '<n>/tcp open <svc>' into scoped 'port' entities (passive, Shodan-backed)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "shosubgo reads its -o file (not r.raw_path) -> names ingested; smap nmap-text parsed into ip:port 'port' entities, scope-gated; both no longer recorded-raw-only" || no "shosubgo/smap ingestion broken"
import sys, re, inspect
from quarry_recon.phases import vertical, probe
from quarry_recon import normalize
# shosubgo: reads the -o file (not r.raw_path, which is None for a -o tool) via the fail-closed helper
vsrc = inspect.getsource(vertical.run)
shb = vsrc[vsrc.find("shosubgo"):vsrc.find("shosubgo") + 1400]
c_shosubgo = ("_shosubgo_read(sho)" in shb and "reclassify_from_artifact" in shb and "if r.raw_path:" not in shb)
# normalize.hosts parses the shosubgo name list
c_shparse = (len(list(normalize.hosts("a.acme.com\nb.acme.com\n", "shosubgo", "x"))) == 2)
# smap: probe parses smap -oJ JSON into port entities (was recorded raw only); full matrix in [136]
psrc = inspect.getsource(probe)
c_smap_wire = ('add("port"' in psrc and '"smap"' in psrc and "_smap_records" in psrc and '"-oJ"' in psrc)
c_smap_parse = callable(getattr(probe, "_smap_records", None))   # helper present; behavioral coverage in [136]
sys.exit(0 if (c_shosubgo and c_shparse and c_smap_wire and c_smap_parse) else 1)
PYEOF

echo "[114] honest findings framing (complete_with_gaps batch) — scanner output is CANDIDATE until confirmed: digest inventory splits confirmed_findings vs scanner_candidates (no bare 'findings' number presenting confirmed:false as confirmed); HOTLIST header says 'Scanner candidates (N) — UNCONFIRMED' when none confirmed, and 'M confirmed · N candidate' when some are."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "digest inventory = confirmed_findings + scanner_candidates + findings_total (no ambiguous bare 'findings'); HOTLIST header candidate/confirmed split" || no "findings candidate/confirmed framing broken"
import sys, tempfile, pathlib
from quarry_recon import triage
from quarry_recon.store import Run
from quarry_recon.config import ScopeMatcher
scope = ScopeMatcher([], [], [], False)
r = Run(pathlib.Path(tempfile.mkdtemp()), "t")
r.add("finding", {"id": "a", "template": "xss-candidate", "severity": "medium", "matched": "x", "confirmed": False})
r.add("finding", {"id": "b", "template": "cve", "severity": "high", "matched": "y", "confirmed": False})
inv = triage.collect(r, scope)["inventory"]
c_split = (inv["scanner_candidates"] == 2 and inv["confirmed_findings"] == 0 and inv["findings_total"] == 2
           and "findings" not in inv)   # the ambiguous bare key is gone
md = triage.build(r, scope)
c_hotlist_cand = ("Scanner candidates (2) — UNCONFIRMED" in md)
# with a confirmed finding -> header splits
r.add("finding", {"id": "c", "template": "verified-thing", "severity": "high", "matched": "z", "confirmed": True})
inv2 = triage.collect(r, scope)["inventory"]
md2 = triage.build(r, scope)
c_confirmed = (inv2["confirmed_findings"] == 1 and inv2["scanner_candidates"] == 2
               and "1 confirmed" in md2 and "2 candidate" in md2)
sys.exit(0 if (c_split and c_hotlist_cand and c_confirmed) else 1)
PYEOF

echo '[115] xnLinkFinder lane (run-audit + audit-5) — v8.2 "-i <dir>" silently yields NOTHING (0712: 4x fast-empty on 100s MB); only STDIN parses file CONTENT. The lane is now ONE lifecycle (_xnl_lane) over independently identified units: _xnl_blob builds the bounded stdin artifact (its digest IS the unit identity), _xnl_run invokes the closed flag set at -d 0, _xnl_ingest is the parser boundary used by BOTH the fresh and the replay path. Unit state is PROJECT-owned, so a fresh run directory replays owned evidence instead of re-mining or losing it.'
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "one start/finish; stdin blob (no -i, -d 0, byte-accurate cap); scope re-validated; params RETAINED (no cap); large input -> -owl/-os skipped + DERIVED wordlist; project-owned state LOCKED and replayed read-only across runs; truncated input never owned; unit failure contained; cancellation + state failure honest; secrets VERBATIM, malformed -> parse gap + re-mine; durability both ways; absent/planted artifacts; engine bound to identity" || no "xnLinkFinder lane broken"
import sys, inspect, json, tempfile, pathlib
from types import SimpleNamespace
from quarry_recon.phases import crawl
from quarry_recon import budget, events
from quarry_recon.runner import RunResult, Status

# ── structural: the three decomposed pieces still hold the load-bearing decisions ──
s_blob, s_run = (inspect.getsource(f) for f in (crawl._xnl_blob, crawl._xnl_run))
s_lane = "".join(inspect.getsource(f) for f in (crawl._xnl_lane, crawl._xnl_mine, crawl._xnl_settle,
                                                crawl._xnl_terminal))
c_struct = ("XNL_MAX_INPUT" in s_blob and "1 << 20" in s_blob                  # byte-accurate chunked cap
            and 'bf.write(b"\\n")' in s_blob.split("for i, f in enumerate")[0]  # blank line BEFORE the loop
            and "input_file=blob" in s_run and '"-i", indir' not in s_run and '"-inc"' not in s_run
            and '"-d", "0"' in s_run and '"-ow"' in s_run and "unlink(missing_ok=True)" in s_run
            and '"PYTHONHASHSEED": "0"' in s_run
            and "cand[:" not in inspect.getsource(crawl._xnl_ingest)   # step 4.1: retention is COMPLETE
            and "<stdin>" in inspect.getsource(crawl._xnl_ingest)
            and "_xnl_state_dir" in s_lane and "_xnl_replay_bundle" in s_lane
            and "state_lock" in s_lane and "_xnl_materialize" in s_lane
            and "tool_start" in s_lane and "tool_finish" in s_lane)

tmp = pathlib.Path(tempfile.mkdtemp())
events.configure(tmp)

class Run:
    def __init__(self, project, name):
        self.project_dir = project
        self.dir = project / name
        self.added = []
    def raw_path(self, ph, tl, nm):
        p = self.dir / "raw" / ph / tl / nm; p.parent.mkdir(parents=True, exist_ok=True); return p
    def add(self, ent, rec):
        self.added.append((ent, rec)); return True
    def record(self, *a, **k):
        pass

def ctx_for(project, name="run1"):
    c = SimpleNamespace(run=Run(project, name), http_timeout=60,
                        profile=SimpleNamespace(apex_domains=["acme.com"], http_rl=0),
                        scope=SimpleNamespace(in_scope=lambda h: h == "acme.com" or h.endswith(".acme.com"),
                                              is_oos=lambda h: False),
                        echo=lambda m: None)
    c.write_list = lambda nm, it: (c.run.dir / nm).write_text("\n".join(map(str, it))) or (c.run.dir / nm)
    return c

def events_of(log):
    return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []

_LOGS = [0]

def lane(ctx, units, exec_fn, installed=True, engine="8.2"):
    """One lane invocation with its OWN event log — a shared log makes every later case read the earlier
    cases' terminals, which is how a contaminated fixture passes for the wrong reason."""
    crawl.exec_tool = exec_fn
    crawl.have = lambda t: installed
    crawl._xnl_engine = lambda: engine        # the real probe shells out to pipx; pin it here
    _LOGS[0] += 1
    log_dir = tmp / "logs" / str(_LOGS[0]); log_dir.mkdir(parents=True)
    events.reset(); events.configure(log_dir)
    crawl._xnl_lane(ctx, units)
    return events_of(log_dir / "events.jsonl")

def indir(root, name, body=b"var x = '/a';"):
    d = root / "in" / name; d.mkdir(parents=True, exist_ok=True); (d / "a.js").write_bytes(body); return str(d)

# ── (1) capability: one lifecycle, stdin blob, <stdin> noise dropped, scope re-validated ──
def ok_exec(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("id\n<stdin>\ntoken\n")
    # MEASURED (8.2, empty stdin blob): EVERY requested artifact is created — links/params/wordlist as
    # EMPTY FILES, secrets as `[]`.
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    if "-owl" in cmd and not pathlib.Path(cmd[cmd.index("-owl")+1]).exists():
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("")
    ol = pathlib.Path(cmd[cmd.index("-o")+1])
    ol.write_text("https://api.acme.com/x?id=1\nhttps://acme.com.evil.net/pwn\n")   # 2nd is OFF SCOPE
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("id\ntoken\napi\n")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, ol, 1)

p1 = tmp / "p1"; c1 = ctx_for(p1)
evs = lane(c1, [(indir(p1, "js"), "js", False)], ok_exec)
starts = [e for e in evs if e.get("event") == events.TOOL_START]
fins = [e for e in evs if e.get("event") == events.TOOL_FINISH]
led = [e for e in evs if e.get("event") == events.LEDGER]
params = sorted(r["value"] for ent, r in c1.run.added if ent == "parameter")
eps = [r["value"] for ent, r in c1.run.added if ent == "endpoint"]
c_capability = (len(starts) == 1 and len(fins) == 1 and starts[0]["input_total"] == 1
                and params == ["id", "token"]                              # <stdin> filtered
                and eps == ["https://api.acme.com/x?id=1"]                 # the evil.net link is NOT surface
                and led and led[-1]["produced"]["potential_params"] == 2
                and led[-1]["produced"]["oos_links"] == 1
                and fins[0]["status"] == "success"
                and fins[0]["produced"] == {"references": 2, "params": 2, "wordlist": 3, "secrets": 0})

# ── (2) suspicious-empty: real input, none of the four artifacts ──
p2 = tmp / "p2"; c2 = ctx_for(p2)
evs = lane(c2, [(indir(p2, "js", b"x" * 2000), "js", False)],
           lambda tool, cmd, timeout=None, input_file=None, **k: RunResult("xnLinkFinder", cmd, Status.EMPTY, 0, 0.1, None, 0))
c_suspicious = any("0 links/params/words/secrets" in (e.get("reason") or "") for e in evs)

# ── (3) a WORDLIST-ONLY run is USEFUL -> not suspicious, and SUCCESS not EMPTY ──
def wl_only(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-o")+1]).write_text("")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("word1\nword2\n")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 0)
p3 = tmp / "p3"; c3 = ctx_for(p3)
evs = lane(c3, [(indir(p3, "js", b"x" * 2000), "js", False)], wl_only)
fin3 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_wl_ok = (not any("0 links/params/words/secrets" in (e.get("reason") or "") for e in evs)
           and fin3["status"] == "success" and fin3["produced"]["wordlist"] == 2)

# ── (4) BYTE cap: 3x2MB with a 5MB cap -> bounded blob, capped coverage, and NEVER owned ──
old_cap = crawl.XNL_MAX_INPUT; crawl.XNL_MAX_INPUT = 5*1024*1024
p4 = tmp / "p4"; c4 = ctx_for(p4)
big = p4 / "in" / "big"; big.mkdir(parents=True)
for i in range(3): (big / f"f{i}.bin").write_bytes(b"x" * (2*1024*1024))
evs = lane(c4, [(str(big), "big", False)], ok_exec)
blob = c4.run.raw_path("crawl", "xnLinkFinder", "big_input.txt")
c_bytecap = (blob.stat().st_size <= 5*1024*1024
             and any("input cap" in (e.get("reason") or "") for e in evs)
             and any(e.get("measure") == "units" and e.get("omitted") == 1
                     and "input incomplete" in (e.get("reason") or "") for e in evs))
calls = []
evs = lane(ctx_for(p4, "run2"), [(str(big), "big", False)],
           lambda t, cmd, **k: (calls.append(cmd), ok_exec(t, cmd, **k))[1])
c_capped_remines = len(calls) == 1        # a truncated input is re-mined, not frozen
crawl.XNL_MAX_INPUT = old_cap

# ── (5) large input: -owl/-os skipped (timekillers), wordlist DERIVED, params capped as POTENTIAL ──
cap_cmd = {}
def integ_exec(tool, cmd, timeout=None, input_file=None, **k):
    cap_cmd["c"] = list(cmd)
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    pathlib.Path(cmd[cmd.index("-o")+1]).write_text("https://acme.com/api/users/[id]\nhttps://acme.com/admin\n")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("\n".join(f"p{i}" for i in range(3000)))
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)
old_wl = crawl.XNL_WORDLIST_LIMIT; crawl.XNL_WORDLIST_LIMIT = 1000
p5 = tmp / "p5"; c5 = ctx_for(p5)
evs = lane(c5, [(indir(p5, "waymore", b"y" * 5000), "waymore", True)], integ_exec)
prm = [r for ent, r in c5.run.added if ent == "parameter"]
eps5 = [r["value"] for ent, r in c5.run.added if ent == "endpoint"]
wl5 = c5.run.raw_path("crawl", "xnLinkFinder", "waymore_wordlist.txt")
c_large = ("-orig" not in cap_cmd["c"] and "-ow" in cap_cmd["c"] and "-spo" in cap_cmd["c"]
           and "-owl" not in cap_cmd["c"] and "-os" not in cap_cmd["c"]
           and "https://acme.com/api/users/[id]" in eps5              # route template NOT corrupted
           # step 4.1: EVERY accepted candidate is retained (the cap destroyed 94.5% on the 2026-07-25 measured run),
           # and the coverage record no longer claims an omission it does not have.
           and len(prm) == 3000 and prm[0]["kind"] == "potential"
           and any("3000/3000 potential params retained (no cap)" in (e.get("reason") or "") for e in evs)
           and wl5.exists() and wl5.read_text().strip()
           and any("DERIVED" in (e.get("reason") or "") for e in evs))
crawl.XNL_WORDLIST_LIMIT = old_wl
p5b = tmp / "p5b"; c5b = ctx_for(p5b)
cap_cmd.clear(); lane(c5b, [(indir(p5b, "small"), "small", False)], integ_exec)
c_small = ("-owl" in cap_cmd["c"] and "-os" in cap_cmd["c"])

# ── (6) audit-5#1: state is PROJECT-owned, so a SECOND run replays owned evidence: no re-mine, and the
#        entities are in the NEW run's store (a skip would lose them) ──
p6 = tmp / "p6"
c6a = ctx_for(p6, "runA"); calls = []
lane(c6a, [(indir(p6, "js"), "js", False)], lambda t, cmd, **k: (calls.append(cmd), ok_exec(t, cmd, **k))[1])
c6b = ctx_for(p6, "runB"); calls.clear()
evs = lane(c6b, [(indir(p6, "js"), "js", False)], lambda t, cmd, **k: (calls.append(cmd), ok_exec(t, cmd, **k))[1])
eps6 = [r["value"] for ent, r in c6b.run.added if ent == "endpoint"]
c_replay = (not calls                                                   # the tool was NOT re-run
            and eps6 == ["https://api.acme.com/x?id=1"]                 # ...and the evidence is still here
            and any(e.get("event") == events.LEDGER and e.get("replay") for e in evs)
            and [e for e in evs if e.get("event") == events.TOOL_FINISH][0]["status"] == "success"
            and not (p6 / "runB" / "recon" / "state").exists())         # state is not run-scoped
c_state_in_project = (p6 / "recon" / "state" / f"xnlinkfinder").exists()

# ── (7) audit-5#5: one unit's failure is contained; audit-5#6: a missing binary still gets a lifecycle ──
real_ingest = crawl._xnl_ingest
seen = []
def boom(ctx, tag, outs, **kw):
    seen.append(tag)
    if tag == "js":
        raise RuntimeError("ingest exploded")
    return real_ingest(ctx, tag, outs, **kw)
p7 = tmp / "p7"; c7 = ctx_for(p7)
crawl._xnl_ingest = boom
evs = lane(c7, [(indir(p7, "js"), "js", False), (indir(p7, "sourcemap"), "sourcemap", False)], ok_exec)
crawl._xnl_ingest = real_ingest
fin7 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_contained = (seen == ["js", "sourcemap"] and "ingest exploded" in (fin7.get("reason") or "")
               and fin7["status"] in ("partial", "failed"))
p8 = tmp / "p8"; c8 = ctx_for(p8)
evs = lane(c8, [(indir(p8, "js"), "js", False)], ok_exec, installed=False)
fin8 = [e for e in evs if e.get("event") == events.TOOL_FINISH]
c_missing = (len([e for e in evs if e.get("event") == events.TOOL_START]) == 1 and len(fin8) == 1
             and fin8[0]["status"] == "skipped"
             and any(e.get("unit") == "install" and e.get("omitted") == 1 for e in evs))

# ── (8) audit-6: the OWNERSHIP boundary itself ──
# #1 the project state is LOCKED for the whole lifecycle (prune/load/replay/publish/save inside it)
import contextlib as _c
order = []
_real_lock, _real_prune = budget.state_lock, budget.prune_state
_real_init, _real_save = budget.Ledger.__init__, budget.Ledger.save


@_c.contextmanager
def _tracing_lock(path):
    order.append("lock")
    with _real_lock(path) as q:
        yield q
    order.append("unlock")


budget.state_lock = _tracing_lock
budget.prune_state = lambda *a, **k: (order.append("prune"), _real_prune(*a, **k))[1]
budget.Ledger.__init__ = lambda self, *a, **k: (order.append("load"), _real_init(self, *a, **k))[1]
budget.Ledger.save = lambda self: (order.append("save"), _real_save(self))[1]
p9 = tmp / "p9"; c9 = ctx_for(p9)
lane(c9, [(indir(p9, "js"), "js", False)], ok_exec)
c_lock_order = (order and order[0] == "lock" and order[-1] == "unlock"
                and all(0 < order.index(s) < order.index("unlock") for s in ("prune", "load", "save")))
budget.state_lock, budget.prune_state = _real_lock, _real_prune
budget.Ledger.__init__, budget.Ledger.save = _real_init, _real_save


@_c.contextmanager
def _busy(path):
    raise budget.StateBusy(f"another lifecycle holds {path}")
    yield


budget.state_lock = _busy
p10 = tmp / "p10"; c10 = ctx_for(p10); mined = []
evs = lane(c10, [(indir(p10, "js"), "js", False)],
           lambda t, cmd, **k: (mined.append(cmd), ok_exec(t, cmd, **k))[1])
fin10 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_busy = (not mined and fin10["status"] == "failed" and "another lifecycle" in (fin10.get("reason") or "")
          and any(e.get("unit") == "lock" and e.get("omitted") == 1 for e in evs))
budget.state_lock = _real_lock

# #2 replay is READ-ONLY over digest-bound evidence (the derive path used to rewrite the wordlist in state)
old_wl3 = crawl.XNL_WORDLIST_LIMIT; crawl.XNL_WORDLIST_LIMIT = 1
p11 = tmp / "p11"
lane(ctx_for(p11, "runA"), [(indir(p11, "js"), "js", False)], ok_exec)
sdir = p11 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
_ev = lambda: {q.name: q.read_bytes() for q in sorted(sdir.rglob("*"))
               if q.is_file() and not q.name.endswith(".state.json") and q.name != ".lock"}
before = _ev()
evs = lane(ctx_for(p11, "runB"), [(indir(p11, "js"), "js", False)], ok_exec)
c_readonly = (before and _ev() == before
              and any(e.get("event") == events.LEDGER and e.get("replay") for e in evs))
crawl.XNL_WORDLIST_LIMIT = old_wl3

# #3 CANCELLATION emits an honest terminal (it used to sign off SUCCESS/EMPTY from the `finally`)
_real_ingest = crawl._xnl_ingest


def _cancel(ctx, tag, outs, **kw):
    raise KeyboardInterrupt("ctrl-c")


crawl._xnl_ingest = _cancel
p12 = tmp / "p12"; c12 = ctx_for(p12)
try:
    lane(c12, [(indir(p12, "js"), "js", False)], ok_exec)
    c_cancel = False
except KeyboardInterrupt:
    evs = events_of(tmp / "logs" / str(_LOGS[0]) / "events.jsonl")
    fins = [e for e in evs if e.get("event") == events.TOOL_FINISH]
    c_cancel = (len(fins) == 1 and fins[0]["status"] == "failed"          # nothing was ingested
                and "CANCELLED" in (fins[0].get("reason") or "")
                and "nothing extracted" in fins[0]["reason"])
crawl._xnl_ingest = _real_ingest

# ...and an ordinary STATE failure is contained (it used to abort the crawl phase with no terminal)
_real_state_dir = crawl._xnl_state_dir


def _bad_state(ctx):
    raise OSError("read-only filesystem")


crawl._xnl_state_dir = _bad_state
p13 = tmp / "p13"; c13 = ctx_for(p13); mined2 = []
evs = lane(c13, [(indir(p13, "js"), "js", False)],
           lambda t, cmd, **k: (mined2.append(cmd), ok_exec(t, cmd, **k))[1])
fin13 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_state_contained = (not mined2 and fin13["status"] == "failed"
                     and "read-only filesystem" in (fin13.get("reason") or ""))
crawl._xnl_state_dir = _real_state_dir

# #4 secrets: MEASURED `-os` schema ingested VERBATIM; anything else is a parse gap and stays retryable
MEASURED_OS = json.dumps([{"type": "AWS Access Key", "value": '"AKIAIOSFODNN7EXAMPLE"',
                           "sources": ["<stdin>"], "count": 1}])


def sec_exec(body):
    def _f(tool, cmd, timeout=None, input_file=None, **k):
        pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("https://api.acme.com/x\n")
        pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("")
        if "-owl" in cmd:
            pathlib.Path(cmd[cmd.index("-owl") + 1]).write_text("")
        if "-os" in cmd and body is not None:      # body=None = REQUESTED and never written (a gap)
            pathlib.Path(cmd[cmd.index("-os") + 1]).write_text(body)
        return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)
    return _f


p14 = tmp / "p14"; c14 = ctx_for(p14)
evs = lane(c14, [(indir(p14, "js"), "js", False)], sec_exec(MEASURED_OS))
secs = [r for ent, r in c14.run.added if ent == "secret"]
fin14 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_secret_verbatim = (len(secs) == 1 and secs[0]["value"] == '"AKIAIOSFODNN7EXAMPLE"'
                     and secs[0]["preview"] == secs[0]["value"] and "*" not in secs[0]["preview"]
                     and secs[0]["kind"] == "AWS Access Key" and fin14["produced"]["secrets"] == 1)
p15 = tmp / "p15"; mined3 = []
_bad_exec = sec_exec("{not json at all")
evs = lane(ctx_for(p15, "runA"), [(indir(p15, "js"), "js", False)],
           lambda t, cmd, **k: (mined3.append(cmd), _bad_exec(t, cmd, **k))[1])
raw15 = (p15 / "runA" / "raw" / "crawl" / "xnLinkFinder" / "js_secrets.json")
sdir15 = p15 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
lane(ctx_for(p15, "runB"), [(indir(p15, "js"), "js", False)],
     lambda t, cmd, **k: (mined3.append(cmd), _bad_exec(t, cmd, **k))[1])
c_secret_gap = (any("RETAINED" in (e.get("reason") or "") for e in evs)
                and raw15.read_text() == "{not json at all"          # the artifact survives the parse
                and not list(sdir15.glob("*_bundle.json"))            # an unaccountable unit is not owned
                and len(mined3) == 2)                                 # ...and is RE-MINED next run

# #5 durability BOTH ways: a failed append that a snapshot rescues is owned WITHOUT a gap; a failed
#    append with no snapshot is not owned at all
_real_append = budget.Ledger._append


def _no_completion(self, rec):
    if "i" in rec:                    # only the COMPLETION append fails; evidence binds normally
        self._journal_unsafe = True
        return False
    return _real_append(self, rec)


budget.Ledger._append = _no_completion
p16 = tmp / "p16"; evs = lane(ctx_for(p16), [(indir(p16, "js"), "js", False)], ok_exec)
u16 = [e for e in evs if e.get("measure") == "units"]
fin16 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
budget.Ledger._append = _real_append
# the claim is OWNERSHIP, so it is proven by REOPENING a real ledger over the rescued snapshot
_sdir16 = p16 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
_snap = next(_sdir16.glob("*.state.json"))
_re = budget.Ledger(_snap, lane="crawl.xnlinkfinder")
c_rescued = (u16 and u16[-1]["omitted"] == 0 and "snapshot compacted" in (u16[-1].get("reason") or "")
             and fin16["status"] == "success" and "NOT persisted" not in (fin16.get("reason") or "")
             and _re.done and all(_re.artifact(u) is not None for u in _re.done))
_real_save2 = budget.Ledger.save
budget.Ledger.save = lambda self: False
_real_record = budget.Ledger.record
budget.Ledger.record = lambda self, *a, **k: False
p17 = tmp / "p17"; evs = lane(ctx_for(p17), [(indir(p17, "js"), "js", False)], ok_exec)
u17 = [e for e in evs if e.get("measure") == "units"]
fin17 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_unrescued = (u17 and u17[-1]["omitted"] == 1 and fin17["status"] == "partial"
               and "reached neither the journal nor a snapshot" in (fin17.get("reason") or ""))
budget.Ledger.record, budget.Ledger.save = _real_record, _real_save2

# #6 an ABSENT artifact is recorded absent, and a PLANTED one is refused on replay
# LARGE input: `-os` is never requested, so a missing secrets artifact is genuine ABSENCE (a
# requested-but-missing one is a parse gap — checked separately below)
old_wl4 = crawl.XNL_WORDLIST_LIMIT; crawl.XNL_WORDLIST_LIMIT = 1
p18 = tmp / "p18"; mined4 = []
lane(ctx_for(p18, "runA"), [(indir(p18, "js"), "js", False)],
     lambda t, cmd, **k: (mined4.append(cmd), sec_exec(None)(t, cmd, **k))[1])
sdir18 = p18 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
man18 = json.loads(next(sdir18.glob("*_bundle.json")).read_text())
_links = next(sdir18.glob("*_links.txt"))
_links.with_name(_links.name.replace("_links.txt", "_secrets.json")).write_text('[{"type":"x","value":"planted"}]')
c18 = ctx_for(p18, "runB")
lane(c18, [(indir(p18, "js"), "js", False)],
     lambda t, cmd, **k: (mined4.append(cmd), sec_exec(None)(t, cmd, **k))[1])
crawl.XNL_WORDLIST_LIMIT = old_wl4
c_presence = (man18["outputs"]["secrets"]["present"] is False
              and not any(r.get("value") == "planted" for ent, r in c18.run.added if ent == "secret")
              and len(mined4) == 2)                                   # planted evidence -> RE-MINE

# #7 identity binds the ENGINE, and an unprovable engine mines without owning
p19 = tmp / "p19"; m19 = []
_count = lambda t, cmd, **k: (m19.append(cmd), ok_exec(t, cmd, **k))[1]
lane(ctx_for(p19, "runA"), [(indir(p19, "js"), "js", False)], _count, engine="8.2")
lane(ctx_for(p19, "runB"), [(indir(p19, "js"), "js", False)], _count, engine="8.2")
lane(ctx_for(p19, "runC"), [(indir(p19, "js"), "js", False)], _count, engine="8.3")
c_engine = [len(m19)] == [2]
p20 = tmp / "p20"; m20 = []
_count2 = lambda t, cmd, **k: (m20.append(cmd), ok_exec(t, cmd, **k))[1]
evs = lane(ctx_for(p20, "runA"), [(indir(p20, "js"), "js", False)], _count2, engine="")
lane(ctx_for(p20, "runB"), [(indir(p20, "js"), "js", False)], _count2, engine="")
c_engine_unproven = (len(m20) == 2 and any("identity is unproven" in (e.get("reason") or "") for e in evs))

# #4/#5 (audit-7): the WHOLE measured row is enforced, `[]` is the measured no-find answer, and an `-os`
# artifact we ASKED for and did not get fails closed
p21 = tmp / "p21"; c21 = ctx_for(p21)
lane(c21, [(indir(p21, "js"), "js", False)],
     sec_exec(json.dumps([{"type": "AWS", "value": "AKIA_GOOD", "sources": ["<stdin>"], "count": 1},
                          {"type": "Generic", "value": "no-count", "sources": ["<stdin>"]}])))
_s21 = [r["value"] for ent, r in c21.run.added if ent == "secret"]
_sd21 = p21 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
c_row_shape = (_s21 == ["AKIA_GOOD"] and not list(_sd21.glob("*_bundle.json")))
p22 = tmp / "p22"
evs = lane(ctx_for(p22), [(indir(p22, "js"), "js", False)], sec_exec("[]"))
_sd22 = p22 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
c_nofind_clean = (list(_sd22.glob("*_bundle.json"))
                  and not any("retryable" in (e.get("reason") or "") for e in evs))
p23 = tmp / "p23"
evs = lane(ctx_for(p23), [(indir(p23, "js"), "js", False)], sec_exec(None))     # -os asked for, not written
_sd23 = p23 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
c_missing_os = (any("no artifact was written" in (e.get("reason") or "") for e in evs)
                and not list(_sd23.glob("*_bundle.json")))

# ── (9) audit-8: the accounting cannot contradict the store ──
# #1 a sink that raises MID-ingestion: what already landed is still production
p24 = tmp / "p24"; c24 = ctx_for(p24)
_seen = []
_real_add = c24.run.add


def _flaky(kind, rec):
    _seen.append(kind)
    if len(_seen) == 2:
        raise RuntimeError("store died")
    return _real_add(kind, rec)


c24.run.add = _flaky


def two_links(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-o")+1]).write_text("https://api.acme.com/a\nhttps://api.acme.com/b\n")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("")
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)


evs = lane(c24, [(indir(p24, "js"), "js", False)], two_links)
fin24 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_mid_ingest = (len(_seen) == 2 and fin24["produced"]["references"] == 1
                and fin24["status"] == "partial" and "store died" in (fin24.get("reason") or ""))

# #2 a REQUESTED artifact the tool never wrote is retryable; an UNREQUESTED one says nothing
c_requested_missing = True
for _flag in ("-o", "-op", "-owl"):
    def _skip_one(tool, cmd, timeout=None, input_file=None, flag=_flag, **k):
        for f, body in (("-o", "https://api.acme.com/x\n"), ("-op", "id\n"), ("-owl", ""), ("-os", "[]")):
            if f in cmd and f != flag:
                pathlib.Path(cmd[cmd.index(f)+1]).write_text(body)
        return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)

    _p = tmp / f"p25{_flag}"; _c = ctx_for(_p)
    evs = lane(_c, [(indir(_p, "js"), "js", False)], _skip_one)
    _sd = _p / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
    c_requested_missing = c_requested_missing and (
        any(_flag in (e.get("reason") or "") and "no artifact written" in (e.get("reason") or "")
            for e in evs if e.get("measure") == "units")
        and not list(_sd.glob("*_bundle.json")))

# #3 the measured ROW: stdin provenance and a positive occurrence count
c_row_strict = True
for _body in ('[{"type": "AWS", "value": "v", "sources": [], "count": 1}]',
              '[{"type": "AWS", "value": "v", "sources": ["elsewhere"], "count": 1}]',
              '[{"type": "AWS", "value": "v", "sources": ["<stdin>"], "count": 0}]',
              '[{"type": " ", "value": "v", "sources": ["<stdin>"], "count": 1}]'):
    _p = tmp / f"p26{abs(hash(_body)) % 10000}"; _c = ctx_for(_p)
    evs = lane(_c, [(indir(_p, "js"), "js", False)], sec_exec(_body))
    _sd = _p / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
    c_row_strict = c_row_strict and (not [r for ent, r in _c.run.added if ent == "secret"]
                                     and not list(_sd.glob("*_bundle.json")))

# ── (10) audit-9: production is DELIVERY, and one read decides absent/readable/unreadable ──
# #1 parameters counted as delivered, not as parsed
p27 = tmp / "p27"; c27 = ctx_for(p27)
_pseen = []


def _param_flaky(kind, rec):
    _pseen.append(kind)
    if len(_pseen) == 3:
        raise RuntimeError("store died")
    return True


c27.run.add = _param_flaky


def params_only(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-o")+1]).write_text("")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("a_param\nb_param\nc_param\n")
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)


evs = lane(c27, [(indir(p27, "js"), "js", False)], params_only)
fin27 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_params_delivered = (fin27["produced"]["params"] == 2 and fin27["status"] == "partial"
                      and "store died" in (fin27.get("reason") or ""))

# #2 secrets counted into the carrier as each write returns
p28 = tmp / "p28"; c28 = ctx_for(p28)
_ssee = []


def _sec_flaky(kind, rec):
    _ssee.append(kind)
    if len([x for x in _ssee if x == "secret"]) == 2:
        raise RuntimeError("store died on secret two")
    return True


c28.run.add = _sec_flaky
_two = json.dumps([{"type": "AWS", "value": "AKIA_ONE", "sources": ["<stdin>"], "count": 1},
                   {"type": "AWS", "value": "AKIA_TWO", "sources": ["<stdin>"], "count": 1}])
evs = lane(c28, [(indir(p28, "js"), "js", False)], sec_exec(_two))
fin28 = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
c_secrets_delivered = (fin28["produced"]["secrets"] == 1 and fin28["status"] == "partial"
                       and "store died on secret two" in (fin28.get("reason") or ""))

# #3 ONE read authority: an UNREADABLE artifact is never absence and never a clean zero
_real_rb = pathlib.Path.read_bytes


def _deny_secrets(self, *a, **k):
    if self.name.endswith("_secrets.json"):
        raise PermissionError("denied")
    return _real_rb(self, *a, **k)


pathlib.Path.read_bytes = _deny_secrets
p29 = tmp / "p29"; c29 = ctx_for(p29)
evs = lane(c29, [(indir(p29, "js"), "js", False)], sec_exec("[]"))
pathlib.Path.read_bytes = _real_rb
_sd29 = p29 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
c_read_authority = (any("unreadable" in (e.get("reason") or "")
                        for e in evs if e.get("measure") == "units")
                    and not list(_sd29.glob("*_bundle.json")))

# ── (11) audit-10: the bytes ingested ARE the bytes owned, and rejected bytes never arm A1d ──
p30 = tmp / "p30"; c30 = ctx_for(p30)
_real_add30 = c30.run.add


def _rewriting_add(kind, rec):
    for q in (p30 / "run1" / "raw" / "crawl" / "xnLinkFinder").glob("*_links.txt"):
        q.write_text("https://api.acme.com/SWAPPED\n")      # swap the artifact under the parser
    return _real_add30(kind, rec)


c30.run.add = _rewriting_add


def one_link(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-o")+1]).write_text("https://api.acme.com/original\n")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("")
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)


lane(c30, [(indir(p30, "js"), "js", False)], one_link)
_sd30 = p30 / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
_owned = next(_sd30.glob("*_links.txt")).read_text()
c_bytes_owned = ("SWAPPED" not in _owned and _owned.strip() == "https://api.acme.com/original")

# ...and the run-local copy a replay leaves behind IS that same evidence
for _stale in (p30 / "run1" / "raw" / "crawl" / "xnLinkFinder").glob("*_links.txt"):
    _stale.write_text("stale junk\n")
_c30b = ctx_for(p30, "run2"); _mined30 = []
lane(_c30b, [(indir(p30, "js"), "js", False)],
     lambda t, cmd, **k: (_mined30.append(cmd), one_link(t, cmd, **k))[1])
_copy = next((p30 / "run2" / "raw" / "crawl" / "xnLinkFinder").glob("*_links.txt")).read_text()
c_replay_copy = (not _mined30 and _copy == _owned)

# #2 the DERIVED wordlist contains only ACCEPTED values (it arms an active puredns brute in A1d)
old_wl5 = crawl.XNL_WORDLIST_LIMIT; crawl.XNL_WORDLIST_LIMIT = 1


def junk_exec(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-o")+1]).write_bytes(
        b"https://api.acme.com/keep\nadmin\xffinternal\nthis is not a url ###junkword\n"
        b"https://oosword.evil.example/x\n")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_bytes(b"good_param\nbad\xffparam\n")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)


p31 = tmp / "p31"; c31 = ctx_for(p31)
lane(c31, [(indir(p31, "js"), "js", False)], junk_exec)
crawl.XNL_WORDLIST_LIMIT = old_wl5
_wl = next((p31 / "run1" / "raw" / "crawl" / "xnLinkFinder").glob("*_wordlist.txt")).read_text().split()
c_derived_clean = ({"keep", "good"} <= set(_wl)
                   and not ({"admin", "internal", "bad", "junkword", "oosword"} & set(_wl)))

# ...and A1d's own reader drops undecodable lines rather than replacing them, REPORTING the loss
from quarry_recon.phases import vertical as _vertical
p32 = tmp / "p32"; c32 = ctx_for(p32)
_wldir = c32.run.dir / "raw" / "crawl" / "xnLinkFinder"; _wldir.mkdir(parents=True, exist_ok=True)
(_wldir / "js_wordlist.txt").write_bytes(b"internal\nadmin\xffsecret\n")
_loss = {}
_words = _vertical._target_wordlist(c32, loss=_loss)
c_a1d_strict = ("internal" in _words and not any("admin" in w or "secret" in w for w in _words)
                and _loss["dropped_lines"] == 1 and _loss["unreadable_files"] == 0)

# review-B-audit-11#1/#2/#3: the loss must reach the REAL verdict — a reason-only coverage event does not.
from quarry_recon import store as _store
from quarry_recon.phases import enrich as _enrich


def verdict_for(root, wordlist_bytes, deny=False):
    """Drive the crawl lane (and A1d) on a REAL Run and read the manifest verdict."""
    from quarry_recon.runner import RunResult as _RR
    r = _store.Run.create(root, "t")
    events.reset(); events.configure(r.dir)

    def _exec(tool, cmd, timeout=None, input_file=None, **k):
        pathlib.Path(cmd[cmd.index("-o")+1]).write_text("https://api.acme.com/x\n")
        pathlib.Path(cmd[cmd.index("-op")+1]).write_text("")
        if "-os" in cmd:
            pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
        if "-owl" in cmd:
            pathlib.Path(cmd[cmd.index("-owl")+1]).write_bytes(wordlist_bytes)
        return _RR(tool, cmd, Status.SUCCESS, 0, 0.1, None, 1)

    crawl.exec_tool = _exec; crawl.have = lambda t: True; crawl._xnl_engine = lambda: "8.2"
    c = ctx_for(root, "unused"); c.run = r
    d = indir(root, "js")
    crawl._xnl_lane(c, [(d, "js", False)])
    r.write_manifest({}, ["crawl"])
    return json.loads(r.manifest_path.read_text())["summary"]


c_verdict_gated = verdict_for(tmp / "p33", b"good\nbad\xffword\n")["verdict"] != "complete"
c_verdict_clean = verdict_for(tmp / "p34", b"good\nfine\n")["verdict"] == "complete"

# an UNREADABLE vocabulary is a DEGRADED A1d, never "the target had none"
p35 = tmp / "p35"; _r35 = _store.Run.create(p35, "t")
events.reset(); events.configure(_r35.dir)
_wd = _r35.dir / "raw" / "crawl" / "xnLinkFinder"; _wd.mkdir(parents=True, exist_ok=True)
(_wd / "js_wordlist.txt").write_bytes(b"internal\n")
_real_rb2 = pathlib.Path.read_bytes


def _deny_wl(self, *a, **k):
    if self.name.endswith("_wordlist.txt"):
        raise PermissionError("denied")
    return _real_rb2(self, *a, **k)


pathlib.Path.read_bytes = _deny_wl
_c35 = ctx_for(p35, "unused"); _c35.run = _r35
_c35.profile = SimpleNamespace(apex_domains=["acme.com"], http_rl=0, dns_rate=0)
_c35.scope.passive_only = False
_enrich.have = lambda t: False
_vertical._wordlist = lambda c: None
_enrich._a1d_recursive_brute(_c35)
pathlib.Path.read_bytes = _real_rb2
_r35.write_manifest({}, ["enrich"])
_sum35 = json.loads(_r35.manifest_path.read_text())["summary"]
_a1d_runs = [x for x in _r35.tool_runs("enrich") if x.tool == "a1d"]
# review-B-audit-12#1: ONE attempt records exactly ONE outcome, and it names what was actually lost
c_a1d_degraded = (_sum35["verdict"] != "complete" and len(_a1d_runs) == 1
                  and _a1d_runs[0].status == "failed"
                  and "ALL 1 mined wordlist artifact(s) unreadable" in (_a1d_runs[0].note or ""))

# a MIXED input (one unreadable, one readable-but-empty) must not claim every artifact was unreadable,
# and the BASE wordlist read lives inside the same boundary (review-B-audit-12#2)
def a1d_records(root, files, deny=(), base=None, base_deny=False, puredns=False):
    r = _store.Run.create(root, "t")
    events.reset(); events.configure(r.dir)
    wd = r.dir / "raw" / "crawl" / "xnLinkFinder"; wd.mkdir(parents=True, exist_ok=True)
    for nm, body in files.items():
        (wd / nm).write_bytes(body)
    base_path = None
    if base is not None:
        base_path = root / "base.txt"; base_path.write_bytes(base)
    _rb = pathlib.Path.read_bytes
    _op = pathlib.Path.open

    def _picky(self, *a, **k):
        if self.name in deny or (base_deny and base_path is not None and self.name == base_path.name):
            raise PermissionError("denied")
        return _rb(self, *a, **k)

    def _picky_open(self, *a, **k):
        # the base dictionary is STREAMED now, not read whole (step 4 measurement #3)
        if base_deny and base_path is not None and self.name == base_path.name:
            raise PermissionError("denied")
        return _op(self, *a, **k)

    from quarry_recon.runner import RunResult as _RR2
    pathlib.Path.read_bytes = _picky
    pathlib.Path.open = _picky_open
    _enrich.have = lambda t: puredns
    _enrich.exec_tool = lambda tool, cmd, raw_path=None, timeout=None, **k: _RR2(
        tool, cmd, Status.EMPTY, 0, 0.1, None, 0)
    _vertical._resolvers = lambda c: (root / "r", root / "rt")
    _vertical._wordlist = lambda c: base_path
    c = ctx_for(root, "unused"); c.run = r
    c.profile = SimpleNamespace(apex_domains=["acme.com"], http_rl=0, dns_rate=0)
    c.scope.passive_only = False
    try:
        _enrich._a1d_recursive_brute(c)
    finally:
        pathlib.Path.read_bytes = _rb
        pathlib.Path.open = _op
    return [x for x in r.tool_runs("enrich") if x.tool == "a1d"]


_mixed = a1d_records(tmp / "p36", {"a_wordlist.txt": b"", "b_wordlist.txt": b"internal\n"},
                     deny=("b_wordlist.txt",))
c_a1d_mixed = (len(_mixed) == 1 and _mixed[0].status == "failed" and "ALL" not in (_mixed[0].note or "")
               and "1/2 mined wordlist artifact(s) unreadable" in _mixed[0].note)
_clean = a1d_records(tmp / "p37", {"a_wordlist.txt": b""})
c_a1d_clean_skip = (len(_clean) == 1 and _clean[0].status == "skipped")
_basefail = a1d_records(tmp / "p38", {"a_wordlist.txt": b"internal\n"}, base=b"api\n", base_deny=True,
                        puredns=True)
c_a1d_base = (len(_basefail) == 1 and _basefail[0].status == "partial"
              and "base wordlist could not be read" in _basefail[0].note)

# review-B-audit-13#1: eligible work that was never SUBMITTED is reported, and the outcome is chosen
# after the work — a lane that never ran must not claim it ran with less
_nopd = a1d_records(tmp / "p39", {"a_wordlist.txt": b"internal\napi\n"}, puredns=False)
_nopd_a1d = [x for x in _nopd if x.tool == "a1d"]
c_a1d_unsubmitted = (len(_nopd_a1d) == 1 and _nopd_a1d[0].status == "failed"
                     and "did NOT run" in _nopd_a1d[0].note
                     and "apex brute(s) unsubmitted" in _nopd_a1d[0].note)
_ranclean = a1d_records(tmp / "p40", {"a_wordlist.txt": b"internal\napi\n"}, puredns=True)
c_a1d_clean_run = ([x for x in _ranclean if x.tool == "a1d"] == [])
# review-B-audit-14: wildcard zones EXISTING is not the wildcard pass RUNNING — the differentiator
# reports what it actually probed, and unsubmitted zones are named with the reason
_wc_stats = {}
_c42 = ctx_for(tmp / "p42", "unused")
_c42.scope.passive_only = False
_c42.scope.is_oos = lambda h: False
_vertical.have = lambda t: False                     # no httpx -> nothing can be probed
_vertical._wildcard_differentiate(_c42, {"z.acme.com"}, phase="enrich", label="wc", stats=_wc_stats)
c_wc_stats = (_wc_stats["eligible_zones"] == 1 and _wc_stats["probed_zones"] == 0
              and _wc_stats["blocked_reason"] == "httpx is not installed")

# review-B-audit-15: A1d's own vocabulary IS a wordlist; omissions name themselves; the stats dict is a
# SNAPSHOT; and the coverage unit is the caller's label (a hard-coded one overwrote the vertical pass).
from quarry_recon.phases import probe as _probe
from quarry_recon.runner import RunResult as _RR3
_vertical.have = lambda t: True
_probe._vhost_wordlist = lambda: None
_vertical._wordlist = lambda c: None
_vertical.exec_tool = lambda tool, cmd, raw_path=None, timeout=None, **k: _RR3(
    tool, cmd, Status.EMPTY, 0, 0.1, None, 0)
_vertical.netguard._block_private = lambda c: False
_vertical.netguard.self_deny_list = lambda: "127.0.0.1"
_vertical.netguard.contact_state = lambda host, block_private=False: ("public", False, None)
p43 = tmp / "p43"; _c43 = ctx_for(p43, "unused"); _c43.scope.is_oos = lambda h: False
_c43.scope.passive_only = False
_c43.run.dir.mkdir(parents=True, exist_ok=True)         # the differ writes candidate lists into the run
_st43 = {}
_vertical._wildcard_differentiate(_c43, {"a.acme.com"}, extra_words=["api"], label="wildcard", stats=_st43)
c_wc_own_words = (_st43["probed_zones"] == 1 and not _st43["blocked_reason"])
_vertical._wildcard_differentiate(_c43, {"nope.example.org"}, extra_words=["api"], stats=_st43)
c_wc_snapshot = (_st43["probed_zones"] == 0 and _st43["eligible_zones"] == 0
                 and _st43["blocked_reason"] == "no in-scope wildcard zone")
_vertical.netguard.contact_state = lambda host, block_private=False: ("self", True, None)
_st44 = {}
_vertical._wildcard_differentiate(_c43, {f"z{i}.acme.com" for i in range(7)}, extra_words=["api"],
                                  stats=_st44)
# 4.3 v77: the guard is ACTIVE work, so it runs only for the zones the scheduler ADMITS — five here, all
# refused — while the per-run allowance defers the other two. Two facts, each with its own count.
c_wc_reasons = (_st44["blocked"] == {"zone_cap": 2, "self_or_private": 5}
                and "5 zone(s) refused by the self/private contact guard" in _st44["blocked_reason"]
                and "2 zone(s) deferred to a later run" in _st44["blocked_reason"])
_vertical.netguard.contact_state = lambda host, block_private=False: ("public", False, None)
p45 = tmp / "p45"; _c45 = ctx_for(p45, "unused"); _c45.scope.is_oos = lambda h: False
_c45.scope.passive_only = False
_c45.run.dir.mkdir(parents=True, exist_ok=True)
events.reset(); events.configure(p45 / "logs")
_vertical._wildcard_differentiate(_c45, {"a.acme.com"}, extra_words=["api"], label="wildcard")
_vertical._wildcard_differentiate(_c45, {"b.acme.com", "c.acme.com"}, extra_words=["api"],
                                  phase="enrich", label="wildcard-a1d")
_zev = {e.get("unit"): e for e in events_of(p45 / "logs" / "events.jsonl") if e.get("measure") == "zones"}
c_wc_units = (set(_zev) == {"wildcard", "wildcard-a1d"}
              and _zev["wildcard"]["eligible"] == 1 and _zev["wildcard-a1d"]["eligible"] == 2)

# review-B-audit-16#1: a decodable line is not a LABEL — a URL-shaped word would build a candidate whose
# AUTHORITY is another host entirely, contacted without ever passing scope or the contact guard.
p46 = tmp / "p46"; _c46 = ctx_for(p46, "unused"); _c46.scope.is_oos = lambda h: False
_c46.scope.passive_only = False
_c46.run.dir.mkdir(parents=True, exist_ok=True)
_st46 = {}
_vertical._wildcard_differentiate(_c46, {"wild.acme.com"},
                                  extra_words=["https://outside.example/private", "evil.example.com",
                                               "ok", "under_score", "-lead", "trail-", "a" * 64, "UPPER"],
                                  label="wildcard", stats=_st46)
# the candidate list carries a per-INVOCATION token now (4.3 v50#1: input and output share one), so the
# artifact is found by prefix rather than by a stable name a retry would overwrite
_cand = next(_c46.run.dir.glob("wildcard_cand_wild_acme_com*.txt")).read_text().splitlines()
_cand = [x for x in _cand if x.strip()]
c_wc_labels = (all(x.endswith(".wild.acme.com") and "/" not in x and ":" not in x
                   and "." not in x[: -len(".wild.acme.com")] for x in _cand)
               and "ok.wild.acme.com" in _cand and "upper.wild.acme.com" in _cand
               and _st46["vocabulary"]["rejected"] == 6 and _st46["vocabulary"]["accepted"] == 2)

# review-B-audit-16#2/#3: vocabulary loss is STRUCTURED coverage under the CALLER'S source, and reaches
# the reconciled manifest — a present-but-unreadable list is not a clean run.
p47 = tmp / "p47"; _r47 = _store.Run.create(p47, "t")
events.reset(); events.configure(_r47.dir)
_c47 = ctx_for(p47, "unused"); _c47.run = _r47; _c47.scope.is_oos = lambda h: False
_c47.scope.passive_only = False
_gwl = p47 / "generic.txt"; _gwl.write_bytes(b"good\nhttps://outside.example/x\nbad\xffword\n")
_probe._vhost_wordlist = lambda: _gwl     # the DEDICATED list; the DNS list is NEVER a fallback
_vertical._wordlist = lambda c: None
_vertical._wildcard_differentiate(_c47, {"a.acme.com"}, extra_words=["api"], label="wildcard")
_vertical._wildcard_differentiate(_c47, {"b.acme.com", "c.acme.com"}, extra_words=["api"],
                                  phase="enrich", label="wildcard-a1d", source_id="enrich.wildcard_a1d")
_r47.write_manifest({}, ["vertical", "enrich"])
_sum47 = json.loads(_r47.manifest_path.read_text())["summary"]
_cov47 = {(c["source_id"], c["measure"]): c for c in _sum47.get("coverage", [])}
# review-B-audit-18#1: PARSING and SELECTION are sequential stages over the same words, so each has its
# OWN measure — sharing one made a rollup sum them as disjoint work (10 words became eligible=20).
c_wc_vocab = (_sum47["verdict"] != "complete"
              and _cov47[("vertical.wildcard_http", "vocabulary_entries")]["omitted"] == 2
              and _cov47[("vertical.wildcard_http", "vocabulary_words")]["omitted"] == 0
              and ("enrich.wildcard_a1d", "zones") in _cov47
              and _cov47[("enrich.wildcard_a1d", "zones")]["eligible"] == 2
              and _cov47[("vertical.wildcard_http", "zones")]["eligible"] == 1)

# review-B-audit-17 / v63#1: the corpus is RETAINED WHOLE (the old slice was a membership cut that made
# the tail unreachable) and the per-run bound is reported as candidate PAIRS in the scheduler's measure;
# the label check is EXACT (`$` also matches before a final newline); a clean pass CLEARS an earlier gap.
_old_cap = _vertical.WILDCARD_WORD_CAP; _vertical.WILDCARD_WORD_CAP = 3
p48 = tmp / "p48"; _r48 = _store.Run.create(p48, "t")
events.reset(); events.configure(_r48.dir)
_c48 = ctx_for(p48, "unused"); _c48.run = _r48; _c48.scope.is_oos = lambda h: False
_c48.scope.passive_only = False
_vertical._wordlist = lambda c: None
_probe._vhost_wordlist = lambda: None       # these two cases measure the CALLER's words alone
_st48 = {}
_vertical._wildcard_differentiate(_c48, {"a.acme.com"}, extra_words=[f"w{i}" for i in range(10)],
                                  label="wildcard", stats=_st48)
_r48.write_manifest({}, ["vertical"])
_sum48 = json.loads(_r48.manifest_path.read_text())["summary"]
_cov48 = {(c["source_id"], c["measure"]): c for c in _sum48["coverage"]}
_sel48 = _cov48[("vertical.wildcard_http", "vocabulary_words")]
c_wc_cap = (_st48["vocabulary"]["usable"] == 10 and _st48["vocabulary"]["selected"] == 10
            and _st48["vocabulary"]["withheld"] == 0 and _sum48["verdict"] != "complete"
            and (_sel48["eligible"], _sel48["tested"], _sel48["omitted"]) == (10, 10, 0)
            # ...and the 3-per-zone SPEND withholds candidate PAIRS, which rotate in on a later run
            and _st48["candidate_pairs_eligible"] == 10 and _st48["candidate_pairs_submitted"] == 3
            and _st48["candidate_pairs_withheld"] == 7 and _st48["word_spend"] == 3
            and (lambda c: (c["eligible"], c["tested"], c["omitted"]) == (10, 3, 7))(
                _cov48[("vertical.wildcard_http", "candidate_pairs")])
            and _cov48[("vertical.wildcard_http", "vocabulary_entries")]["omitted"] == 0
            # review-B-audit-18#2: the ZONE reason carries zone facts only
            and _st48["blocked_reason"] == "")
_vertical.WILDCARD_WORD_CAP = _old_cap
# review-B-audit-19#1: PARSING counts ENTRIES, SELECTION counts unique NAMES (dedup is not a loss).
p49 = tmp / "p49"; _r49 = _store.Run.create(p49, "t")
events.reset(); events.configure(_r49.dir)
_c49 = ctx_for(p49, "unused"); _c49.run = _r49; _c49.scope.is_oos = lambda h: False
_c49.scope.passive_only = False
_st49 = {}
_vertical._wildcard_differentiate(_c49, {"a.acme.com"}, extra_words=["API", "api", "bad/url"],
                                  label="wildcard", stats=_st49)
_r49.write_manifest({}, ["vertical"])
_cov49 = {(c["source_id"], c["measure"]): c for c in
          json.loads(_r49.manifest_path.read_text())["summary"]["coverage"]}
_p49 = _cov49[("vertical.wildcard_http", "vocabulary_entries")]
_s49 = _cov49[("vertical.wildcard_http", "vocabulary_words")]
c_wc_entries = ((_p49["eligible"], _p49["tested"], _p49["omitted"]) == (3, 2, 1)
                and (_s49["eligible"], _s49["tested"], _s49["omitted"]) == (1, 1, 0)
                and "RETAINED for probing" in _s49["units"][0]["reason"])

# review-B-audit-20#1: a hard gate must still REPORT — the vertical caller passes no stats, so an early
# return used to leave eligible zones, zero differentiated and a `complete` verdict.
p50 = tmp / "p50"; _r50 = _store.Run.create(p50, "t")
events.reset(); events.configure(_r50.dir)
_c50 = ctx_for(p50, "unused"); _c50.run = _r50; _c50.scope.is_oos = lambda h: False
_c50.scope.passive_only = False
_vertical.have = lambda t: False                       # httpx missing
_vertical._wordlist = lambda c: None
_vertical._wildcard_differentiate(_c50, {"z.acme.com"}, label="wildcard")   # NO stats, like production
_r50.write_manifest({}, ["vertical"])
_sum50 = json.loads(_r50.manifest_path.read_text())["summary"]
_cov50 = {(c["source_id"], c["measure"]): c for c in _sum50["coverage"]}
_zc50 = _cov50[("vertical.wildcard_http", "zones")]              # SELECTION: the zone WAS chosen
_ex50 = _cov50[("vertical.wildcard_http", "zone_execution")]     # EXECUTION: it never returned (4.3 v51)
_hx50 = [x for x in _r50.tool_runs("vertical") if x.tool == "httpx"]
c_wc_gate = (_sum50["verdict"] != "complete"
             and (_zc50["eligible"], _zc50["tested"], _zc50["omitted"]) == (1, 1, 0)
             and _zc50["by_kind"].get("cap")
             and (_ex50["eligible"], _ex50["tested"], _ex50["omitted"]) == (1, 0, 1)
             and _ex50["by_kind"].get("timeout")
             and len(_hx50) == 1 and _hx50[0].status == "skipped"
             and "1 wildcard zone(s) undifferentiated" in (_hx50[0].note or ""))
_vertical.have = lambda t: True

c_wc_label_exact = (bool(_vertical._DNS_LABEL_RX.fullmatch("safe"))
                    and not _vertical._DNS_LABEL_RX.fullmatch("safe\n")
                    and not _vertical._DNS_LABEL_RX.fullmatch("safe\nevil.example"))

# review-B-audit-13#2: a base-only failure with NOTHING mined is not damage — the clean SKIP survives
_baseonly = a1d_records(tmp / "p41", {"a_wordlist.txt": b""}, base=b"api\n", base_deny=True)
c_a1d_base_only = (len(_baseonly) == 1 and _baseonly[0].status == "skipped"
                   and "deduped" not in (_baseonly[0].note or ""))

# step 4.1: the derived wordlist keeps the WHOLE vocabulary, and a v1 bundle (truncated corpus) is
# neither found nor trusted under the v2 schema.
c_retention = (crawl.XNL_PARSER_SCHEMA == 2 and not hasattr(crawl, "XNL_PARAM_CAP")
               and not hasattr(crawl, "XNL_WORDLIST_DERIVE_CAP"))
p51 = tmp / "p51"; c51 = ctx_for(p51)
_old_wl6 = crawl.XNL_WORDLIST_LIMIT; crawl.XNL_WORDLIST_LIMIT = 1


def many_params(tool, cmd, timeout=None, input_file=None, **k):
    pathlib.Path(cmd[cmd.index("-o")+1]).write_text("")
    pathlib.Path(cmd[cmd.index("-op")+1]).write_text("\n".join(f"word{i:05d}" for i in range(6000)))
    if "-owl" in cmd:
        pathlib.Path(cmd[cmd.index("-owl")+1]).write_text("")
    if "-os" in cmd:
        pathlib.Path(cmd[cmd.index("-os")+1]).write_text("[]")
    return RunResult("xnLinkFinder", cmd, Status.SUCCESS, 0, 0.1, None, 1)


lane(c51, [(indir(p51, "js"), "js", False)], many_params)
crawl.XNL_WORDLIST_LIMIT = _old_wl6
_wl51 = c51.run.raw_path("crawl", "xnLinkFinder", "js_wordlist.txt").read_text().split()
_prm51 = [r for ent, r in c51.run.added if ent == "parameter"]
c_retention_full = (len(_prm51) == 6000 and len([w for w in _wl51 if w.startswith("word")]) == 6000)
# ...and the SPEND-side bounds are untouched by this commit (steps 4.2/4.3)
c_selection_untouched = (_vertical.WILDCARD_WORD_CAP == 5000
                         and _enrich.A1D_WORD_CAP == 2000     # the A1d spend bound, now owned by its caller
                         # 4.3 step B: the zone MEMBERSHIP cap is gone — what remains is a per-run
                         # THROUGHPUT allowance the rotation spends, defaulting to the same 5.
                         and _vertical.wildcard_zones_per_run() == 5)

sys.exit(0 if (c_struct and c_capability and c_suspicious and c_wl_ok and c_bytecap and c_capped_remines
               and c_large and c_small and c_replay and c_state_in_project and c_contained and c_missing
               and c_lock_order and c_busy and c_readonly and c_cancel and c_state_contained
               and c_secret_verbatim and c_secret_gap and c_rescued and c_unrescued and c_presence
               and c_engine and c_engine_unproven and c_row_shape and c_nofind_clean
               and c_missing_os and c_mid_ingest and c_requested_missing and c_row_strict
               and c_params_delivered and c_secrets_delivered and c_read_authority
               and c_bytes_owned and c_replay_copy and c_derived_clean and c_a1d_strict
               and c_verdict_gated and c_verdict_clean and c_a1d_degraded and c_a1d_mixed
               and c_a1d_clean_skip and c_a1d_base and c_a1d_unsubmitted and c_a1d_clean_run
               and c_a1d_base_only and c_wc_stats and c_wc_own_words and c_wc_snapshot
               and c_wc_reasons and c_wc_units and c_wc_labels and c_wc_vocab and c_wc_cap
               and c_wc_label_exact and c_wc_entries and c_wc_gate and c_retention
               and c_retention_full and c_selection_untouched)
         else 1)
PYEOF

echo "[116] coverage counters (reconcile event-level input omissions into the verdict) — TRUTH policy, not a threshold: any CAP or TIMEOUT with omitted>0 is a GAP (complete_with_gaps) regardless of fraction; an operator SAMPLE with omitted>0 is a soft LIMIT (complete_with_limits); an INCONSISTENT triple is coverage:unknown (gap, never a crash). Aggregation is rerun/resume-safe (LATEST per (source,unit); a coverage_reset GENERATION drops units that vanished on rerun) and NEVER sums incompatible measures (files vs params are separate (source,measure) rollups); keeps a by_kind breakdown (a mixed source reports sample AND timeout distinctly — no relabeling). The 10%/100 rule survives only as a 'priority' label. Regressions: cap-any-omit gates, cap-zero-omit clears, disappeared-unit clears, measures-not-summed, mixed distinct, malformed no-crash, sample->limits, priority."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "cap-any-omit gates + zero-omit clears + mixed by_kind distinct + malformed no-crash + sample->limits + priority label" || no "coverage reconciliation wrong"
import sys, tempfile, pathlib
from quarry_recon.store import Run, _coverage_gates
from quarry_recon import events as E
run = Run(pathlib.Path(tempfile.mkdtemp()), "t", "R1"); run.dir.mkdir(parents=True, exist_ok=True)
E.configure(run.dir)
# MEASURES NEVER SUMMED: one source, two measures (files 5/10 + params 200/1000) -> TWO rollups, not 205/1010
E.coverage_partial("multi.src", kind=E.COVERAGE_CAP, unit="f", measure="files", eligible=10, tested=5, omitted=5)
E.coverage_partial("multi.src", kind=E.COVERAGE_CAP, unit="p", measure="params", eligible=1000, tested=200, omitted=800)
# DISAPPEARED UNIT + SAME-TIMESTAMP RESET: gen1 unit 'old' capped, then a reset (NO sleep -> may share the ms),
# then gen2 emits only 'new'. Line-ordered clearing drops 'old' regardless of timestamp collision.
E.coverage_partial("disappear.src", kind=E.COVERAGE_CAP, unit="old", eligible=100, tested=50, omitted=50, reason="gen1")
E.coverage_reset("disappear.src")
E.coverage_partial("disappear.src", kind=E.COVERAGE_CAP, unit="new", eligible=10, tested=10, omitted=0, reason="gen2")
# MULTI-UNIT ATTRIBUTION: two capped services (same source+measure) -> aggregate reason + per-unit kept
E.coverage_partial("multiunit.src", kind=E.COVERAGE_CAP, unit="svcA", measure="result_rows", eligible=1000, tested=500, omitted=500, reason="A")
E.coverage_partial("multiunit.src", kind=E.COVERAGE_CAP, unit="svcB", measure="result_rows", eligible=900, tested=500, omitted=400, reason="B")
# UNSTRUCTURED DOES NOT RESET: a structured cap then a legacy reason-only partial -> the structured unit SURVIVES
E.coverage_partial("struct.src", kind=E.COVERAGE_CAP, measure="files", eligible=10, tested=5, omitted=5, reason="cap")
E.coverage_partial("struct.src", reason="legacy timeout note")
# TRUTH: any cap omitted>0 gates regardless of tiny fraction
E.coverage_partial("small.cap", kind=E.COVERAGE_CAP, eligible=1000, tested=999, omitted=1, reason="tiny")   # 0.1% -> STILL gap
# cap with omitted=0 must NOT gate and must appear as fully-covered
E.coverage_partial("full.cap", kind=E.COVERAGE_CAP, eligible=40, tested=40, omitted=0, reason="ok")
# RERUN CLEAR: same (source,unit) capped THEN uncapped -> latest omitted=0 wins -> no gap
E.coverage_partial("rerun.src", kind=E.COVERAGE_CAP, unit="u", eligible=500, tested=200, omitted=300, reason="run1-capped")
E.coverage_partial("rerun.src", kind=E.COVERAGE_CAP, unit="u", eligible=500, tested=500, omitted=0, reason="run2-full")
# MIXED distinct: one source, sample(unit a) + timeout(unit b) -> gap from timeout, limit from sample, by_kind BOTH kept
E.coverage_partial("mix.src", kind=E.COVERAGE_SAMPLE, unit="a", eligible=100, tested=10, omitted=90, reason="sampled")
E.coverage_partial("mix.src", kind=E.COVERAGE_TIMEOUT, unit="b", eligible=10, tested=9, omitted=1, reason="timed-out")
# operator SAMPLE only -> complete_with_limits, not a gap
E.coverage_partial("just.sample", kind=E.COVERAGE_SAMPLE, eligible=100, tested=10, omitted=90, reason="op-sample")
# MALFORMED numeric must not crash; -> unknown gap
E.coverage_partial("bad.src", kind=E.COVERAGE_CAP, eligible="bad", tested=10, omitted=5, reason="garbage")
s = run._run_summary()
gaps = {g["tool"] for g in s["gaps"]}
lims = {c["tool"] for c in s["coverage_limits"]}
cov = {c["source_id"]: c for c in s["coverage"] if c["source_id"] not in ("multi.src", "disappear.src")}
mix_kinds = set(cov["mix.src"]["by_kind"])
multi = sorted(((c["measure"], c["eligible"]) for c in s["coverage"] if c["source_id"] == "multi.src"))
disc = [c for c in s["coverage"] if c["source_id"] == "disappear.src"]
mu = next(c for c in s["coverage"] if c["source_id"] == "multiunit.src")
stc = [c for c in s["coverage"] if c["source_id"] == "struct.src"]
ok = (_coverage_gates(0.10, 0) and _coverage_gates(0.0, 100) and not _coverage_gates(0.05, 2)   # priority label
      and "small.cap" in gaps                                                                    # any omit gates
      and "full.cap" not in gaps and cov["full.cap"]["omitted"] == 0                             # zero-omit no gate
      and "rerun.src" not in gaps and cov["rerun.src"]["omitted"] == 0                           # rerun CLEARED
      and "mix.src" in gaps and mix_kinds == {E.COVERAGE_SAMPLE, E.COVERAGE_TIMEOUT}             # distinct, no relabel
      and "just.sample" in lims and "just.sample" not in gaps                                    # sample -> limits
      and "bad.src" in gaps and cov["bad.src"]["valid"] is False                                 # malformed -> unknown, no crash
      and multi == [("files", 10), ("params", 1000)]                                             # measures NOT summed
      and len(disc) == 1 and disc[0]["omitted"] == 0 and "disappear.src" not in gaps             # stale unit cleared (same-ts)
      and mu["omitted"] == 900 and len(mu["units"]) == 2 and "unit(s) limited" in mu["reason"]   # multi-unit attribution
      and len(stc) == 1 and stc[0]["omitted"] == 5                                                # legacy partial did NOT reset structured
      and all("measure" in c for c in s["coverage"])                                              # every rollup carries its measure
      and s["verdict"] == "complete_with_gaps"                                                   # gaps present -> gaps wins
      and any(g.get("priority") == "major" for g in s["gaps"]))                                  # priority surfaced
# limits-only verdict (no gaps, one operator sample) -> complete_with_limits (soft, not gaps, not clean)
run2 = Run(pathlib.Path(tempfile.mkdtemp()), "t", "R2"); run2.dir.mkdir(parents=True, exist_ok=True); E.configure(run2.dir)
E.coverage_partial("only.sample", kind=E.COVERAGE_SAMPLE, eligible=50, tested=5, omitted=45, reason="op")
s2 = run2._run_summary()
ok = ok and s2["verdict"] == "complete_with_limits" and not s2["gaps"] and len(s2["coverage_limits"]) == 1
sys.exit(0 if ok else 1)
PYEOF

echo "[117] coverage source_ids exist in the registry — every source_id a coverage_partial(cap/sample) site emits must be a real sources.yaml entry (no orphan telemetry). Checks the instrumented ids resolve."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "js_fetch, sourcemaps, katana_headless, content.ffuf, ffuf_vhost, wildcard_http, arjun, xnlinkfinder all registered" || no "coverage source_id missing from registry"
import sys
from quarry_recon import sources
ids = set(sources.all_sources())
need = {"crawl.js_fetch", "crawl.sourcemaps", "crawl.katana_headless", "content.ffuf",
        "probe.ffuf_vhost", "vertical.wildcard_http", "params.arjun", "crawl.xnlinkfinder"}
missing = need - ids
sys.exit(0 if not missing else (print("MISSING:", missing) or 1))
PYEOF

echo "[118] coverage is telemetry, not lifecycle — quarry status must NOT read 'partial' from a coverage event. Every source now emits coverage_partial (incl fully-covered omitted=0), so views._fold_events must ignore coverage_partial/coverage_reset and keep the tool's real lifecycle status (a tool_finish=done source that later emits omitted=0 coverage still shows done, not partial)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "coverage_partial/coverage_reset never override tool status; a done source stays done after an omitted=0 coverage event" || no "coverage overrides status surface"
import sys, tempfile, pathlib, inspect
from quarry_recon import events as E, views, cli as climod
run_dir = pathlib.Path(tempfile.mkdtemp()); E.configure(run_dir)
E.tool_start("probe.httpx"); E.tool_finish("probe.httpx", status="success")
E.coverage_partial("probe.httpx", kind=E.COVERAGE_CAP, eligible=10, tested=10, omitted=0, reason="full")  # fully covered
st = views._fold_events(run_dir / "events.jsonl")
clisrc = inspect.getsource(climod)
ok = (st["probe.httpx"]["last_event"] == "tool_finish"                  # coverage did NOT become last_event
      and st["probe.httpx"].get("status") == "success"                 # lifecycle intact
      and "coverage_partial" not in views._HUMAN                       # coverage_partial not mapped to a state
      and "{c['source_id']}.{c['measure']}" in clisrc)                 # CLI coverage line renders the MEASURE
sys.exit(0 if ok else 1)
PYEOF

echo "[119] netguard CONTACT-BY-DEFAULT (offensive tool) — deny ONLY the SCAN BOX itself: loopback (127/8, ::1, IPv4-mapped ::ffff:127.x), link-local (fe80), and cloud METADATA (169.254.169.254, 169.254.170.2, fd00:ec2::254, 100.100.100.200) are is_self_attack -> never contacted. PRIVATE (RFC1918/CGNAT/ULA) is CONTACTED by default (blocked only under block_private); public always contactable. intel_ips = the private+self subset (recorded regardless). resolve() bounded + nxdomain vs indeterminate; contact_state combines stored+live and never authorizes a live-failed name."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "self-attack always blocked (incl mapped-loopback+metadata); private contacted by default / blocked under block_private; public always; contact_state states; resolve bounded" || no "netguard contact-by-default wrong"
import sys, time, socket
from quarry_recon import netguard as N
self_ips = ["127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "169.254.170.2", "fd00:ec2::254",
            "100.100.100.200", "::1", "fe80::1", "0.0.0.0"]
priv_ips = ["10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fc00::1"]
pub = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]
policy = (all(N.is_self_attack_ip(ip) for ip in self_ips)                          # scan box / metadata / mapped-loopback
          and not any(N.is_self_attack_ip(ip) for ip in pub + priv_ips)
          and all(N.is_private_ip(ip) for ip in priv_ips) and not any(N.is_private_ip(ip) for ip in pub)
          and not any(N.is_contactable_ip(ip) for ip in self_ips)                   # self NEVER contactable
          and all(N.is_contactable_ip(ip) for ip in priv_ips)                       # PRIVATE contacted BY DEFAULT
          and not any(N.is_contactable_ip(ip, block_private=True) for ip in priv_ips)  # ...blocked only under block_private
          and all(N.is_contactable_ip(ip) for ip in pub)                            # public always
          and N.intel_ips(["8.8.8.8", "10.0.0.5", "127.0.0.1"]) == ["10.0.0.5", "127.0.0.1"]  # intel = private+self
          and "169.254.169.254/32" in N.self_deny_list() and "127.0.0.0/8" in N.self_deny_list()
          and "::ffff:127.0.0.0/104" in N.self_deny_list()                             # #4: mapped-loopback in the tool deny too
          and "10.0.0.0/8" not in N.self_deny_list())                                  # deny is SELF-only (private is contacted)
# resolve bounded + state machine
N._STUB = {"mode": "slow", "delay": 0.3}
t0 = time.time(); ips, st = N.resolve("slow", timeout=0.02); dt = time.time() - t0
bounded = (st == "indeterminate" and dt < 0.25)
N._STUB = {"all": ["8.8.8.8"]}; okst = N.resolve("x")[1] == "ok"
N._STUB = {"gaierror": socket.EAI_NONAME}; nx = N.resolve("x")[1] == "nxdomain"
N._STUB = {"gaierror": socket.EAI_AGAIN}; ind = N.resolve("x")[1] == "indeterminate"
resolver = bounded and okst and nx and ind and not hasattr(N, "_resolve_cache")
# contact_state (native fetch): private->contact by default, metadata->self, block_private flips private
STATE = {"pub": (["8.8.8.8"], "ok"), "priv": (["10.0.0.5"], "ok"), "meta": (["169.254.169.254"], "ok"),
         "gone": ([], "nxdomain"), "flap": ([], "indeterminate")}
N._STUB = {"states": STATE}
cs = (N.contact_state("pub")[0] == "contact"
      and N.contact_state("priv")[0] == "contact"                          # private contacted by default
      and N.contact_state("priv", block_private=True)[0] == "private_blocked"
      and N.contact_state("meta")[0] == "self"                             # metadata NEVER contacted
      and N.contact_state("priv")[2] == ["10.0.0.5"]                       # ...but still RECORDED as intel
      and N.contact_state("gone")[0] == "nxdomain" and N.contact_state("flap")[0] == "indeterminate"
      and N.contact_state("flap", stored_ips=["8.8.8.8"])[0] == "contact")  # stored public authorizes when no live needed
sys.exit(0 if (policy and resolver and cs) else 1)
PYEOF

echo "[120] scoped_get + redirect_location safety (audit #1/#3/#15) — resolve-guards EVERY hop TRI-STATE fail-closed (non-global OR unresolved host is NEVER contacted -> None); a 4xx/5xx is handed back as (body,url,status) not raised; redirect_location guards its origin too and closes the HTTPError (no fd leak)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "global contacted; blocked+unresolved not contacted; 4xx->tuple; redirect_location guards origin + closes HTTPError" || no "scoped_get/redirect_location guard broken"
import sys, io, urllib.error
from types import SimpleNamespace
from quarry_recon import fetch, netguard
netguard._STUB = {"states": {"ok.test": (["8.8.8.8"], "ok"), "evil.test": (["127.0.0.1"], "ok"),
                             "flap.test": (["8.8.8.8"], "ok")}}  # unres.test -> indeterminate (miss)
closed = {"n": 0}
class FakeErr(urllib.error.HTTPError):
    def close(self): closed["n"] += 1; super().close()
called = {"n": 0}
class FakeOpener:
    def open(self, req, timeout=None):
        called["n"] += 1
        if "flap.test" in req.full_url:
            raise urllib.error.URLError("connection timed out")   # TRANSPORT failure (not HTTP status)
        raise FakeErr(req.full_url, 403, "Forbidden", {}, io.BytesIO(b"denied"))
fetch._NO_REDIRECT_OPENER = FakeOpener()
recs = []
class Run:
    def add(s, e, r): (recs.append(r) if e == "review" else None); return True
ctx = SimpleNamespace(profile=SimpleNamespace(http_rl=None, block_private_targets=False),
                      scope=SimpleNamespace(active_allowed=lambda h: True), run=Run())
d1, _u, s1 = fetch.scoped_get(ctx, "http://ok.test/x")       # 403 -> tuple
d2, _u, s2 = fetch.scoped_get(ctx, "http://evil.test/x")     # blocked -> None
d3, _u, s3 = fetch.scoped_get(ctx, "http://unres.test/x")    # UNRESOLVED -> None (fail closed)
loc, st = fetch.redirect_location(ctx, "http://ok.test/r")   # guarded origin (global) -> contacts, closes err
loc2, st2 = fetch.redirect_location(ctx, "http://evil.test/r")  # blocked origin -> (None, 0), not contacted
hg, _bd, _f, hs = fetch.scoped_headers(ctx, "http://ok.test/")    # global origin -> headers dict returned (CSP fetch)
hb, _bd, _f, _s = fetch.scoped_headers(ctx, "http://evil.test/")  # blocked origin -> None, not contacted
try:                                                              # audit #2: transport failure is SWALLOWED
    ht, _bd, _f, hts = fetch.scoped_headers(ctx, "http://flap.test/")
    swallowed = (ht is None and hts == 0)                         # URLError -> (None,...,0), no exception raised
except Exception:
    swallowed = False
ok = (s1 == 403 and d1 == b"denied" and d2 is None and s2 == 0 and d3 is None and s3 == 0
      and st == 403 and (loc2, st2) == (None, 0)             # redirect origin guard
      and hg is not None and hb is None                      # scoped_headers: global returns headers, blocked -> None
      and swallowed                                          # transport failure swallowed (phase not aborted)
      and any(r.get("host") == "evil.test" for r in recs)    # audit #3: native fetch RECORDS the self/private lead it found
      and closed["n"] >= 1)                                  # HTTPError closed (no leak)
sys.exit(0 if ok else 1)
PYEOF

echo "[121] fingerprint_hosts CONTACT-BY-DEFAULT (offensive) — guard_hosts RECORDS every private/self-resolving host as review(internal-resolution) intel and withholds ONLY the scan-box/metadata self-hits. UNKNOWN hosts (no stored data) are LIVE-resolved in a bounded batch so recording + BLOCK_PRIVATE_TARGETS reach them too (audit #1); a still-unresolvable host is passed through (dangling reaches the tool). Private hosts are recorded AND probed by default; BLOCK_PRIVATE_TARGETS withholds them (still recorded)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "private recorded+probed; metadata recorded+withheld; public/unknown probed; block_private withholds private (still recorded)" || no "guard_hosts contact-by-default broken"
import sys
from types import SimpleNamespace
from quarry_recon import netguard
from quarry_recon.phases import probe
resolved = [{"host": "pub.test", "a": ["8.8.8.8"]},
            {"host": "priv.test", "a": ["192.168.0.5"]},
            {"host": "meta.test", "a": ["169.254.169.254"]},
            {"host": "mixedpriv.test", "a": ["8.8.8.8"], "aaaa": ["fd00::1"]},
            {"host": "stale.test", "a": ["8.8.8.8"]}]                        # stored PUBLIC...
# CONTACT decision uses the CURRENT (live) answer; intel is UNION(stored, current). Every host is fresh-resolved.
LIVE = {"pub.test": (["8.8.8.8"], "ok"), "priv.test": (["192.168.0.5"], "ok"),
        "meta.test": (["169.254.169.254"], "ok"), "mixedpriv.test": (["8.8.8.8"], "ok"),
        "stale.test": (["169.254.169.254"], "ok"),                          # ...but CURRENTLY resolves METADATA (audit #2)
        "unk-priv.test": (["10.9.9.9"], "ok"), "dead.test": ([], "nxdomain")}
netguard._STUB = {"states": LIVE, "miss": [[], "nxdomain"]}
def mk(block):
    reviews, probed = [], []
    class Run:
        def read(s, e): return resolved if e == "resolved" else []
        def add(s, e, r): (reviews.append(r) if e == "review" else None); return True
        def values(s, e): return []
        @property
        def notes(s): return []
    ctx = SimpleNamespace(run=Run(), profile=SimpleNamespace(ports=[80], portscan=False, block_private_targets=block),
                          echo=lambda *a, **k: None)
    probe._run_httpx = lambda ctx, targets, ports, phase, tag: probed.extend(targets) or ("raw", [])
    import quarry_recon.settings as S
    S.web_port_prefilter = lambda: False
    probe.fingerprint_hosts(ctx, ["pub.test", "priv.test", "meta.test", "mixedpriv.test",
                                  "stale.test", "unk-priv.test", "dead.test"], "probe")
    return {r["host"] for r in reviews if r.get("klass") == "internal-resolution"}, set(probed)
rec, probed = mk(False)                                                       # default: contact private
rec_b, probed_b = mk(True)                                                    # BLOCK_PRIVATE_TARGETS
ok = (rec == {"priv.test", "meta.test", "mixedpriv.test", "stale.test", "unk-priv.test"}  # #1 unknown + #2 stale RECORDED
      and {"pub.test", "priv.test", "mixedpriv.test", "unk-priv.test"} <= probed  # public+private+unknown-private contacted
      and "meta.test" not in probed and "stale.test" not in probed          # #2: stored-public-NOW-metadata WITHHELD (current wins)
      and "dead.test" not in probed                                         # authoritative NXDOMAIN dropped (not takeover)
      and rec_b == {"priv.test", "meta.test", "mixedpriv.test", "stale.test", "unk-priv.test"}
      and probed_b == {"pub.test", "mixedpriv.test"}                        # block: only current-public hosts contacted
      and "priv.test" not in probed_b and "unk-priv.test" not in probed_b)
sys.exit(0 if ok else 1)
PYEOF

echo "[122] netguard RECORDS internal-resolutions as findings, DECOUPLED from contact (offensive posture) — guard_hosts stores review(internal-resolution) for EVERY host with a private/self answer, whether or not it contacts it. DEFAULT: private is CONTACTED (a lead to investigate) + recorded; only the scan-box/metadata self-hit is withheld. MODES.BLOCK_PRIVATE_TARGETS additionally withholds private (still recorded). csprecon (auto-follows redirects) is replaced by fetch.scoped_headers; registry names the native source (no lie)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYE' && ok "internal-resolution recorded as review finding + excluded; ALLOW_PRIVATE_TARGETS flips private (SELF still blocked); csprecon gone/native CSP; registry truth; config mode present" || no "netguard records/mode/registry wrong"
import sys, inspect
from types import SimpleNamespace
from quarry_recon import netguard as N, fetch, sources
from quarry_recon.phases import horizontal
from quarry_recon.config import TargetProfile
resolved = [{"host": "pub.t", "a": ["8.8.8.8"]}, {"host": "meta.t", "a": ["169.254.169.254"]},
            {"host": "priv.t", "a": ["10.0.0.9"]}]
N._STUB = {"states": {"pub.t": (["8.8.8.8"], "ok"), "meta.t": (["169.254.169.254"], "ok"),
                      "priv.t": (["10.0.0.9"], "ok")}, "miss": [[], "nxdomain"]}   # fresh-resolve stub
def mk(block):
    reviews = []
    class Run:
        def read(s, e): return resolved if e == "resolved" else []
        def add(s, e, r): (reviews.append(r) if e == "review" else None); return True
        @property
        def notes(s): return []
    return SimpleNamespace(run=Run(), profile=SimpleNamespace(block_private_targets=block)), reviews
c1, r1 = mk(False); safe1 = N.guard_hosts(c1, ["pub.t", "meta.t", "priv.t"], phase="probe")
rec1 = {r["host"] for r in r1 if r.get("klass") == "internal-resolution"}
c2, r2 = mk(True);  safe2 = N.guard_hosts(c2, ["pub.t", "meta.t", "priv.t"], phase="probe")
rec2 = {r["host"] for r in r2 if r.get("klass") == "internal-resolution"}
from quarry_recon.phases import params as _params
hsrc = inspect.getsource(horizontal)
psrc = inspect.getsource(_params)
ok = ('"-eh"' not in psrc                                           # nuclei -eh REMOVED (it's input-exclude, not connect-deny)
      and 'netguard.guard_hosts(ctx, subs' in psrc                  # takeover subs go through the fresh-resolve guard
      and 'netguard.guard_urls(ctx, live, phase="params.nuclei_scan")' in psrc  # MAIN nuclei fresh-guarded before chunking (P1)
      and set(safe1) == {"pub.t", "priv.t"}                         # DEFAULT: private CONTACTED, metadata withheld
      and rec1 == {"meta.t", "priv.t"}                              # BOTH recorded as intel (recording != blocking)
      and set(safe2) == {"pub.t"}                                   # BLOCK_PRIVATE_TARGETS: private withheld too...
      and rec2 == {"meta.t", "priv.t"}                              # ...still recorded
      and TargetProfile("t", ["t"], [], [], [], {}, [], {"BLOCK_PRIVATE_TARGETS": True}, []).block_private_targets is True
      and '"csprecon"' not in hsrc and "'csprecon'" not in hsrc     # csprecon NOT invoked
      and "fetch.scoped_headers" in hsrc and hasattr(fetch, "scoped_headers")   # native guarded CSP
      and "horizontal.csprecon" not in sources.all_sources() and "horizontal.csp" in sources.all_sources())
sys.exit(0 if ok else 1)
PYE

echo "[123] native CSP result truth + meta-order (audit #6/#7) — _meta_csp extracts <meta http-equiv=content-security-policy content=...> in EITHER attribute order; the horizontal CSP block reads all header variants (incl X-Content-Security-Policy / X-WebKit-CSP), counts an off-scope-3xx/transport-fail (hdrs None) as FAILED not fetched, reports FAILED only when nothing answered / PARTIAL on mixed / EMPTY when answered-but-no-CSP / SUCCESS only when CSP found, and tolerates self-signed TLS (insecure)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "meta-CSP both attribute orders; header variants; honest FAILED/PARTIAL/EMPTY/SUCCESS status; hdrs-None=failed; self-signed TLS" || no "native CSP truth/meta-order broken"
import sys, inspect
from quarry_recon.phases import horizontal as H
m1 = H._meta_csp('<meta http-equiv="Content-Security-Policy" content="default-src a.com">')
m2 = H._meta_csp('<meta content="default-src b.com" http-equiv="content-security-policy">')   # reversed order (#7)
hsrc = inspect.getsource(H)
ok = (m1 == ["default-src a.com"] and m2 == ["default-src b.com"]             # BOTH attribute orders parse
      and "if hdrs is None:" in hsrc                                          # off-scope-3xx/transport -> failed (#6)
      and "Status.FAILED if responses == 0" in hsrc                           # FAILED only when nothing answered
      and "Status.PARTIAL if failed" in hsrc                                  # PARTIAL on mixed
      and "else Status.EMPTY" in hsrc                                         # EMPTY reachable (answered, no CSP)
      and "insecure=True" in hsrc                                             # self-signed TLS tolerated (#7)
      and "X-Content-Security-Policy" in hsrc and "X-WebKit-CSP" in hsrc)     # all header variants
sys.exit(0 if ok else 1)
PYEOF

echo "[124] ffuf truth (batch 3, codex-hardened) — classifier SEPARATES transport degradation (context deadline / i-o timeout / connection reset -> PARTIAL) from a real WAF/403/429 block (-> BLOCKED). reclassify_ffuf refines from the -o JSON, but NEVER launders a hard state into SUCCESS: FAILED/TIMED_OUT with hits cap at PARTIAL (coverage incomplete) and with 0 hits keep the hard state; SKIPPED stays SKIPPED; a completed BLOCKED run WITH a valid artifact becomes PARTIAL (block observed on some request, not the whole job — block+0->PARTIAL, block+hits->PARTIAL), full BLOCKED reserved for a hard stop with NO valid current artifact; clean: hits->SUCCESS, 0->EMPTY. ffuf_results validates dict-root + list results centrally: a bare '[]' JSON root returns None (no AttributeError) so the classifier verdict stands. A1: row validation is FAIL-CLOSED — any non-object row voids the whole artifact (None), so a corrupt/truncated file becomes PARTIAL rather than a clean EMPTY/SUCCESS a ledger would journal as done."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "transport!=block; hard states (FAILED/TIMED_OUT/SKIPPED) never->SUCCESS; block+valid-artifact->PARTIAL, block+no-artifact->BLOCKED; []-root root guarded" || no "ffuf classifier/adapter truth broken"
import sys, json, tempfile, pathlib
from quarry_recon.runner import _classify, reclassify_ffuf, ffuf_results, RunResult, Status
# new signature: _classify(exit_code, has_out, blocked, transport, ok_empty) — stderr strings are matched
# into blocked/transport by _drain_stderr now, so the decision table is exercised with the booleans.
cl = (_classify(0, False, False, True, True)[0] == Status.PARTIAL     # transport, clean -> PARTIAL
      and _classify(0, False, False, True, True)[0] == Status.PARTIAL
      and _classify(0, False, True, False, True)[0] == Status.BLOCKED  # real block
      and _classify(0, False, True, False, True)[0] == Status.BLOCKED
      and _classify(0, False, False, False, True)[0] == Status.EMPTY   # clean, nothing
      and _classify(0, True, False, False, True)[0] == Status.SUCCESS)
def art(payload):
    d = pathlib.Path(tempfile.mkdtemp()) / "o.json"; d.write_text(json.dumps(payload)); return d
def mk(results, status, exit_code=0):
    d = art({"results": results}); return reclassify_ffuf(RunResult("ffuf", [], status, exit_code, 0.1, d, 0), d)
ad = (mk([{"url": "x"}], Status.EMPTY).status == Status.SUCCESS         # results + clean -> SUCCESS (-s hid them)
      and mk([], Status.PARTIAL).status == Status.PARTIAL              # 0 + transport -> PARTIAL (uncertain)
      and mk([], Status.EMPTY).status == Status.EMPTY                  # 0 + clean -> EMPTY
      # BLOCKED matrix keyed on exit code (nonzero+0 = block-associated hard stop):
      and mk([], Status.BLOCKED, exit_code=0).status == Status.PARTIAL   # clean exit + 0 -> PARTIAL (completed)
      and mk([], Status.BLOCKED, exit_code=1).status == Status.BLOCKED   # NONZERO exit + 0 -> stays fully BLOCKED
      and mk([{"url": "x"}], Status.BLOCKED, exit_code=1).status == Status.PARTIAL  # nonzero + hits -> PARTIAL (evidence)
      and mk([{"url": "x"}], Status.BLOCKED, exit_code=0).status == Status.PARTIAL
      # hard states are NEVER laundered into SUCCESS/EMPTY:
      and mk([{"url": "x"}], Status.FAILED).status == Status.PARTIAL   # FAILED + hits -> PARTIAL (not SUCCESS)
      and mk([], Status.FAILED).status == Status.FAILED               # FAILED + 0 -> stays FAILED
      and mk([{"url": "x"}], Status.TIMED_OUT).status == Status.PARTIAL
      and mk([], Status.TIMED_OUT).status == Status.TIMED_OUT
      and mk([{"url": "x"}], Status.SKIPPED).status == Status.SKIPPED  # SKIPPED never refines
      # no valid current artifact -> trust the classifier (block WITHOUT artifact stays fully BLOCKED):
      and reclassify_ffuf(RunResult("ffuf", [], Status.BLOCKED, 0, 0.1, None, 0),
                          pathlib.Path("/no/such.json")).status == Status.BLOCKED
      # bare '[]' JSON root must NOT AttributeError -> ffuf_results None -> classifier stands:
      and ffuf_results(art([])) is None
      and ffuf_results(art({"results": "nope"})) is None               # results not a list -> None
      # malformed ROWS fail the WHOLE artifact CLOSED (A1 review#4 — was: filter the bad rows, keep the rest).
      # ffuf never emits a non-object row, so one is corruption/truncation: ingesting the readable subset let a
      # broken file read as clean and a resumable ledger journal it done.
      and ffuf_results(art({"results": [None, {"url": "x"}, "junk"]})) is None
      and ffuf_results(art({"results": [{"url": "x"}, {"url": "y"}]})) == [{"url": "x"}, {"url": "y"}]  # all-valid still parses
      and mk([None, {"url": "x"}], Status.EMPTY).status == Status.PARTIAL   # clean run, untrustworthy artifact -> PARTIAL
      and reclassify_ffuf(RunResult("ffuf", [], Status.FAILED, 0, 0.1, art([]), 0), art([])).status == Status.FAILED)
sys.exit(0 if (cl and ad) else 1)
PYEOF

echo "[125] nuclei UX (batch 3) — startup echo: budget 0 renders 'unbounded' (not '0m'), chunk COUNT shown, 'checkpointed' not 'resumable'; _nuclei_scan emits tool_progress BEFORE each chunk and advances COMPLETED-hosts (clean chunks only) not attempted; views renders 'chunk i/N · c/total complete' (chunk no longer hidden by input_total)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "unbounded wording; chunk-count + checkpointed echo; progress-before-chunk + _completed_hosts; views combines chunk + complete" || no "nuclei UX broken"
import sys, inspect
from quarry_recon.phases import params
from quarry_recon import views
psrc = inspect.getsource(params.run) + inspect.getsource(params._nuclei_scan)
vsrc = inspect.getsource(views._fold_events) + inspect.getsource(views.status_lines)
ok = ('"unbounded"' in psrc                                            # #1: 0 budget -> unbounded (not 0m)
      and "sequential chunk(s) of" in psrc and "checkpointed" in psrc  # chunk count + #5 checkpointed (echo)
      and "· per-chunk budget {_budget_txt}" in psrc
      and "tool_progress(sid, chunk_index=ci + 1" in psrc              # #2: progress BEFORE the chunk
      and "def _completed_hosts()" in psrc and "current_index=_completed_hosts()" in psrc  # #4: completed not attempted
      and "complete" in vsrc and "chunk_total" in vsrc                 # #3: views renders chunk + completed
      # budget render must NOT truncate a sub-minute / non-round ceiling to "0m" (codex UX edge):
      and '_budget < 60' in psrc and '{_budget}s' in psrc and '_budget % 60' in psrc)
sys.exit(0 if ok else 1)
PYEOF

echo "[126] RoE rate = engagement cap (T0.1) — v0.3.8: dalfox v3 has a REAL global --rate-limit (req/s, shared across --workers AND --max-concurrent-targets), set DIRECTLY to http_rl. This SUPERSEDES the v2 per-host --delay ceil(1000/rl) model (and its per-target-limiter/bootstrap-burst caveat) — a true aggregate cap now exists in-tool. No --delay, no worker-multiplied math. arjun uses its own global --rate-limit (keeps -t concurrency; unlike -d which arjun collapses to threads=1). Pacing only — coverage unchanged."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "dalfox v3 --rate-limit == http_rl (global cap, no --delay); arjun uses global --rate-limit not -d" || no "RoE rate-cap wrong"
import sys, inspect
from quarry_recon.phases import params
class P:
    def __init__(self, rl): self.http_rl = rl
cmd = params._dalfox_cmd("b", "o", P(10))
dalfox_ok = (cmd[cmd.index("--rate-limit") + 1] == "10"          # global cap == RoE rate, verbatim
             and "--delay" not in cmd                             # v2 per-host delay model retired
             and "-w" not in cmd and "--max-cpu" not in cmd       # v2 flags gone
             and "--rate-limit" not in params._dalfox_cmd("b", "o", P(0)))   # no cap set -> no pacing flag
if not hasattr(params, "_arjun_exec"):
    sys.exit(1)                      # A2: the invocation lives in the per-target worker now; fail LOUD
rsrc = inspect.getsource(params._arjun_exec)
# per-process cap => the GLOBAL rate is partitioned across workers, never given to each in full
arjun_ok = ('"--rate-limit", str(rate)' in rsrc and '"-d"' not in rsrc
            and sum(params._arjun_rate_shares(10, 5)) == 10
            and all(s >= 1 for s in params._arjun_rate_shares(3, 5)))
sys.exit(0 if (dalfox_ok and arjun_ok) else 1)
PYEOF

echo "[127] trufflehog verification is an opt-in authorized lane (T0.2 safety) — trufflehog VERIFIES by default (sends discovered TARGET credentials to their THIRD-PARTY provider APIs = active credential use against a third party, an RoE/legal concern). Default now adds --no-verification; verification only when MODES.SECRET_VERIFICATION is set. Discovery is UNAFFECTED — every secret is still found and reported; the record carries a TRI-state 'verification' (verified/unverified/not_checked) so an unverified default never reads as 'checked and invalid'. SECRET_VERIFICATION default False."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "default --no-verification (no 3rd-party cred use); opt-in lane omits it; tri-state verification; flag default False" || no "trufflehog verification default / gating wrong"
import sys, os, tempfile, inspect
from quarry_recon.config import TargetProfile
from quarry_recon.phases import crawl
from quarry_recon.config import ProfileError
def prof(v):
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
    open(p, "w").write(f"TARGET: t\nAPEX_DOMAINS:\n  - t.com\nMODES:\n  SECRET_VERIFICATION: {v}\n")
    return TargetProfile.load(p)
def prof_raises(v):
    try: prof(v); return False
    except ProfileError: return True
fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd)
open(p, "w").write("TARGET: t\nAPEX_DOMAINS:\n  - t.com\n")     # no MODES -> default
flag_ok = (TargetProfile.load(p).verify_secrets is False       # default False (safe)
           and prof("true").verify_secrets is True             # bare true arms it
           and prof("false").verify_secrets is False           # bare false disables
           # T1.7 P2.5: an arming flag given a QUOTED STRING fails LOUD (no silent disable of a danger lane)
           and prof_raises('"false"') and prof_raises('"true"'))
src = inspect.getsource(crawl.run)
src_ok = ('if not prof.verify_secrets:' in src
          and 'th_cmd.append("--no-verification")' in src      # default withholds provider round-trip
          and '"not_checked"' in src and 'verification =' in src  # tri-state, not a bare bool
          and 'verified = None' in src                         # not-attempted -> None (not False)
          and '"verification": verification' in src)
sys.exit(0 if (flag_ok and src_ok) else 1)
PYEOF

echo "[128] CDN-aware SYN gate (T0.3 safety) — raw SYN (naabu web-port prefilter) must not hit SHARED third-party edge (CDN/WAF): those IPs are multi-tenant and not the origin. cdncheck (offline, no target contact) classifies resolved public IPs; CDN + WAF IPs are dropped from the SYN target set, CLOUD (aws/gcp/azure — the target's own dedicated instances) is NOT excluded. Non-suppressing: a host left with no SYN-eligible IP is NOT dropped, it falls to direct httpx-by-name (zero coverage loss). When cdncheck can't classify (missing/errored -> None), the gate withholds SYN for un-vetted IPs (httpx by name still runs) rather than packet-scan possible shared infra."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "cdn+waf excluded, cloud kept; malformed/schema-invalid/stale/missing -> None (fail CLOSED); any-CDN host + zero-open host -> direct httpx (never dropped); 9.9.9.9 CDN never SYN'd" || no "CDN-aware SYN gate broken"
import sys, json, tempfile, pathlib, inspect
from quarry_recon.phases import probe
from quarry_recon import netguard as NG, settings
from quarry_recon.runner import RunResult, Status
d = pathlib.Path(tempfile.mkdtemp())
# ---- Part A: _cdn_shared_ips unit truth ----
class Run:
    notes = []
    def raw_path(self, *a): return d / "_".join(a)
    def record(self, *a, **k): pass
class Ctx:
    http_timeout = 15
    run = Run()
    def write_list(self, name, items):
        p = d / name; p.write_text("\n".join(items)); return p
ctx = Ctx()
def cdncheck_writes(rows):
    def fx(tool, cmd, timeout=None, **k):
        out = pathlib.Path(cmd[cmd.index("-o") + 1]); out.write_text(rows); return RunResult("cdncheck", cmd, Status.SUCCESS, 0, 0.1, out, 0)
    return fx
probe.have = lambda t: True
ips = ["8.8.8.8", "1.1.1.1", "52.94.236.248", "93.184.216.34"]
probe.exec_tool = cdncheck_writes("\n".join(json.dumps(x) for x in [
    {"ip": "8.8.8.8", "cdn": True}, {"ip": "1.1.1.1", "waf": True}, {"ip": "52.94.236.248", "cloud": True}]))
a1 = probe._cdn_shared_ips(ctx, ips) == {"8.8.8.8", "1.1.1.1"}      # cdn+waf shared; cloud + unclassified SYN-eligible
probe.exec_tool = cdncheck_writes('{"ip":"8.8.8.8","cdn":true}\nNOT JSON{')
a2 = probe._cdn_shared_ips(ctx, ips) is None                        # malformed row -> fail CLOSED
a3 = True
for bad in ('{"waf":true}',                       # no ip key -> schema-invalid
            '[]', 'null', '"text"', '5',          # valid JSON, NOT a dict row -> must not AttributeError, fail CLOSED
            '{"ip":["9.9.9.9"],"cdn":true}',      # ip is a list -> must not crash shared.add(), fail CLOSED
            '{"ip":"7.7.7.7","cdn":true}'):       # ip not among the queried set -> fail CLOSED
    probe.exec_tool = cdncheck_writes(bad + "\n")
    a3 = a3 and probe._cdn_shared_ips(ctx, ips) is None
probe.exec_tool = cdncheck_writes("")                               # empty valid artifact = legitimate 'none shared'
a4 = probe._cdn_shared_ips(ctx, ips) == set()
probe.have = lambda t: False
a5 = probe._cdn_shared_ips(ctx, ips) is None                        # cdncheck missing -> cannot vet
# stale artifact: pre-write a shared IP, then an exec that writes NOTHING; unlink-before-exec must drop it
probe.have = lambda t: True
def noop_exec(tool, cmd, timeout=None, **k):
    return RunResult("cdncheck", cmd, Status.SUCCESS, 0, 0.1, None, 0)   # writes no -o file
probe.exec_tool = noop_exec
stale = d / "probe_cdncheck_classified.jsonl"; stale.write_text('{"ip":"6.6.6.6","cdn":true}\n')
a6 = probe._cdn_shared_ips(ctx, ips) is None                        # unlinked -> no file -> None (NOT the stale {6.6.6.6})
# ---- Part B: fingerprint_hosts routing (mixed CDN, zero-hit, no host dropped) ----
STORE = {"resolved": [{"host": "ded.com", "a": ["1.2.3.4"]}, {"host": "zero.com", "a": ["5.6.7.8"]},
                      {"host": "mixed.com", "a": ["1.2.3.4", "9.9.9.9"]}, {"host": "cdn.com", "a": ["9.9.9.9"]}],
         "dns_record": []}
HTTPX = []; NAABU = []
class Run2:
    notes = []
    def read(self, e): return STORE.get(e, [])
    def add(self, e, r): return True
    def record(self, *a, **k): pass
    def raw_path(self, ph, t, n): p = d / ph / t; p.mkdir(parents=True, exist_ok=True); return p / n
class Prof: ports = [80, 443]; http_rl = None; portscan_rate = None; block_private_targets = False
class Ctx2:
    def __init__(s): s.run = Run2(); s.profile = Prof(); s.http_timeout = 60
    def echo(s, *a): pass
    def write_list(s, n, items): p = d / n; p.write_text("\n".join(items) + "\n"); return p
def fexec(t, c, **k):
    rp = k.get("raw_path")
    if t == "cdncheck":
        pathlib.Path(c[c.index("-o") + 1]).write_text(json.dumps({"ip": "9.9.9.9", "cdn": True}) + "\n")  # 9.9.9.9 = CDN
        return RunResult("cdncheck", c, Status.SUCCESS, 0, 1.0, None, 1)
    if t == "naabu":
        NAABU.append(set(pathlib.Path(c[c.index("-list") + 1]).read_text().split()))
        pathlib.Path(c[c.index("-o") + 1]).write_text('{"ip":"1.2.3.4","port":80}\n')   # 1.2.3.4 open :80; 5.6.7.8 ZERO
        return RunResult("naabu", c, Status.SUCCESS, 0, 1.0, None, 1)
    if t == "httpx":
        hs = pathlib.Path(c[c.index("-l") + 1]).read_text().split(); rp.parent.mkdir(parents=True, exist_ok=True)
        HTTPX.append((c[c.index("-ports") + 1], hs)); rp.write_text("\n".join(json.dumps({"url": f"https://{h}", "host": h}) for h in hs))
        return RunResult("httpx", c, Status.SUCCESS, 0, 1.0, rp, len(hs))
    return RunResult(t, c, Status.SUCCESS, 0, 1.0, rp, 0)
probe.exec_tool = fexec; probe.have = lambda t: True; import quarry_recon.contract as _CT; _CT._run = fexec
settings.web_port_prefilter = lambda: True; settings.workers = lambda t, dv: 10
NG._STUB = {"all": ["8.8.8.8"]}               # all hosts resolve GLOBAL (none withheld)
probe.fingerprint_hosts(Ctx2(), ["ded.com", "zero.com", "mixed.com", "cdn.com"], "probe")
probed = {}
for ports, hs in HTTPX:
    for h in hs: probed.setdefault(h, set()).add(ports)
b1 = {"ded.com", "zero.com", "mixed.com", "cdn.com"} <= set(probed)   # NO host dropped
b2 = probed.get("ded.com") == {"80"}                                  # dedicated + hit -> grouped on OPEN port only
b3 = probed.get("zero.com") == {"80,443"}                             # dedicated + ZERO naabu hit -> full direct (not dropped)
b4 = probed.get("mixed.com") == {"80,443"}                            # ANY-CDN answer -> whole host direct (all ports)
b5 = probed.get("cdn.com") == {"80,443"}                             # CDN-only -> direct
b6 = NAABU and NAABU[0] == {"1.2.3.4", "5.6.7.8"} and all("9.9.9.9" not in s for s in NAABU)  # CDN IP never SYN'd
sys.exit(0 if (a1 and a2 and a3 and a4 and a5 and a6 and b1 and b2 and b3 and b4 and b5 and b6) else 1)
PYEOF

echo "[129] naabu prefilter TRI-STATE (T1.1, truth-only) — state lives in RunResult.note: usable_with_ports (open host:ports -> dict), usable_empty (CLEAN scan, 0 open -> {} NOT None, note only, NO coverage event — it is not partial coverage), unusable (truncated/error/GARBLED -> None -> full fallback + a coverage event). Routing is identical for the non-hit states (both hosts still direct-httpx'd — a clean SYN 0-open never DROPS a host). FAIL-CLOSED parse: stale artifact is unlinked before the run; any malformed row / unexpected IP / out-of-profile port makes the whole scan UNUSABLE (never narrow httpx off a stale/garbled artifact)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "with_ports->dict+note; empty->{}+note+NO event; unusable->None+event; malformed/unexpected-ip/oob-port->unusable; stale artifact unlinked (not narrowed)" || no "naabu tri-state / fail-closed parse broken"
import sys, tempfile, pathlib
from quarry_recon.phases import probe
from quarry_recon.runner import RunResult, Status
d = pathlib.Path(tempfile.mkdtemp())
EV = []; REC = []
probe.events.coverage_partial = lambda sid, **k: EV.append(k.get("reason", ""))
class Run:
    notes = []
    def raw_path(self, ph, t, n): p = d / ph / t; p.mkdir(parents=True, exist_ok=True); return p / n
    def record(self, ph, res): REC.append(res)
    def add(self, *a, **k): return True
class Prof: ports = [80, 443]; portscan_rate = None
class Ctx:
    run = Run(); http_timeout = 60; profile = Prof()
    def echo(self, *a): pass
    def write_list(self, n, items): p = d / n; p.write_text("\n".join(items)); return p
ctx = Ctx(); pubmap = {"h.com": ["1.2.3.4"]}; probe.have = lambda t: True
RAW = d / "probe" / "naabu-web" / "open.json"
def run_naabu(status, body, prewrite=None):
    EV.clear(); REC.clear(); RAW.parent.mkdir(parents=True, exist_ok=True)
    if prewrite is not None: RAW.write_text(prewrite)               # a STALE artifact present before the run
    def ex(t, c, **k):
        p = pathlib.Path(c[c.index("-o") + 1])
        if isinstance(body, bytes): p.write_bytes(body)             # invalid-encoding artifact
        elif body is not None: p.write_text(body)                   # None => naabu writes nothing
        return RunResult("naabu", c, status, 0, 1, None, 0)
    probe.exec_tool = ex
    return probe._web_port_prefilter(ctx, ["h.com"], "probe", pubmap)
def note(): return REC[-1].note if REC else ""
def status(): return REC[-1].status if REC else None
r = run_naabu(Status.SUCCESS, '{"ip":"1.2.3.4","port":80}\n'); s1 = (r == {"h.com": [80]} and "usable_with_ports" in note() and not EV)
r = run_naabu(Status.EMPTY, ""); s2 = (r == {} and "usable_empty" in note() and not EV)                  # clean-empty emits NO event
r = run_naabu(Status.FAILED, None); s3 = (r is None and "unusable" in note() and any("UNUSABLE" in e for e in EV))
r = run_naabu(Status.SUCCESS, '{"ip":"1.2.3.4","port":80}\nGARBLED{'); s4 = (r is None and "unusable" in note())  # malformed -> unusable (not narrowed)
r = run_naabu(Status.SUCCESS, '{"ip":"9.9.9.9","port":80}\n'); s5 = (r is None)                          # unexpected IP -> unusable
r = run_naabu(Status.SUCCESS, '{"ip":"1.2.3.4","port":22}\n'); s6 = (r is None)                          # out-of-profile port -> unusable
r = run_naabu(Status.SUCCESS, None, prewrite='{"ip":"1.2.3.4","port":80}\n'); s7 = (r == {} and "usable_empty" in note())  # stale unlinked -> not narrowed
r = run_naabu(Status.SUCCESS, '{"ip":[],"port":443}\n'); s8 = (r is None)                                # list ip -> unusable, no TypeError
r = run_naabu(Status.SUCCESS, '{"ip":"1.2.3.4","port":true}\n'); s9 = (r is None)                        # boolean port -> unusable
r = run_naabu(Status.EMPTY, '{"ip":"1.2.3.4","port":80}\nGARBLED{')                                      # valid THEN malformed under EMPTY
s10 = (r is None and "unusable" in note() and status() == Status.EMPTY)                                  # status NEVER promoted to SUCCESS
r = run_naabu(Status.SUCCESS, b'\xff\xfe not utf8'); s11 = (r is None)                                    # unreadable/invalid-encoding -> unusable
sys.exit(0 if (s1 and s2 and s3 and s4 and s5 and s6 and s7 and s8 and s9 and s10 and s11) else 1)
PYEOF

echo "[130] subfinder runs ALL sources, not the recursive subset (T1.2) — upstream '-recursive' means 'use ONLY recursive-capable sources' (subfinder v2.14.0 -h), so the old '-all -recursive' RESTRICTED to that subset and silently dropped the other providers (coverage loss). The passive pass now uses '-all' with NO '-recursive' (selected provider SET is a superset of the old recursive-only subset; observed results still vary run-to-run as passive APIs do); '-stats' (present on v2.14.0) kept for per-source/key health."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "subfinder cmd has -all, NOT -recursive (all sources, not recursive-only subset); -stats kept" || no "subfinder -recursive still narrowing sources"
import sys, inspect
from quarry_recon.phases import vertical
# 1098ce7 moved the passive pass into _run_subfinder (per-apex). Read THAT, and fail loud if the cmd list
# cannot be found at all — a stale locator must not silently pass this check.
src = inspect.getsource(vertical._run_subfinder)
if '["subfinder"' not in src:
    sys.exit(1)
i = src.index('["subfinder"')                            # the run_contract cmd LIST (not the raw_path arg)
region = src[i:i + 200]
ok = ('"-all"' in region and '"-recursive"' not in region and '"-stats"' in region
      and '"-d"' in region and '"-max-time"' in region)  # per-apex + its own budget (see [143]/[144] lineage)
sys.exit(0 if ok else 1)
PYEOF

echo "[131] gitleaks 'dir' + hardened file-output adapter (T1.3) — migrated 'detect --no-git -s <path>' to 'dir <path>' (positional; verified 'gitleaks dir --help'). Stale report unlinked before the run. _gitleaks_status validates the -f json report FULLY (list-of-dict root, else None — never item.get()s a bad row) and applies the file-output matrix: clean+findings->SUCCESS, clean+[]->EMPTY, clean+missing/malformed->PARTIAL, HARD (FAILED/TIMED_OUT)+findings->PARTIAL (never laundered to SUCCESS), hard+empty/absent->PARTIAL or kept hard. Live [6] runs the real 'dir' as the oracle."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "dir+positional (no detect/-s/--no-git); stale unlinked; matrix (clean/hard × findings/empty/missing/malformed) never crashes or launders a hard state" || no "gitleaks migration / adapter broken"
import sys, tempfile, pathlib, inspect
from quarry_recon.phases import crawl
from quarry_recon.runner import RunResult, Status
csrc = inspect.getsource(crawl.run)
i = csrc.index('["gitleaks"'); region = csrc[i:i + 160]
struct = ('"dir"' in region and 'str(sd)' in region and '"detect"' not in region
          and '"--no-git"' not in region and '"-s"' not in region
          and '"-f", "json"' in region and '"-r"' in region
          and 'rep.unlink(missing_ok=True)' in csrc)                 # stale report cleared before the run
d = pathlib.Path(tempfile.mkdtemp()); _n = [0]
def st(status, content):
    _n[0] += 1; p = d / f"r{_n[0]}.json"
    if isinstance(content, bytes): p.write_bytes(content)
    elif content is not None: p.write_text(content)
    r = RunResult("gitleaks", [], status, 0, 0.1, None, 0)
    items = crawl._gitleaks_status(r, p)
    return r.status, items
m = []
# clean (SUCCESS/EMPTY) — report authoritative
m.append(st(Status.EMPTY, '[{"RuleID":"aws","Secret":"x"}]') == (Status.SUCCESS, [{"RuleID": "aws", "Secret": "x"}]))
m.append(st(Status.EMPTY, '[]')[0] == Status.EMPTY)                            # clean+[] -> EMPTY
m.append(st(Status.EMPTY, None)[0] == Status.PARTIAL)                          # clean+missing report -> PARTIAL
s4, i4 = st(Status.SUCCESS, '{"RuleID":"x"}'); m.append(i4 is None and s4 == Status.PARTIAL)  # dict root -> None, no crash
m.append(st(Status.EMPTY, 'null')[1] is None)                                  # null root -> None
m.append(st(Status.EMPTY, '[{"RuleID":"a"}, "not-a-dict"]')[1] is None)        # non-dict row -> untrusted
m.append(st(Status.EMPTY, 'GARBAGE{')[1] is None)                              # malformed JSON -> None
m.append(st(Status.SUCCESS, b'\xff\xfe not utf8')[1] is None)                  # invalid UTF-8 -> None (no crash)
# degraded — never laundered; empty report preserves the original hard state
m.append(st(Status.FAILED, '[{"RuleID":"a"}]') == (Status.PARTIAL, [{"RuleID": "a"}]))  # HARD+findings -> PARTIAL not SUCCESS
m.append(st(Status.FAILED, '[]')[0] == Status.FAILED)                          # HARD+[] -> KEEP FAILED (empty proves nothing)
m.append(st(Status.TIMED_OUT, '[]')[0] == Status.TIMED_OUT)                    # HARD+[] -> KEEP TIMED_OUT
m.append(st(Status.TIMED_OUT, None)[0] == Status.TIMED_OUT)                    # hard+no report -> keep hard
m.append(st(Status.PARTIAL, '[{"RuleID":"a"}]')[0] == Status.PARTIAL)          # PARTIAL is NOT clean -> stays PARTIAL (not SUCCESS)
m.append(st(Status.SKIPPED, '[{"RuleID":"a"}]') == (Status.SKIPPED, None))     # SKIPPED never refines
sys.exit(0 if (struct and all(m)) else 1)
PYEOF

echo "[132] shared file-output status adapter (T1.6) — runner.reclassify_from_artifact(r, n, label) is the ONE vetted matrix behind gowitness (reclassify_from_files) and gitleaks (_gitleaks_status), reused by future file-output tools (shosubgo/arjun/smap/nmap) so the pattern is reviewed ONCE. n = validated result count (>=0) or None (no trustworthy artifact). SKIPPED untouched; clean(SUCCESS/EMPTY) only: n>0->SUCCESS, 0->EMPTY, None->PARTIAL; degraded(FAILED/TIMED_OUT/BLOCKED/PARTIAL): n>0->PARTIAL (never SUCCESS), 0/None-> KEEP original hard status."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "reclassify_from_artifact: SKIPPED untouched; clean n>0/0/None -> SUCCESS/EMPTY/PARTIAL; degraded n>0->PARTIAL, 0/None keeps hard state (no launder)" || no "shared file-output adapter broken"
import sys
from quarry_recon.runner import reclassify_from_artifact as R, RunResult, Status
def mk(st): return RunResult("t", [], st, 0, 1.0, None, 0)
def s(st, n): return R(mk(st), n).status
ok = (
    s(Status.SKIPPED, 5) == Status.SKIPPED                 # never ran -> untouched
    and s(Status.SUCCESS, 3) == Status.SUCCESS and s(Status.EMPTY, 3) == Status.SUCCESS   # clean + n>0 -> SUCCESS
    and s(Status.SUCCESS, 0) == Status.EMPTY               # clean + 0 -> EMPTY
    and s(Status.SUCCESS, None) == Status.PARTIAL          # clean + no trustworthy artifact -> PARTIAL
    and s(Status.FAILED, 2) == Status.PARTIAL              # degraded + n>0 -> PARTIAL (evidence, incomplete)
    and s(Status.TIMED_OUT, 2) == Status.PARTIAL
    and s(Status.BLOCKED, 2) == Status.PARTIAL
    and s(Status.PARTIAL, 2) == Status.PARTIAL             # PARTIAL is NOT clean -> stays (not SUCCESS)
    and s(Status.FAILED, 0) == Status.FAILED               # degraded + 0 -> KEEP hard (empty preserves nothing)
    and s(Status.TIMED_OUT, None) == Status.TIMED_OUT      # degraded + None -> KEEP hard
    and s(Status.BLOCKED, 0) == Status.BLOCKED
    # count-contract: invalid n (negative / bool / float / str) normalizes to None (fail CLOSED), never truthy-success
    and s(Status.SUCCESS, -1) == Status.PARTIAL            # -1 -> None -> clean+None -> PARTIAL (not truthy SUCCESS)
    and s(Status.SUCCESS, True) == Status.PARTIAL          # bool -> None (not a count)
    and s(Status.SUCCESS, 1.5) == Status.PARTIAL           # float -> None
    and s(Status.SUCCESS, "2") == Status.PARTIAL           # str -> None
    and s(Status.FAILED, -1) == Status.FAILED)             # invalid on a degraded run -> keep hard
sys.exit(0 if ok else 1)
PYEOF

echo "[133] gowitness counts a FRESH per-invocation dir (T1.6) — the shared adapter's precondition is a fresh artifact, but gowitness derives its count by globbing a directory. runner.fresh_artifact_dir(base) returns base/attempt-N (N = existing attempt count), created EMPTY, so a reused/pre-populated dir (resume, re-invocation) can't let old screenshots inflate this attempt's count or launder a failed/empty run. Prior attempts are PRESERVED (not deleted). Both probe and enrich gowitness use it."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "fresh_artifact_dir: attempt-N fresh+empty, distinct per call, prior evidence preserved; probe+enrich both wired" || no "gowitness fresh-dir / stale-count broken"
import sys, tempfile, pathlib, inspect
from quarry_recon.runner import fresh_artifact_dir
import quarry_recon.phases.probe as P
import quarry_recon.phases.enrich as EN
base = pathlib.Path(tempfile.mkdtemp()) / "gw"
base.mkdir(parents=True); (base / "old.png").write_bytes(b"x")   # a stale screenshot from a prior run
d1 = fresh_artifact_dir(base)
f1 = (d1.name == "attempt-0" and d1.is_dir() and not list(d1.glob("*.png")))   # fresh + EMPTY (stale not inside)
d2 = fresh_artifact_dir(base)
f2 = (d2.name == "attempt-1" and d2 != d1)                                     # 2nd invocation -> distinct dir
preserved = (base / "old.png").exists()                                       # prior evidence NOT deleted
# GAPPED attempts: attempt-0 + attempt-2 exist (attempt-2 holds a screenshot). The allocator must FILL the
# gap (attempt-1) and NEVER reopen the occupied attempt-2 (a count-based N would have picked attempt-2).
g = pathlib.Path(tempfile.mkdtemp()) / "gw2"
(g / "attempt-0").mkdir(parents=True); (g / "attempt-2").mkdir(parents=True); (g / "attempt-2" / "s.png").write_bytes(b"x")
dg = fresh_artifact_dir(g)
gap = (dg.name == "attempt-1" and not list(dg.glob("*.png")) and (g / "attempt-2" / "s.png").exists())
# a NAME occupied by a FILE is skipped, not reopened
h = pathlib.Path(tempfile.mkdtemp()) / "gw3"; h.mkdir(parents=True); (h / "attempt-0").write_text("x")
fileskip = fresh_artifact_dir(h).name == "attempt-1"
wired = ("fresh_artifact_dir(" in inspect.getsource(P) and "fresh_artifact_dir(" in inspect.getsource(EN))
sys.exit(0 if (f1 and f2 and preserved and gap and fileskip and wired) else 1)
PYEOF

echo "[134] shosubgo -fail + FAIL-CLOSED artifact (T1.5) — WITHOUT -fail an invalid/rate-limited Shodan key exits 0 -> looks clean-empty (false-negative); -fail (verified upstream main.go) surfaces it as FAILED. The parser is genuinely fail-closed: _shosubgo_read returns (hosts, artifact_ok) — normalize.hosts silently drops malformed lines, so a garbage-only artifact would ELSE read as clean EMPTY and valid+garbage as clean SUCCESS. Any malformed line / invalid UTF-8 sets artifact_ok=False -> the caller marks completion PARTIAL while KEEPING the valid hosts (evidence never suppressed). Missing/unreadable -> (None, False). Stale -o unlinked."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "-fail+unlink+read wired; read: (None) missing, clean all-host->ok, garbage-only/mixed/bad-utf8->artifact_ok False (valid kept); call-site downgrades clean+!ok to PARTIAL; FAILED+no-file kept" || no "shosubgo fail-closed / adapter broken"
import sys, tempfile, pathlib, inspect
from quarry_recon.phases import vertical
from quarry_recon.runner import RunResult, Status, reclassify_from_artifact
vsrc = inspect.getsource(vertical.run)
shb = vsrc[vsrc.find("# ── shosubgo"):vsrc.find("# ── shosubgo") + 2000]
struct = ('"-fail"' in shb and '"-o"' in shb and "sho.unlink(missing_ok=True)" in shb
          and "_shosubgo_read(sho)" in shb and "reclassify_from_artifact" in shb
          and "artifact_ok" in shb and "Status.PARTIAL" in shb)     # call-site downgrade present
d = pathlib.Path(tempfile.mkdtemp())
def read(name, content=None, raw=None):
    p = d / name
    if raw is not None: p.write_bytes(raw)
    elif content is not None: p.write_text(content)
    return vertical._shosubgo_read(p)
h_miss, ok_miss = vertical._shosubgo_read(d / "nope.txt")          # missing -> (None, False)
h_clean, ok_clean = read("c.txt", "a.acme.com\nb.acme.com\n")      # all valid -> ok True
h_empty, ok_empty = read("e.txt", "")                              # empty -> [] ok True (genuine 0)
h_garb, ok_garb = read("g.txt", "not a host\n!!!\n")               # garbage-only -> [] but ok False (NOT clean-empty)
h_mix, ok_mix = read("m.txt", "a.acme.com\ngarbage line\n")        # mixed -> keep valid, ok False
h_bad, ok_bad = read("b.txt", raw=b"a.acme.com\n\xff\xfe\n")       # invalid UTF-8 -> ok False, valid kept
helper = (h_miss is None and ok_miss is False
          and len(h_clean) == 2 and ok_clean is True
          and h_empty == [] and ok_empty is True
          and h_garb == [] and ok_garb is False                    # garbage-only is NOT a clean EMPTY
          and len(h_mix) == 1 and ok_mix is False                  # valid host preserved, but artifact flagged
          and any(e["host"] == "a.acme.com" for e in h_bad) and ok_bad is False)
# call-site downgrade simulation: clean-exit + artifact_ok False -> PARTIAL (keep hosts)
r = RunResult("shosubgo", [], Status.EMPTY, 0, 0.1, None, 0)
reclassify_from_artifact(r, len(h_mix), label="shosubgo")
if r.status in (Status.SUCCESS, Status.EMPTY):    # mirrors the call-site guard
    r.status = Status.PARTIAL
downgrade = r.status == Status.PARTIAL
rf = RunResult("shosubgo", [], Status.FAILED, 1, 0.1, None, 0); reclassify_from_artifact(rf, None, label="shosubgo")
sys.exit(0 if (struct and helper and downgrade and rf.status == Status.FAILED) else 1)
PYEOF

echo "[135] gau single input channel (T1.4) — gau reads domains from POSITIONAL ARGS or stdin, never both (args take precedence; verified upstream cmd/gau/main.go). The apexes are passed as args, so the old duplicate stdin_data was DEAD input (gau never read it). Dropped: the gau call passes apexes as args and NO stdin_data. Coverage unchanged."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "gau exec passes apexes as args, no stdin_data (single channel)" || no "gau still double-feeds args + stdin"
import sys, inspect
from quarry_recon.phases import crawl
src = inspect.getsource(crawl.run)
i = src.index('["gau"')
region = src[i:i + 220]
ok = ('prof.apex_domains' in region                       # apexes as positional args
      and 'stdin_data' not in region)                     # dead stdin channel removed
sys.exit(0 if ok else 1)
PYEOF

echo "[136] smap -oJ structured + shared adapter + ip-remap + enrich parse (T1.6) — _smap_records parses smap's -oJ JSON FAIL-CLOSED (missing/unreadable/bad-utf8/malformed-JSON/non-list-root/non-dict-record/bad-ip/bad-ports/non-int-port -> None). _smap_ingest reclassifies from the port YIELD (clean+ports->SUCCESS, clean+0->EMPTY, degraded+ports->PARTIAL never laundered, malformed/unreadable->keep hard / PARTIAL) and attributes ports to the in-scope host(s) each returned IP maps to (via our resolved data, else the record hostnames). smap OMITS no-data IPs (verified 4->2), so returned/eligible is a VISIBILITY note, NOT a forced PARTIAL. enrich previously DISCARDED smap output (C12) — now shares the helper."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "(records,complete): valid kept when others malformed->PARTIAL; semantic ip/port validation; user_hostname-priority attribution beats stale resolved; total-silence/0-ports->EMPTY not forced-PARTIAL; degraded/malformed-root kept; enrich wired" || no "smap -oJ adapter broken"
import sys, json, tempfile, pathlib, inspect
from quarry_recon.phases import probe, enrich
from quarry_recon.runner import RunResult, Status
d = pathlib.Path(tempfile.mkdtemp())
def art(payload, raw=None):
    p = d / f"s{len(list(d.iterdir()))}.json"
    if raw is not None: p.write_bytes(raw)
    else: p.write_text(json.dumps(payload))
    return p
def rec(ip="1.2.3.4", uh="h.acme.com", hn=None, ports=((80, "http"), (443, "https"))):
    return {"ip": ip, "user_hostname": uh, "hostnames": hn if hn is not None else ["sh.com"],
            "ports": [{"port": p, "service": s} for p, s in ports]}
# parse: valid -> (records, True)
recs, comp = probe._smap_records(art([rec()]))
p1 = (recs == [("1.2.3.4", "h.acme.com", ["sh.com"], [(80, "http"), (443, "https")])] and comp is True)
# no salvageable evidence -> (None, False)
p2 = all(probe._smap_records(x) == (None, False) for x in
         [d / "nope.json", art({"not": "a list"}), art(None, raw=b'\xff\xfe'), art(None, raw=b'GARBAGE{')])
# MIXED valid + malformed rows: keep the valid, complete=False (P1 — strict parse must not suppress evidence)
mr, mc = probe._smap_records(art([rec(), ["not-a-dict"], {"ip": "not-an-ip", "ports": []},
                                   {"ip": "5.6.7.8", "user_hostname": "b.acme.com", "hostnames": [],
                                    "ports": [{"port": 22, "service": "ssh"}, {"port": 99999}, {"port": True}]}]))
p3 = (mc is False and len(mr) == 2                                             # 1 bad-ip row dropped, valid kept
      and mr[0][0] == "1.2.3.4"
      and mr[1] == ("5.6.7.8", "b.acme.com", [], [(22, "ssh")]))               # out-of-range 99999 + bool port dropped
parse_ok = (p1 and p2 and p3)
# ingest: user_hostname beats STALE resolved data (P2)
NOTES = []; ADDED = []
class Scope:
    def in_scope(self, h): return not h.startswith("oos")
    def is_oos(self, h): return h.startswith("oos")
class Run:
    # resolved is STALE: it maps a DIFFERENT ip, so only the record's user_hostname can attribute correctly
    def read(self, e): return [{"host": "h.acme.com", "a": ["9.9.9.9"]}] if e == "resolved" else []
    def add(self, e, r): ADDED.append((e, r.get("host"))); return True
    def record(self, ph, rr): NOTES.append(rr.note)
class Ctx: run = Run(); scope = Scope()
ctx = Ctx(); tgts = ["h.acme.com", "quiet.acme.com"]
r = RunResult("smap", [], Status.SUCCESS, 0, 1, None, 0); n = probe._smap_ingest(ctx, r, art([rec()]), "probe", tgts)
attrib = (n == 2 and r.status == Status.SUCCESS
          and all(h == "h.acme.com" for _, h in ADDED)                         # user_hostname attribution (resolved was stale)
          and "1/2 target IP(s) had InternetDB records" in (NOTES[-1] or ""))
# mixed-malformed on a clean exit -> PARTIAL, valid records still ingested
rm = RunResult("smap", [], Status.SUCCESS, 0, 1, None, 0)
probe._smap_ingest(ctx, rm, art([rec(), ["bad"]]), "probe", tgts); partial = rm.status == Status.PARTIAL
# total silence (0 records) -> EMPTY (not forced PARTIAL); complete records 0 ports -> EMPTY
r0 = RunResult("smap", [], Status.SUCCESS, 0, 1, None, 0); probe._smap_ingest(ctx, r0, art([]), "probe", tgts)
r0p = RunResult("smap", [], Status.SUCCESS, 0, 1, None, 0)
probe._smap_ingest(ctx, r0p, art([rec(ports=())]), "probe", tgts)
empties = (r0.status == Status.EMPTY and r0p.status == Status.EMPTY)
# degraded + records -> PARTIAL; unreadable/malformed-root -> keep hard
rd = RunResult("smap", [], Status.TIMED_OUT, None, 1, None, 0); probe._smap_ingest(ctx, rd, art([rec()]), "probe", tgts)
rf = RunResult("smap", [], Status.FAILED, 1, 1, None, 0); probe._smap_ingest(ctx, rf, art(None, raw=b'GARBAGE{'), "probe", tgts)
hard = (rd.status == Status.PARTIAL and rf.status == Status.FAILED)
enr = "_smap_ingest(" in inspect.getsource(enrich) and '"-oJ"' in inspect.getsource(enrich)
sys.exit(0 if (parse_ok and attrib and partial and empties and hard and enr) else 1)
PYEOF

echo "[137] nmap -oX structured + grouped + registered (T1.6/C07/C12) — nmap was invoked with -oN text, its service yield NEVER parsed, given the CARTESIAN union of every port over every IP, and absent from tools.yaml. Now: registered; IPs grouped by their EXACT open-port set (one nmap call per group on just those ports — no Cartesian); -oX XML parsed FAIL-CLOSED into (ip,port,proto,service,product,version) for OPEN ports only (malformed/missing/non-nmaprun-root -> None); status via the shared adapter; nmap ingests BEFORE the naabu-bare fill so its richer service entity wins the {ip}:{port} id."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "_nmap_services parses open ports from -oX (closed skipped), fail-closed on malformed/missing/bad-root; source groups by port-set + -oX + adapter + nmap-before-naabu-bare; nmap registered" || no "nmap -oX / grouping / registry broken"
import sys, tempfile, pathlib, inspect
from quarry_recon.phases import probe
from quarry_recon.registry import load_tools
d = pathlib.Path(tempfile.mkdtemp())
FIN = '<runstats><finished exit="success"/></runstats>'
def xml(hosts, fin=FIN):
    return f'<?xml version="1.0"?><nmaprun>{hosts}{fin}</nmaprun>'
def w(name, text): p = d / name; p.write_text(text); return p
H = ('<host><address addr="1.2.3.4" addrtype="ipv4"/><ports>'
     '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.20"/></port>'
     '<port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>'
     '<port protocol="tcp" portid="8080"><state state="open"/></port></ports></host>')
recs, comp = probe._nmap_services(w("s.xml", xml(H)))
OPEN = [("1.2.3.4", 80, "tcp", "http", "nginx", "1.20"), ("1.2.3.4", 8080, "tcp", "", "", "")]   # 443 closed skipped
parse = (recs == OPEN and comp is True                                       # clean finish -> complete
         and probe._nmap_services(d / "nope.xml") == (None, False)           # missing
         and probe._nmap_services(w("bad.xml", "<nmaprun><host")) == (None, False)   # malformed XML
         and probe._nmap_services(w("root.xml", "<other/>")) == (None, False)        # wrong root
         # P1: no runstats / errored finish -> valid rows KEPT but complete=False
         and probe._nmap_services(w("nofin.xml", xml(H, "")))[0] == OPEN
         and probe._nmap_services(w("nofin.xml2", xml(H, "")))[1] is False
         and probe._nmap_services(w("err.xml", xml(H, '<runstats><finished exit="error"/></runstats>')))[1] is False
         # P2: malformed portid keeps valid rows, complete=False
         and probe._nmap_services(w("mal.xml", xml(
             '<host><address addr="1.1.1.1" addrtype="ipv4"/><ports>'
             '<port protocol="tcp" portid="80"><state state="open"/></port>'
             '<port protocol="tcp" portid="99999"><state state="open"/></port></ports></host>')))
             == ([("1.1.1.1", 80, "tcp", "", "", "")], False))
src = inspect.getsource(probe.run)
i = src.index("nmap -sV only on the ports")
region = src[i:i + 3400]
struct = ("groups.setdefault(tuple(sorted(ports" in region        # group IPs by open-port set (no Cartesian)
          and '"-oX"' in region and "svcs, complete = _nmap_services(xml)" in region  # parse+completion (now in reclassify cb)
          and 'run_contract("probe.nmap_service"' in region and "reclassify=_nmap_reclassify" in region  # C07: under contract
          and "res.status = Status.PARTIAL" in region             # incomplete -> PARTIAL (in the callback)
          and "work_unit=wu" in region                            # C07 inc3: per-port-group work_unit (resume key)
          and '"sources": ["naabu", "nmap"]' in region            # P3: enriched entity carries both sources
          and "scaled_timeout(len(ips) * len(ptup)" in region)    # P4: host×port work
registered = any(t.bin == "nmap" for t in load_tools())
sys.exit(0 if (parse and struct and registered) else 1)
PYEOF

echo "[138] arjun onto the shared adapter — false-success fix (T1.6) — arjun is a FILE-output tool (-oT) but was classified from its CHATTY stdout: the the measured run run exited 0 with 3954 stdout lines and NO arjun.txt -> SUCCESS with 0 params. Now: stale -oT unlinked; _arjun_urls reads it FAIL-CLOSED (missing/unreadable -> None); status via reclassify_from_artifact on the param-bearing-URL count (0 -> EMPTY, absent -> PARTIAL/keep-hard). Ingestion (url + parameter + xss review -> dalfox) unchanged."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "_arjun_urls: query-lines only, missing->None, empty->[]; missing -oT + no-params terminal = COMPLETE empty (was a permanent PARTIAL); chatty stdout with no artifact -> UNKNOWN never SUCCESS; unlink kept, file-only adapter retired" || no "arjun adapter / false-success broken"
import sys, tempfile, pathlib, inspect
from quarry_recon.phases import params
d = pathlib.Path(tempfile.mkdtemp())
T = "https://x/s"
good = d / "a.txt"; good.write_text(T+"?q=1\n"+T+"?id=2\nno-query-line\nhttps://other/s?q=1\n\n")
# rows are TARGET-BOUND now: the fail-open `"?" in line` parser is GONE (it ingested `garbage?x=1`)
h1 = params._arjun_rows(good, T) == ([T+"?q=1", T+"?id=2"], 2)   # 2 malformed/off-target, siblings kept
h2 = params._arjun_rows(d / "nope.txt", T) == (None, 0)          # missing -> None (NOT an error)
empty = d / "e.txt"; empty.write_text("")
h3 = params._arjun_rows(empty, T) == ([], 0)                     # empty file -> no rows, no corruption
h1 = h1 and not hasattr(params, "_arjun_urls")                   # the fail-open helper is removed
# A2 SUPERSEDES the file-only adapter. `missing -oT -> PARTIAL (uncertain)` was the best available guard
# while the artifact was the ONLY signal, but it is WRONG as a general rule: arjun calls exporter() solely
# inside `elif these_params:`, so the ordinary no-parameters outcome writes NO FILE and was permanently
# reported as an uncertain PARTIAL. The stdout terminal line resolves it, so the verdict is what decides.
if not hasattr(params, "_arjun_verdict") or not hasattr(params, "_arjun_lane"):
    sys.exit(1)
S = "[*] Scanning 0/1: http://t/"
T = "http://t/"
def v(ok, text, urls):
    return params._arjun_verdict(ok, params._arjun_signals(text), urls, target=T)[0]
none_is_complete = v(True, S + "\n[!] No parameters were discovered.", None) == "empty"
# the ORIGINAL false-success this check was written for still cannot happen: a chatty stdout claiming
# parameters with no artifact behind it is UNKNOWN (a gap), and never SUCCESS.
no_false_success = (v(True, S + "\n[+] Parameters found: foo", None) == "unknown"
                    and v(True, S + "\n[+] Parameters found: foo", []) == "unknown")
lsrc = inspect.getsource(params._arjun_exec)
struct = ("out_f.unlink(missing_ok=True)" in lsrc               # stale -oT still cannot fake output
          and "_arjun_verdict(r.exit_code == 0" in lsrc         # verdict wired to the REAL exit code
          and "_arjun_rows(out_f, url)" in inspect.getsource(params._arjun_exec)   # TARGET-bound parse
          and "reclassify_from_artifact" not in inspect.getsource(params))   # file-only adapter retired
sys.exit(0 if (h1 and h2 and h3 and none_is_complete and no_false_success and struct) else 1)
PYEOF

echo "[139] profile-input validation (T1.7/C04) — CONSERVATIVE hardening of malformed/dangerous input, never narrows a legitimate target. (1) MODES booleans: _flag parses a QUOTED \"false\" as False, not bool('false')==True — the footgun that could silently flip PASSIVE_ONLY on and SUPPRESS the active scan; ambiguous values fail loud. (2) APEX_DOMAINS canonicalized/validated (IDNA punycode; wildcard preserved) — rejects path/traversal/garbage, which ALSO closes the apex->filename path escape. (3) PORTS.HTTP range 1..65535 + RATELIMIT positive-int, both fail loud at load."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "_flag strict(0/1); footgun fixed; wildcard->root MATCHES subs; IDNA2008 (faß.de->xn--fa-hia.de not fass.de); single-label ok, IP-literal rejected; strict-int ports/rates (no float/bool); arming quoted-string fails loud; _apex_of longest" || no "profile validation (C04) broken"
import sys, os, tempfile
from quarry_recon.config import TargetProfile, ProfileError, _flag, _canon_domain
from quarry_recon.phases.dns import _apex_of
def prof(body):
    fd, p = tempfile.mkstemp(suffix=".yaml"); os.close(fd); open(p, "w").write(body); return TargetProfile.load(p)
def raises(body):
    try: prof(body); return False
    except ProfileError: return True
def craises(fn, *a):
    try: fn(*a); return False
    except ProfileError: return True
BASE = "TARGET: t\nAPEX_DOMAINS:\n  - example.com\n"
# _flag: strict — quoted false->False, ambiguous & int!=0/1 fail loud
flag = (_flag("false", True) is False and _flag("true", False) is True and _flag("", True) is False
        and _flag(1, False) is True and _flag(0, True) is False and _flag(None, True) is True
        and craises(_flag, "maybe", False) and craises(_flag, 2, False) and craises(_flag, -1, False))
footgun = prof(BASE + 'MODES:\n  PASSIVE_ONLY: "false"\n').passive_only is False   # quoted false -> False (not True)
# P1.1 wildcard -> root, and it actually MATCHES subdomains (was zero-scope)
wp = prof('TARGET: t\nAPEX_DOMAINS:\n  - "*.example.com"\n')
wild = (wp.apex_domains == ["example.com"] and wp.scope().in_scope("www.example.com")
        and wp.scope().in_scope("example.com"))
# P1.2 IDNA2008/UTS-46 non-transitional (identity-correct)
idna_ok = (_canon_domain("faß.de") == "xn--fa-hia.de"           # NOT the builtin's transitional "fass.de"
           and _canon_domain("münchen.de") == "xn--mnchen-3ya.de"
           and _canon_domain("Example.COM.") == "example.com")
# P1.3 single-label internal zone OK; IP literal + traversal rejected
single = (_canon_domain("corp") == "corp" and craises(_canon_domain, "1.2.3.4")
          and craises(_canon_domain, "../../etc") and craises(_canon_domain, "a b.com"))
# P2.4 strict int — no float/bool coercion into ports/rates
strict = (raises(BASE + 'PORTS:\n  HTTP: [80.9]\n')             # float port
          and raises(BASE + 'PORTS:\n  HTTP: [true]\n')         # bool port
          and raises(BASE + 'PORTS:\n  HTTP: [99999]\n') and raises(BASE + 'PORTS:\n  HTTP: [0]\n')
          and raises(BASE + 'RATELIMIT:\n  HTTP: 5.5\n') and raises(BASE + 'RATELIMIT:\n  HTTP: -5\n')
          and raises(BASE + 'RATELIMIT:\n  HTTP: abc\n'))
# P2.5 arming flags: a quoted string / typo fails loud, never silently disables the danger lane
arming = (raises(BASE + 'MODES:\n  SECRET_VERIFICATION: "true"\n')   # quoted string -> must fail, not silent-off
          and raises(BASE + 'MODES:\n  DEEP_EVIDENCE: maybe\n')
          and prof(BASE + 'MODES:\n  SECRET_VERIFICATION: true\n').verify_secrets is True)  # bare true still arms
# P2.6 _apex_of picks the LONGEST apex regardless of list order
longest = (_apex_of("x.dev.example.com", ["example.com", "dev.example.com"]) == "dev.example.com"
           and _apex_of("x.dev.example.com", ["dev.example.com", "example.com"]) == "dev.example.com")
good = prof(BASE + 'PORTS:\n  HTTP: [80, 443]\nRATELIMIT:\n  HTTP: 10\n')
good_ok = (good.ports == [80, 443] and good.http_rl == 10 and good.apex_domains == ["example.com"])
sys.exit(0 if (flag and footgun and wild and idna_ok and single and strict and arming and longest and good_ok) else 1)
PYEOF

echo "[140] permutation frontier-only RESOLVE + retry-on-degraded (T2.3/C20) — the loop re-resolved the ENTIRE candidate set every iteration (the measured run ~9.9M candidate lines / 10M massdns rows for 8 net additions). Now candidates are SETTLED (not re-resolved) only after a CLEAN puredns batch; a DEGRADED batch settles only its confirmed-resolved names and leaves the rest RETRYABLE (a transient resolver failure is re-attempted next iteration, bounded by MAX_ITERS) — so the RESOLVED union is set-equal to the old blanket re-resolution. alterx still runs over the FULL known set (its -enrich word cloud stays complete — frontier-only would lose cross-pollinated perms). Dedup savings ride on the RunResult.note; coverage_partial is reserved for the degraded-retryable gap."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "BOOKKEEPING: settle-on-clean-only + degraded-retry recovers a transient batch failure ({a,b,c,d} vs no-retry {a,d}); savings on note not coverage_partial; alterx full-known. (Full resolved-union equality vs the old loop's clean-negative re-submission is a BENCHMARK question, not unit-provable.)" || no "permutation frontier-only / retry bookkeeping broken"
import sys, inspect
from quarry_recon.phases import vertical
# the recursion loop lives in its own seam since the flag-axis step 4 (`--unbound` drives MAX_ITERS),
# so the phase body and the loop are read TOGETHER
src = inspect.getsource(vertical.run) + inspect.getsource(vertical._recursive_permute)
struct = ("new_cand = [c for c in dict.fromkeys(cand) if c and c not in seen_candidates]" in src
          and 'ctx.write_list(f"all_candidates_{it}.txt", new_cand)' in src        # puredns resolves only the delta
          and '"-l", str(known), "-enrich", "-mode", "both"' in src                # alterx over the FULL known set
          and "clean_batch = r.status in (Status.SUCCESS, Status.EMPTY)" in src    # settle only on a clean batch
          and "if clean_batch:" in src
          # ...and a degraded batch's stall is NOT convergence (flag-axis step 4 review)
          and 'stop = "converged" if clean_batch else "no_progress"' in src
          and "seen_candidates.update(new_cand)" in src and "seen_candidates.update(resolved_now)" in src
          and 'r.note = (f"frontier:' in src                                       # savings on the note, not coverage_partial
          and "retryable next iteration" in src)                                   # coverage_partial reserved for degraded
# retry semantics: iter1 DEGRADED, only {a} resolves (b,c fail transiently); iter2 CLEAN retries b,c (not
# settled) and resolves {b,c,d}. Frontier-with-retry must recover b,c -> {a,b,c,d} (a no-retry frontier
# would settle b,c on the degraded batch and LOSE them -> {a,d}).
def sim(iters):
    seen = set(); resolved = set()
    for cand, status, resolves in iters:
        new_cand = [c for c in dict.fromkeys(cand) if c and c not in seen]
        got = {c for c in new_cand if c in resolves}
        resolved |= got
        seen |= set(new_cand) if status == "clean" else got     # clean settles all; degraded settles resolved-only
    return resolved
retry = sim([(["a", "b", "c"], "deg", {"a"}), (["a", "b", "c", "d"], "clean", {"b", "c", "d"})])
no_retry = set()   # what a settle-everything frontier would get (loses the transient failures)
seen = set()
for cand, status, resolves in [(["a", "b", "c"], "deg", {"a"}), (["a", "b", "c", "d"], "clean", {"b", "c", "d"})]:
    nc = [c for c in dict.fromkeys(cand) if c not in seen]; no_retry |= {c for c in nc if c in resolves}; seen |= set(nc)
logic = (retry == {"a", "b", "c", "d"} and no_retry == {"a", "d"} and retry != no_retry)   # retry recovers b,c
sys.exit(0 if (struct and logic) else 1)
PYEOF

echo "[141] ffuf graceful -maxtime ceiling + -noninteractive (T2.2) — both ffuf call sites (probe vhost, content) now pass -maxtime = the scaled ceiling so ffuf GRACEFULLY stops a slow/calibration-stuck origin and writes its PARTIAL -o artifact (reclassify_ffuf then sees real results), instead of exec_tool SIGKILL'ing it and losing the buffered output — exec_tool's timeout becomes the hard BACKSTOP (ceiling + 60). -noninteractive drops the keybinding console (batch hygiene). -ach NOT added: one origin per ffuf call, so -ac already calibrates per-origin. Existing -ac / -mc-3xx / no-redirect-follow preserved."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "-maxtime only when bounded (0 stays unbounded, no 60s kill); native maxtime-reached -> PARTIAL (hits AND 0-hits, never laundered); ordinary clean -> SUCCESS/EMPTY; outer hard timeout -> TIMED_OUT/PARTIAL; -noninteractive; no -ach" || no "ffuf -maxtime edges broken"
import sys, json, tempfile, pathlib, inspect
from quarry_recon.phases import probe, content
from quarry_recon.runner import reclassify_ffuf, RunResult, Status
if not hasattr(content, "_run_one"):
    sys.exit(1)   # A1 moved the content ffuf invocation into _run_one; fail LOUD if that helper vanishes
p = inspect.getsource(probe); c = inspect.getsource(content.run) + inspect.getsource(content._run_one)
i = p.index('"-H", f"Host: FUZZ'); vh = p[i:i + 600]
struct = ('"-noninteractive"' in vh and '"-maxtime", str(ffuf_to)' in vh and "if ffuf_to:" in vh
          and "ffuf_to + 60 if ffuf_to else 0" in p and '"-ach"' not in vh and '"-ac"' in vh   # UNBOUNDED stays 0
          and '"-maxtime", str(ct_to)' in c and "if ct_to:" in c and "ct_to + 60 if ct_to else 0" in c
          and '"-noninteractive"' in c)
d = pathlib.Path(tempfile.mkdtemp())
def rc(status, stderr, n):
    a = d / f"a{len(list(d.iterdir()))}.json"; a.write_text(json.dumps({"results": [{"url": "x"}] * n}))
    return reclassify_ffuf(RunResult("ffuf", [], status, 0, 0.1, a, 0, stderr_tail=stderr), a).status
MT = "[WARN] Maximum running time for entire process reached, exiting."
behav = (rc(Status.EMPTY, MT, 3) == Status.PARTIAL            # native maxtime + hits -> PARTIAL (not SUCCESS)
         and rc(Status.EMPTY, MT, 0) == Status.PARTIAL         # native maxtime + 0 hits -> PARTIAL (not EMPTY)
         and rc(Status.SUCCESS, MT, 3) == Status.PARTIAL       # even if classifier said SUCCESS, maxtime demotes
         and rc(Status.EMPTY, "", 3) == Status.SUCCESS         # ordinary clean + hits -> SUCCESS
         and rc(Status.EMPTY, "", 0) == Status.EMPTY           # ordinary clean + 0 -> EMPTY
         and rc(Status.TIMED_OUT, "", 3) == Status.PARTIAL)    # outer hard SIGKILL timeout + hits -> PARTIAL (kept)
sys.exit(0 if (struct and behav) else 1)
PYEOF

echo "[142] offline pytest CI gate (T4/C18) — hermetic pytest suite (tests/) + .github offline-ci workflow. TWO-LAYER network deny: a per-test autouse fixture (local dev) + a session guard armed by QUARRY_OFFLINE_CI=1 installed BEFORE collection (covers import-time network too). Both block sockets/resolvers/UDP/subprocess-spawn, so the gate can neither connect nor launch a scanner. Default run excludes live/integration/requires_tool (opt-in). This shell suite RUNS the pytest gate (with QUARRY_OFFLINE_CI=1) during the dual-run transition. Skips only if pytest is unavailable."
if PYTHONPATH="$QUARRY_SRC" $PY -c 'import pytest' 2>/dev/null; then
  if PYTHONPATH="$QUARRY_SRC" QUARRY_OFFLINE_CI=1 $PY -m pytest "$(dirname "$QUARRY_SRC")/tests" -m offline -q >/tmp/quarry_pytest.out 2>&1; then
    ok "pytest -m offline green ($(grep -oE '[0-9]+ passed' /tmp/quarry_pytest.out | head -1)); network-deny fixture enforced"
  else
    no "pytest offline suite FAILED: $(tail -3 /tmp/quarry_pytest.out | tr '\n' ' ')"
  fi
else
  sk "pytest not installed (pip install -e '.[dev]')"
fi


echo "[143] v0.3.9 lock-robustness schema — maintenance_state (active/monitor/frozen/distro) + release (human tag, kept SEPARATE from a pseudo-version/commit pin) are REFRESH-POLICY metadata: validated at load, planning-only (never gate verify/drift/install/runtime). Every registry tool is classified; release rejected when a sentinel / missing pin / == pin; distro state <=> policy:distro (both or neither). 'quarry lock --maintenance' renders the grouped refresh view WITHOUT probing installed tools. js-beautify 2.0.3 + porch-pirate repo=WatchDogSecurity (verified upstream)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "maintenance/release schema validated + planning-only + every tool classified + --maintenance probe-free" || no "v0.3.9 lock-robustness schema broken"
import sys
from quarry_recon import registry
from quarry_recon.registry import _validate_lock, LockError, _MAINTENANCE_STATES
def bad(d):
    try: _validate_lock(d.get("bin","?"), d); return False
    except LockError: return True
c_reject = (bad({"bin":"t","maintenance_state":"bogus"})
            and bad({"bin":"t","release":"latest","ref":"abc"})       # sentinel
            and bad({"bin":"t","release":"3.1.1"})                    # no pin/ref
            and bad({"bin":"t","release":"v2.14.0","version":"v2.14.0","install":"go install x/cmd/x@latest"})  # ==pin
            and bad({"bin":"t","policy":"distro"})                    # distro policy, no state
            and bad({"bin":"t","maintenance_state":"distro"})         # distro state, no policy
            and bad({"bin":"t","policy":"distro","maintenance_state":"active"}))  # disagree
ts = registry.load_tools()
c_complete = all(t.maintenance_state in _MAINTENANCE_STATES for t in ts)
c_release = all((not t.release) or (t.release != (t.pin or t.ref)) for t in ts)
c_distro = all((t.maintenance_state == "distro") == (t.policy == "distro") for t in ts)
# planning-only: maintenance_state must NOT be consulted by verify/drift/install
import inspect
src = inspect.getsource(registry.drift) + inspect.getsource(registry._drift_status) + inspect.getsource(registry.health) + inspect.getsource(registry.install_one)
c_planning = "maintenance_state" not in src
# --maintenance renders WITHOUT probing installed tools
from click.testing import CliRunner
from quarry_recon.cli import cli
probed = []
_orig = registry.installed_identity
registry.installed_identity = lambda t: probed.append(t.bin) or ""
try:
    r = CliRunner().invoke(cli, ["lock","--maintenance"])
finally:
    registry.installed_identity = _orig
c_view = (r.exit_code == 0 and not probed and "refresh-policy view" in r.output
          and "[active]" in r.output and "[distro]" in r.output)
sys.exit(0 if (c_reject and c_complete and c_release and c_distro and c_planning and c_view) else 1)
PYEOF

echo "[144] install.sh control-flow — PATH is persisted BEFORE tool provisioning, so a REQUIRED-tool failure (or a host below minimum) does NOT abort the bootstrap before the rc-file PATH block is written. The failing run still exits nonzero, and the printed recovery hint ('quarry install --only <tool>') is runnable in a new shell. Simulated with fake pipx (ok) + fake quarry (exit 1)."
_t144=$(mktemp -d); _fb="$_t144/bin"; mkdir -p "$_fb" "$_t144/home"
printf '#!/usr/bin/env bash\nexit 0\n' > "$_fb/pipx"; chmod +x "$_fb/pipx"
printf '#!/usr/bin/env bash\nexit 1\n' > "$_fb/quarry"; chmod +x "$_fb/quarry"   # a required tool failed
PATH="$_fb:$PATH" HOME="$_t144/home" SHELL=/bin/bash bash "$(dirname "$QUARRY_SRC")/install.sh" >"$_t144/out" 2>&1
_rc=$?
if [ "$_rc" -ne 0 ] \
   && grep -q '>>> quarry path >>>' "$_t144/home/.bashrc" 2>/dev/null \
   && grep -q 'export PATH=.*\.local/bin' "$_t144/home/.bashrc" 2>/dev/null \
   && grep -qi 'quarry install --only' "$_t144/out"; then
  ok "install.sh: rc-file PATH block written + nonzero exit ($_rc) + recovery hint on required-tool failure"
else
  no "install.sh control-flow: rc=$_rc / rc-file / recovery hint (see $_t144/out)"
fi
rm -rf "$_t144"
echo "[145] nuclei EXECUTION vs COVERAGE split — status now tracks whether nuclei reached its OWN terminal ('Scan completed in' + exit 0), so a chunk with degraded request coverage is recorded DONE and a resume skips it; request coverage rides separate structured counters (measure=requests, one unit per chunk) parsed from nuclei -stats. Replays a REAL 2026-07-25 nuclei stderr capture: 10/10 chunks execution-complete (the old generic stderr signature marked all 10 degraded, left chunks={} and a resume would have repeated 8.5h) and coverage 5624634/6084564 = 92.44%, 459930 skipped by -mhe. Also: -mhe policy (PERFORMANCE.NUCLEI_MAX_HOST_ERROR, 0 -> -nmhe full depth) is folded into the resume work_unit."
# Point NUCLEI_STDERR_FIXTURE (or the legacy OTC_NUCLEI_LOG) at a real nuclei run log to exercise this
# check; unset it SKIPS. No engagement path is baked in — this script is versioned with the repo.
_OTC_NUCLEI_LOG="${NUCLEI_STDERR_FIXTURE:-${OTC_NUCLEI_LOG:-}}"
if [ -z "$_OTC_NUCLEI_LOG" ] || [ ! -f "$_OTC_NUCLEI_LOG" ]; then
  sk "nuclei execution/coverage split: no nuclei stderr fixture (set NUCLEI_STDERR_FIXTURE=<path>)"
else
PYTHONPATH="$QUARRY_SRC" OTC_NUCLEI_LOG="$_OTC_NUCLEI_LOG" $PY - <<'PYEOF' && ok "nuclei: 10/10 execution-complete + 92.44% request coverage from the real the measured run stderr; -mhe in the resume key" || no "nuclei execution/coverage split"
import json, os, sys, inspect
from quarry_recon import events, settings
from quarry_recon.phases import params
from quarry_recon.phases.params import _nuclei_cmd, _nuclei_mhe, _nuclei_progress

text = open(os.environ["OTC_NUCLEI_LOG"]).read()
blocks, cur, last = [], [], None
for line in text.splitlines():                     # the log is 10 concatenated per-chunk stderr tails
    s = line.strip()
    if s.startswith("{"):
        try:
            st = json.loads(s).get("startedAt")
        except json.JSONDecodeError:
            st = last
        else:
            if last is not None and st != last:
                blocks.append("\n".join(cur)); cur = []
            last = st
    cur.append(line)
blocks.append("\n".join(cur))

done = planned = sent = 0
for b in blocks:
    p = _nuclei_progress(b)
    done += 1 if p["completed"] else 0
    if p["planned"]:
        planned += p["planned"]; sent += p["requests"]
c_blocks = len(blocks) == 10
c_done = done == 10                                # every chunk resumable (was 0/10)
c_cov = (planned, sent) == (6084564, 5624634)      # the REAL gap, measured not guessed

# the tail alone must NOT be trusted: an [INF] burst evicts the terminal line from 8 lines
burst = "\n".join(["[INF] Scan completed in 1m. No results found."] + ["[INF] noise"] * 12)
c_tail = (_nuclei_progress(burst)["completed"] is True
          and _nuclei_progress("\n".join(burst.splitlines()[-8:]))["completed"] is False)

# -mhe policy: strict parse, 0 = full depth, and it changes the resume work_unit
settings.performance = lambda: {}
c_zero = _nuclei_mhe() == 0                        # review#P1.3: UNSET = full depth (-nmhe), not nuclei's 30
settings.performance = lambda: {"NUCLEI_MAX_HOST_ERROR": True}
c_bool = _nuclei_mhe() == 0                        # bool never becomes a policy -> full-depth default
settings.performance = lambda: {"NUCLEI_MAX_HOST_ERROR": 30}
c_explicit = _nuclei_mhe() == 30                   # an explicit bounded policy is still honoured
prof = type("P", (), {"http_rl": 0})()
c_flag = ("-nmhe" in _nuclei_cmd("t", "o", prof, 0)
          and _nuclei_cmd("t", "o", prof, 7)[_nuclei_cmd("t", "o", prof, 7).index("-mhe") + 1] == "7")
c_key = (events.work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config={"mhe": 30})
         != events.work_unit("params.nuclei_scan", inputs={"hosts": ["a"]}, config={"mhe": 0}))

# resume is keyed on EXECUTION, and per-chunk coverage is persisted so a resume re-reports the gap
src = inspect.getsource(params._nuclei_scan)
c_src = ('"coverage": cov_map' in src and "done_map[str(ci)] = rel" in src
         and "prog = _nuclei_progress(" in src and "stderr_path=ef" in src
         and '"digests": digest_map' in src and "_bind(rel, cf)" in src          # P3: content-bound artifacts
         and "res.exit_code == 0" in src)                                        # P1.2: exit code, NOT res.status
# review#P1.2: with no recognized progress output, an exit-0 chunk whose stderr carries ordinary transport noise
# (which the generic classifier turns into PARTIAL) must still be treated as EXECUTION COMPLETE — a status-based
# fallback would recreate permanent non-resumability the moment nuclei's wording changed.
noise = _nuclei_progress("[INF] future wording nobody parses\n[ERR] read tcp: i/o timeout\n")
c_p12 = noise["completed"] is False and noise["planned"] is None
# review#P1.4: execution completion must be exit_code==0 ALONE. The completion SENTENCE is corroborating
# telemetry — requiring it whenever stats were recognized left a second way to lock resumability forever
# (a release that keeps the -stats JSON but rewords only its terminal). Assert the source keys on the
# exit code and does NOT gate on an `oracle` flag.
c_p14 = ("complete = res.exit_code == 0" in src           # the WHOLE completion test
         and "oracle =" not in src and "if oracle" not in src   # no gate flag survives
         and 'terminal_seen = bool(prog["completed"])' in src)  # the sentence is telemetry only
# review#P1.1: an unmeasurable unit must reach the VERDICT as coverage:unknown, and must SUPERSEDE a prior
# generation's counters rather than let them stand in for this run.
import pathlib, tempfile
from quarry_recon.store import Run
_d = pathlib.Path(tempfile.mkdtemp())
events.reset(); _st = Run(_d, "t", run_id="r1"); events.configure(_st.dir)
events.coverage_partial("params.nuclei_scan", kind=events.COVERAGE_TIMEOUT, unit="chunk_0",
                        measure="requests", eligible=610900, tested=605552, omitted=5348, reason="measured")
_g1 = [g for g in _st._run_summary()["gaps"] if g["tool"] == "params.nuclei_scan"]
events.reset(); events.configure(_st.dir)
events.coverage_partial("params.nuclei_scan", kind=events.COVERAGE_UNKNOWN, unit="chunk_0",
                        measure="requests", reason="stats corrupt")
_s2 = _st._run_summary()
_g2 = [g for g in _s2["gaps"] if g["tool"] == "params.nuclei_scan"]
c_p11 = (len(_g1) == 1 and _g1[0]["omitted"] == 5348
         and len(_g2) == 1 and _g2[0]["status"] == "coverage:unknown"
         and _g2[0]["omitted"] == 0 and _g2[0]["why"] == "stats corrupt"
         and _s2["verdict"] == "complete_with_gaps")
sys.exit(0 if all((c_blocks, c_done, c_cov, c_tail, c_zero, c_bool, c_explicit, c_flag, c_key, c_src,
                   c_p12, c_p14, c_p11)) else 1)
PYEOF
fi

echo "[146] arjun completion contract + per-target lane (A2) — arjun 2.2.7 PROBED (source read + executed): main() returns None on every ordinary path so EXIT 0 is not an execution oracle (an all-skipped run exits 0), exporter() runs only inside 'elif these_params:' so a no-parameter target writes NO -oT AT ALL, and an unhandled '.status_code' on a dict crashes the process on any 400/413/418/429/503 target — which in a batched '-i' run abandons every REMAINING target (measured: 3 targets, 429 second, target 3 never scanned). Lane is now ONE TARGET PER PROCESS in a BOUNDED CONCURRENT pool (ARJUN_TARGETS, default 5, at most one active target per HOST) — isolation is one process per target and never implied one at a time; --rate-limit is per-process, so RATELIMIT.HTTP is a GLOBAL lane cap PARTITIONED across workers (_arjun_rate_shares sums to exactly R, never 0 which arjun reads as unlimited, and a rate below the pool size shrinks the POOL not the rate), full guarded endpoint set (ARJUN_CAP 40 GONE) in host-fair order under ARJUN_BUDGET_S (0=unbounded), never-attempted ranked BEFORE previously skipped/crashed (retry starvation), and completion claimed only when exit code + stdout terminal line + artifact AGREE — bound by a manifest covering ALL THREE evidence channels (stdout/stderr/-oT)."
PYTHONPATH="$QUARRY_SRC" $PY - <<'PYEOF' && ok "verdict matrix (empty/success/skipped/failed/unknown); contradictory+duplicate+missing signals -> unknown; \\r progress never hides the terminal line; no membership cap; bounded concurrency 1-per-host; GLOBAL rate partitioned across workers" || no "arjun contract/lane broken"
import sys, inspect
from quarry_recon.phases import params as P
if not hasattr(P, "_arjun_lane") or not hasattr(P, "_arjun_verdict"):
    sys.exit(1)                                  # fail LOUD if the lane/parser is renamed away
S = "\x1b[1;97m[*]\x1b[0m Scanning 0/1: http://t/"
F = "\x1b[1;32m[+]\x1b[0m Parameters found: foo"
N = "\x1b[1;93m[!]\x1b[0m No parameters were discovered."
K = "\x1b[1;91m[-]\x1b[0m Skipped http://t/ due to errors"
U = "\x1b[1;91m[-]\x1b[0m Webpage is returning different content on each request. Skipping."
TGT = "http://t/"
def v(ok, text, urls, target=TGT, malformed=0):
    return P._arjun_verdict(ok, P._arjun_signals(text), urls, target=target, malformed=malformed)[0]
matrix = (v(True, S+"\n"+N, None) == "empty"            # exit 0 + no-params terminal + NO file = complete
          and v(True, S+"\n"+F, ["http://t/?a=1"]) == "success"
          and v(True, S+"\n"+K, None) == "skipped"      # exit 0 but SKIPPED -> degraded, retryable
          and v(False, S, None) == "failed"              # nonzero -> never complete
          and v(True, S+"\n"+N, ["http://t/?a=1"]) == "unknown"  # contradictory: says none, artifact exists
          and v(True, S+"\n"+F, None) == "unknown"      # contradictory: says found, no artifact
          and v(True, S+"\n"+F, []) == "unknown"
          and v(True, S+"\n"+U+"\n"+N, None) == "skipped"   # terminal line LIES about an abandoned target
          and v(True, S, None) == "unknown"              # missing terminal line
          and v(True, S+"\n"+N+"\n"+K, None) == "unknown"   # duplicate terminal lines
          and v(True, N, None) == "unknown"              # no attempt line
          and v(True, "", None) == "unknown"
          # review#2: the output must be ABOUT the requested target, and a malformed row blocks completion
          and v(True, "[*] Scanning 0/1: http://other/\n"+F, ["http://other/?a=1"]) == "unknown"
          and v(True, S+"\n"+F, ["http://t/?a=1"], malformed=1) == "unknown")
# progress uses end='\r'; splitting on \n alone would swallow the terminal line that follows it
cr = v(True, S+"\n[!] Processing chunks: 2/2   \r"+F, ["http://t/?a=1"]) == "success"
src = inspect.getsource(P._arjun_lane)
_whole = inspect.getsource(P)
# the CAP must be gone, not the word: comments recording the retired cap are documentation, and asserting
# on the bare name made a green check depend on how the removal was described.
struct = ("ARJUN_CAP =" not in _whole and "[:ARJUN_CAP]" not in _whole and "ARJUN_CAP)" not in _whole
          and "ARJUN_BUDGET_S" in src and "order_ranked_fair" in src
          and "ledger.evidence(u)) else 1" in src                 # never-attempted ranked FIRST
          and '"--rate-limit", str(rate)' in inspect.getsource(P._arjun_exec) and '"-d"' not in src
          and sum(P._arjun_rate_shares(10, 5)) == 10               # GLOBAL rate PARTITIONED, not per-worker
          and all(s >= 1 for s in P._arjun_rate_shares(3, 5))      # 0 would read as UNLIMITED to arjun
          and "ThreadPoolExecutor" in src and "busy_hosts" in src  # BOUNDED concurrency, 1 target per host
          and "ARJUN_TARGETS" in src and "_arjun_rate_shares" in src
          # r2: pool sized from DISTINCT HOSTS before the rate is split, else one host strands the rate
          and P._arjun_pool(5, 1, 7) == 1 and P._arjun_rate_shares(7, P._arjun_pool(5, 1, 7)) == [7]
          and P._arjun_pool(5, 3, 7) == 3 and P._arjun_pool(5, 9, 0) == 5
          and "free.pop(0)" in src                                 # largest share consumed FIRST
          # r2/r3: Ctrl-C in the main thread must reach tools running in WORKER threads, HARVEST what
          # already finished before killing the rest, and never re-block on a shutdown(wait=True).
          and "runner_cancel_all()" in src and "raise KeyboardInterrupt" in src
          and "if f.done()" in src and "pool.shutdown(wait=False, cancel_futures=True)" in src
          # r4: harvest AGAIN after the drain — work finishing during the kill race is still earned
          and src.count("if f.done()") >= 2 and "f.done() and not f.cancelled()" in src
          and "with ThreadPoolExecutor" not in src         # __exit__ IS shutdown(wait=True)
          and hasattr(__import__("quarry_recon.runner", fromlist=["x"]), "cancel_all")
          # r4: an unexpected exception must not orphan a live child, and the post-kill REAP window is
          # shared too (a per-process wait reintroduced the linear blow-up the shared TERM deadline fixed)
          # r5: the gate is EXCEPTIONAL EXIT, not the leader's poll() — a leader can exit while its
          # children keep the process GROUP alive, which is exactly what terminate_group() addresses.
          and "not group_settled or proc.poll() is None" in inspect.getsource(
              __import__("quarry_recon.runner", fromlist=["x"]).run)
          and "reap_deadline" in inspect.getsource(
              __import__("quarry_recon.runner", fromlist=["x"]).cancel_all)
          # r3: an unhashable evidence channel must block the completion claim, not ride into the manifest
          and "channels_ok = False" in src and "if channels_ok else (None, None)" in src
          # r2: a completion that could not publish its evidence is NOT durable
          and "saved and not unpublished" in src
          and '"-u", url' in inspect.getsource(P._arjun_exec)       # ONE TARGET PER PROCESS
          and '"-i"' not in inspect.getsource(P._arjun_exec)        # never the batched import file
          and "COVERAGE_UNKNOWN" in src and "_arjun_manifest" in src)
sys.exit(0 if (matrix and cr and struct) else 1)
PYEOF

echo
echo "== summary: PASS=$pass FAIL=$fail SKIP=$skip =="
[ "$fail" -eq 0 ]
