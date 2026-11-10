"""T-e: scan tracked files for e-mail addresses, phone numbers, keys/tokens,
and (optionally) a private deny-list of names kept OUTSIDE the repo.
Usage: python3 tools/public_safe_check.py [--denylist FILE]"""
import re, subprocess, sys
from pathlib import Path

ALLOWED_EMAILS = {"info@thatched.ai"}
# Exact strings inside vendored third-party test corpora (not personal data): WPT urltestdata
# userinfo cases and the 2^32 boundary port numbers. Only these strings, only in this file;
# the deny-list still applies to it.
VENDORED_OK = {"data/vectors/wpt-urltestdata-http.json": {"foobar@foodomain.com", "www.@pple.com", "4294967295", "4294967296"}}
# AgentDojo 0.1.35 synthetic benchmark accounts inside batch 10 run records (no personal data):
# the suites' fake users and company domains (a JSON escape such as u202f or n may be glued on),
# and one benchmark account number printed with spaces. Only under this path; deny-list still applies.
AGENTDOJO_RUNS = "repeats/batch10/runs/"
AGENTDOJO_EMAIL = re.compile(r"(?:u[0-9a-f]{4}|n)?(?:(?:dora|fred9246)@gmail\.com|[a-z0-9._%+-]+@(?:yourcompany|bluesparrowtech)\.com)", re.I)
AGENTDOJO_DIGITS = {"3012400231215421872"}
RESERVED_DOMAIN = re.compile(r"@(?:[a-z0-9-]+\.)*(?:example\.(?:com|net|org)|[a-z0-9-]+\.(?:test|example|invalid))$", re.I)
PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?<![\w:.-])(?:\+\d{1,3}[ -]?)?(?:\(?\d{2,5}\)?[ -]?){2,4}\d{3,4}(?![\w.-])"),
    "key_or_token": re.compile(r"(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[bp]-[A-Za-z0-9-]{10,}|"
                               r"-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,})"),
}
root = Path(__file__).resolve().parent.parent
files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=root, capture_output=True, text=True).stdout.split()
deny = []
if "--denylist" in sys.argv:
    deny = [l.strip() for l in open(sys.argv[sys.argv.index("--denylist") + 1]) if l.strip() and not l.startswith("#")]
hits = []
for f in files:
    p = root / f
    if f.startswith("tools/public_safe_check.py") or not p.is_file():
        continue
    text = p.read_text("utf-8", "replace")
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            s = m.group(0)
            if s in VENDORED_OK.get(f, ()):
                continue
            if f.startswith(AGENTDOJO_RUNS) and (kind == "email" and AGENTDOJO_EMAIL.fullmatch(s)
                                                 or kind == "phone" and re.sub(r"\D", "", s) in AGENTDOJO_DIGITS):
                continue
            if kind == "email" and (s in ALLOWED_EMAILS or RESERVED_DOMAIN.search(s)):
                continue  # RFC 2606 / 6761 reserved names can never reach a real mailbox
            if kind == "phone" and (re.fullmatch(r"[\d-]{10}", s) and s.count("-") == 2 or len(re.sub(r"\D", "", s)) < 10):
                continue  # ISO dates and short numbers
            if kind == "phone" and re.fullmatch(r"\d{11,}", s):
                continue  # long digit runs inside hashes/timestamps
            hits.append((f, kind, s))
    low = text.lower()
    for d in deny:
        if d.lower() in low:
            hits.append((f, "denylist", "<redacted deny-list entry>"))
for h in hits:
    print(*h, sep="\t")
print(f"{len(files)} files scanned, {len(hits)} hits", "(deny-list used)" if deny else "(no deny-list)")
sys.exit(1 if hits else 0)
