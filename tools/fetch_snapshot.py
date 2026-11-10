"""One-off LIVE fetch for run 1 (the only network call in this repo).

Fetches the public Companies House overview page of a company, keeps the
visible main-content text and the list of same-company links, and writes
data/public/companies-house-<number>.txt + .meta.json. Reference runs replay
this snapshot so they reproduce offline; the meta file records the URL,
retrieval time and SHA-256 of the raw HTML actually received.

Content: Crown copyright, Companies House, Open Government Licence v3.0.

Usage: python3 tools/fetch_snapshot.py 02557590
"""
import hashlib, html, json, re, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

num = sys.argv[1] if len(sys.argv) > 1 else "02557590"
url = f"https://find-and-update.company-information.service.gov.uk/company/{num}"
req = urllib.request.Request(url, headers={"User-Agent": "agent-control-plane-evidence/0.1 (research reference run)"})
with urllib.request.urlopen(req, timeout=30) as r:
    status, raw = r.status, r.read()
retrieved = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
t = raw.decode("utf-8", "replace")
main = re.search(r'<main[^>]*>(.*?)</main>', t, re.S)
body = main.group(1) if main else t
links = sorted(set(re.findall(rf'href="(/company/{num}/[a-z-]+)"', t)))
body = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.S)
body = re.sub(r"<[^>]+>", "\n", body)
lines = [re.sub(r"\s+", " ", html.unescape(x)).strip() for x in body.splitlines()]
text = "\n".join(x for x in lines if x) + "\n"
out = Path(__file__).resolve().parent.parent / "data" / "public"
out.mkdir(parents=True, exist_ok=True)
(out / f"companies-house-{num}.txt").write_text(text, encoding="utf-8")
meta = {"source_url": url, "retrieved_at": retrieved, "http_status": status,
        "raw_html_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "raw_html_bytes": len(raw),
        "text_sha256": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
        "links_on_page": links,
        "licence": "Crown copyright, Companies House; Open Government Licence v3.0 (https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/)"}
(out / f"companies-house-{num}.meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
print(json.dumps(meta, indent=2))
