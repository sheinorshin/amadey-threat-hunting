#!/usr/bin/env python3
"""
normalize_iocs.py — Week 3 processing pipeline for the Amadey IOCs collected in Week 2.

  raw files (TXT, STIX 2.1, Markdown tables)
    -> 1 ingest  -> 2 refang -> 3 type detection -> 4 validation -> 5 canonicalisation
    -> 6 family/role attribution -> 7 de-duplication (cross-source correlation)
    -> 8 derivation (URL -> host) -> 9 filtering (allowlist, decay/TTL, infra status, context-only)
    -> 10 confidence scoring + ATT&CK tag normalisation
    -> outputs: CSV, JSON, rejected list, blocklists, pipeline report

Standard library only.  Usage (from this folder):
    python normalize_iocs.py                      # uses default paths
    python normalize_iocs.py --as-of 2026-10-02   # reproduce the committed output
"""
import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
RAW_DIR = HERE.parents[1] / "week-02-data-collection" / "data" / "raw"
ENRICH_CSV = HERE.parents[1] / "week-02-data-collection" / "data" / "enrichment" / "infrastructure_enrichment_2026-10-02.csv"
OUT_DIR = HERE.parent / "output"

NS = uuid.UUID("6f1c2a3e-0d6b-4a43-9a8e-a1b2c3d4e5f6")  # fixed namespace -> stable UUIDs across runs

# ---- source metadata (from week-02/data/raw/SOURCES.md) -------------------------------
SOURCES = {
    "talos_2025-07_emmenhtal-amadey.txt":       {"name": "Cisco Talos",  "published": "2025-07-17", "admiralty": "A2"},
    "talos_2025-07_emmenhtal-amadey.stix2.json": {"name": "Cisco Talos", "published": "2025-07-15", "admiralty": "A2"},
    "trellix_2025-12-18_amadey-gitlab.md":      {"name": "Trellix",      "published": "2025-12-18", "admiralty": "A2"},
    "microsoft_2026-06-24_stealc-amadey.md":    {"name": "Microsoft",    "published": "2026-06-24", "admiralty": "A2"},
    "splunk_2023-07-25_amadey.txt":             {"name": "Splunk",       "published": "2023-07-25", "admiralty": "A2"},
}

# ---- filtering knowledge --------------------------------------------------------------
ALLOWLIST_DOMAINS = {"github.com", "githubusercontent.com", "gitlab.com", "microsoft.com",
                     "windowsupdate.com", "google.com", "cloudflare.com", "amazonaws.com"}
COMPROMISED_LEGIT_PARENTS = {"bzctoons.net"}       # legit org whose GitLab was abused (Trellix)
TTL_DAYS = {"ip": 90, "domain": 180, "url": 180}   # hashes / host artefacts don't expire
DEPRECATED_ATTACK = {"T1158": "T1564.001",          # Hidden Files and Directories (old ID)
                     "T1562.004": "T1686"}         # Disable/Modify System Firewall (revoked in ATT&CK v19)

# declared types written in vendor tables -> our canonical types
DECLARED = {
    "sha-256": "sha256", "sha256": "sha256", "c2 url": "url", "url": "url", "ip": "ip",
    "domain": "domain", "mutex": "mutex", "bot id": "bot_id", "decryption key": "crypto_key",
    "directory": "directory", "file": "filename", "task": "scheduled_task",
}

RE_HEX = re.compile(r"^[0-9a-fA-F]+$")
RE_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


# =========================== 1. INGEST ==================================================
def ingest_txt(path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        yield {"raw": parts[0], "declared": "", "desc": parts[1] if len(parts) > 1 else ""}


def ingest_stix(path):
    bundle = json.loads(path.read_text(encoding="utf-8"))
    pat = re.compile(r"(file:hashes\.'?SHA-?256'?|url:value|domain-name:value|dst_ref\.value)\s*=\s*'([^']+)'")
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            for _, val in pat.findall(obj.get("pattern", "")):
                yield {"raw": val, "declared": "", "desc": obj.get("name") or ""}


def stix_attack_ids(path):
    ids = []
    for obj in json.loads(path.read_text(encoding="utf-8")).get("objects", []):
        if obj.get("type") == "attack-pattern":
            m = re.search(r"T\d{4}(?:\.\d{3})?", obj.get("name", ""))
            if m:
                ids.append(m.group(0))
    return ids


def ingest_md(path):
    header = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("|"):
            header = None if not line.strip() else header
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(set(c) <= set("-: ") for c in cells):
            continue
        if header is None:
            header = [c.lower() for c in cells]
            continue
        row = dict(zip(header, cells))
        value = row.get("indicator") or row.get("value", "")
        yield {"raw": value, "declared": row.get("type", ""), "desc": row.get("description", "")}


def ingest_all(raw_dir):
    records, attack_ids = [], []
    for fname, meta in SOURCES.items():
        p = raw_dir / fname
        if fname.endswith(".json"):
            gen = ingest_stix(p)
            attack_ids += stix_attack_ids(p)
        elif fname.endswith(".md"):
            gen = ingest_md(p)
        else:
            gen = ingest_txt(p)
        for r in gen:
            r.update(source_file=fname, source=meta["name"], published=meta["published"], admiralty=meta["admiralty"])
            records.append(r)
    return records, attack_ids


# =========================== 2. REFANG ==================================================
def refang(v):
    v = v.strip().strip("`")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"^fxp", "ftp", v, flags=re.I)
    return v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[:]", ":").replace("[/]", "/")


# =========================== 3-5. TYPE / VALIDATE / CANONICALISE ========================
def detect_type(value, declared):
    d = DECLARED.get(declared.strip().lower())
    if d:                       # vendor told us -> trust it (a 32-hex mutex is NOT an MD5!)
        return d
    if RE_HEX.match(value):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "invalid_hash")
    if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        return "url"
    try:
        ipaddress.IPv4Address(value)
        return "ip"
    except ValueError:
        pass
    return "domain" if "." in value and " " not in value else "unknown"


def validate_and_canon(t, v):
    """return (canonical_value, None) or (None, reject_reason)"""
    if t == "invalid_hash":
        return None, f"malformed hash: {len(v)} hex chars (expected 32/40/64) - truncated in source"
    if t in ("md5", "sha1", "sha256"):
        exp = {"md5": 32, "sha1": 40, "sha256": 64}[t]
        if len(v) != exp or not RE_HEX.match(v):
            return None, f"invalid {t}: length {len(v)}"
        return v.lower(), None
    if t == "ip":
        try:
            ip = ipaddress.IPv4Address(v)
        except ValueError:
            return None, "invalid IPv4"
        if not ip.is_global:
            return None, "non-routable IP (private/reserved)"
        return str(ip), None
    if t == "domain":
        d = v.lower().rstrip(".")
        if not RE_DOMAIN.match(d):
            return None, "invalid domain syntax"
        return d, None
    if t == "url":
        try:
            s = urlsplit(v)
        except ValueError:
            return None, "unparseable URL"
        if s.scheme.lower() not in ("http", "https", "ftp") or not s.hostname:
            return None, "URL without valid scheme/host"
        netloc = s.hostname.lower() + (f":{s.port}" if s.port else "")
        return urlunsplit((s.scheme.lower(), netloc, s.path or "/", s.query, "")), None
    if t == "directory":
        return re.sub(r"%(\w+)%", lambda m: f"%{m.group(1).upper()}%", v.rstrip("\\") + "\\"), None
    if t in ("mutex", "filename", "scheduled_task", "bot_id", "crypto_key"):
        return v.strip(), None
    return None, "unknown indicator type"


# =========================== 6. FAMILY / ROLE ===========================================
def attribute(t, value, desc, source):
    d = desc.lower()
    if "stealc" in d:
        family = "StealC"
    elif "amadey" in d or "cred64" in d or "clip64" in d or "clipper" in d:
        family = "Amadey"
    elif "gitlab" in d or "parent domain" in d:
        family = "StealC"            # Trellix: GitLab hosted the StealC payload pulled by Amadey
    elif source == "Cisco Talos":
        family = "Amadey-campaign"   # Talos list is not labelled per indicator (Emmenhtal/Amadey MaaS)
    else:
        family = "Amadey"

    if t in ("md5", "sha1", "sha256"):
        role = "plugin" if ("plugin" in d or "dll" in d) else "sample"
    elif t in ("url", "domain", "ip"):
        if "c2" in d or "check-in" in d or value.endswith("/index.php") or value.endswith(".php"):
            role = "c2"
        elif "download" in d or "gitlab" in d or "parent" in d or re.search(r"\.(exe|mp4|zip)$", value):
            role = "payload-host"
        else:
            role = "network-unlabelled"
    elif t in ("bot_id", "crypto_key"):
        role = "context"
    else:
        role = "host-artefact"
    return family, role


# =========================== 9. FILTER helpers ==========================================
def load_infra_status(path):
    status = {}
    if not path.exists():
        return status
    for row in csv.DictReader(path.open(encoding="utf-8")):
        announced = row.get("prefix_announced_2026-10-02", "")
        notes = row.get("notes", "").lower()
        if announced.startswith("no"):
            status[row["indicator"]] = "infrastructure offline (BGP prefix withdrawn)"
        elif "re-assigned" in notes or "decayed" in notes:
            status[row["indicator"]] = "IP re-assigned to unrelated host (Shodan, 2026-10-02)"
    return status


def registered_domain(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# =========================== MAIN PIPELINE ==============================================
def run(as_of, raw_dir=RAW_DIR, out_dir=OUT_DIR, enrich_csv=ENRICH_CSV):
    steps = []
    records, attack_ids = ingest_all(raw_dir)
    steps.append(("1 Ingest", len(records), "TXT + STIX 2.1 + Markdown tables from 5 publishers"))

    defanged = sum(1 for r in records if re.search(r"\[\.\]|hxxp|\[:\]", r["raw"], re.I))
    for r in records:
        r["value"] = refang(r["raw"])
    steps.append(("2 Refang", len(records), f"{defanged} values were defanged"))

    rejected, valid = [], []
    for r in records:
        r["type"] = detect_type(r["value"], r["declared"])
    steps.append(("3 Type detection", len(records), str(dict(Counter(r["type"] for r in records)))))

    for r in records:
        canon, reason = validate_and_canon(r["type"], r["value"])
        if reason:
            rejected.append({**r, "reason": reason})
        else:
            r["value"] = canon
            valid.append(r)
    steps.append(("4-5 Validate + canonicalise", len(valid), f"{len(rejected)} rejected"))

    for r in valid:
        r["family"], r["role"] = attribute(r["type"], r["value"], r["desc"], r["source"])
    steps.append(("6 Family + role attribution", len(valid), str(dict(Counter(r["family"] for r in valid)))))

    # 7. de-duplicate / correlate
    merged = {}
    for r in valid:
        k = (r["type"], r["value"])
        m = merged.setdefault(k, {"type": r["type"], "value": r["value"], "family": r["family"], "role": r["role"],
                                  "sources": set(), "source_files": set(), "descriptions": set(),
                                  "first_seen": r["published"], "last_seen": r["published"], "derived": False})
        m["sources"].add(r["source"])
        m["source_files"].add(r["source_file"])
        if r["desc"]:
            m["descriptions"].add(r["desc"])
        m["first_seen"] = min(m["first_seen"], r["published"])
        m["last_seen"] = max(m["last_seen"], r["published"])
        if m["family"] == "Amadey-campaign" and r["family"] != "Amadey-campaign":
            m["family"], m["role"] = r["family"], r["role"]
    dupes = len(valid) - len(merged)
    multi_src = sum(1 for m in merged.values() if len(m["sources"]) > 1)
    multi_file = sum(1 for m in merged.values() if len(m["source_files"]) > 1)
    steps.append(("7 De-duplicate", len(merged),
                  f"{dupes} duplicates merged; {multi_file} values seen in >1 file; {multi_src} confirmed by >1 publisher"))

    # 8. derive host indicators from URLs
    derived = 0
    for m in list(merged.values()):
        if m["type"] != "url":
            continue
        host = urlsplit(m["value"]).hostname
        try:
            ipaddress.IPv4Address(host)
            ht = "ip"
        except ValueError:
            ht = "domain"
        k = (ht, host)
        if k in merged:
            merged[k]["sources"] |= m["sources"]
            continue
        merged[k] = {"type": ht, "value": host, "family": m["family"], "role": m["role"],
                     "sources": set(m["sources"]), "source_files": set(m["source_files"]),
                     "descriptions": {f"derived from URL {m['value']}"},
                     "first_seen": m["first_seen"], "last_seen": m["last_seen"], "derived": True}
        derived += 1
    steps.append(("8 Derive hosts from URLs", len(merged), f"+{derived} IP/domain indicators derived"))

    # 9. filtering -> to_ids decision
    infra = load_infra_status(enrich_csv)
    today = dt.date.fromisoformat(as_of)
    for m in merged.values():
        reasons = []
        t, v = m["type"], m["value"]
        host = urlsplit(v).hostname if t == "url" else v
        if t in ("domain", "url") and host:
            if registered_domain(host) in ALLOWLIST_DOMAINS:
                reasons.append("allowlisted legitimate service")
            if t == "domain" and v in COMPROMISED_LEGIT_PARENTS:
                reasons.append("compromised legitimate organisation - block the URL, not the whole domain")
        if t in ("bot_id", "crypto_key"):
            reasons.append("context only (not observable in logs)")
        if t in ("filename", "directory") :
            reasons.append("weak alone (generic/random per build) - use for hunting, not blocking")
        ttl = TTL_DAYS.get(t)
        age = (today - dt.date.fromisoformat(m["last_seen"])).days
        m["age_days"] = age
        if ttl and age > ttl:
            reasons.append(f"expired: {age} days old > TTL {ttl}")
        ip_for_status = v if t == "ip" else (host if t == "url" else None)
        if ip_for_status in infra:
            reasons.append(infra[ip_for_status])
        m["expires"] = (dt.date.fromisoformat(m["last_seen"]) + dt.timedelta(days=ttl)).isoformat() if ttl else ""
        m["to_ids"] = not reasons
        m["filter_reasons"] = "; ".join(reasons)

    # 10. confidence
    for m in merged.values():
        score = 70 + 10 * (len(m["sources"]) - 1)               # A2 base, +10 per extra publisher
        if m["family"] == "Amadey-campaign":
            score -= 20                                        # unlabelled in source
        if m["derived"]:
            score -= 10
        if not m["to_ids"] and "expired" in m["filter_reasons"]:
            score -= 20
        m["confidence_score"] = max(0, min(score, 100))
        m["confidence"] = "High" if score >= 70 else "Medium" if score >= 40 else "Low"

    to_ids = sum(1 for m in merged.values() if m["to_ids"])
    steps.append(("9-10 Filter + score", len(merged), f"{to_ids} actionable (to_ids=true), {len(merged) - to_ids} context-only"))

    attack_norm = sorted({DEPRECATED_ATTACK.get(t, t) for t in attack_ids})
    write_outputs(merged, rejected, steps, attack_ids, attack_norm, as_of, out_dir)
    return merged, rejected, steps


# =========================== OUTPUT =====================================================
def write_outputs(merged, rejected, steps, attack_raw, attack_norm, as_of, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    order = ["sha256", "sha1", "md5", "url", "domain", "ip", "mutex", "scheduled_task", "directory",
             "filename", "bot_id", "crypto_key"]
    rows = sorted(merged.values(), key=lambda m: (order.index(m["type"]) if m["type"] in order else 99,
                                                  m["family"], m["value"]))
    fields = ["uuid", "type", "value", "family", "role", "to_ids", "confidence", "confidence_score",
              "first_seen", "last_seen", "age_days", "expires", "sources", "derived", "filter_reasons", "description"]
    out_rows = []
    for m in rows:
        out_rows.append({
            "uuid": str(uuid.uuid5(NS, f"{m['type']}|{m['value']}")),
            "type": m["type"], "value": m["value"], "family": m["family"], "role": m["role"],
            "to_ids": m["to_ids"], "confidence": m["confidence"], "confidence_score": m["confidence_score"],
            "first_seen": m["first_seen"], "last_seen": m["last_seen"], "age_days": m["age_days"],
            "expires": m["expires"], "sources": ";".join(sorted(m["sources"])), "derived": m["derived"],
            "filter_reasons": m["filter_reasons"], "description": " | ".join(sorted(m["descriptions"])),
        })
    with (out_dir / "iocs_normalized.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(out_rows)
    (out_dir / "iocs_normalized.json").write_text(json.dumps(
        {"generated": as_of, "attack_techniques": attack_norm, "count": len(out_rows), "indicators": out_rows},
        indent=2), encoding="utf-8")

    with (out_dir / "iocs_rejected.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["raw", "type", "source", "source_file", "reason"])
        w.writeheader()
        for r in rejected:
            w.writerow({k: r[k] for k in ["raw", "type", "source", "source_file", "reason"]})

    bl = out_dir / "blocklists"
    bl.mkdir(exist_ok=True)
    for t in ("sha256", "domain", "url", "ip"):
        vals = [r["value"] for r in out_rows if r["type"] == t and r["to_ids"]]
        body = "\n".join(vals) + "\n" if vals else f"# no actionable {t} indicators as of {as_of} (all expired, offline or re-assigned)\n"
        (bl / f"{t}.txt").write_text(body, encoding="utf-8")

    # ---------- report ----------
    by_type = Counter(r["type"] for r in out_rows)
    by_type_ids = Counter(r["type"] for r in out_rows if r["to_ids"])
    by_family = Counter(r["family"] for r in out_rows)
    reasons = Counter()
    for r in out_rows:
        for x in filter(None, r["filter_reasons"].split("; ")):
            reasons[re.sub(r"\d+ days old > TTL \d+", "older than TTL", x)] += 1
    L = [f"# Pipeline report (as of {as_of})", "",
         "Generated by `scripts/normalize_iocs.py` — do not edit by hand.", "",
         "## Steps", "", "| Step | Records out | Notes |", "|---|---|---|"]
    L += [f"| {s} | {n} | {note} |" for s, n, note in steps]
    L += ["", "## Indicators by type", "", "| Type | Total | Actionable (to_ids) |", "|---|---|---|"]
    L += [f"| {t} | {by_type[t]} | {by_type_ids.get(t, 0)} |" for t in sorted(by_type, key=lambda x: -by_type[x])]
    L += [f"| **Total** | **{len(out_rows)}** | **{sum(by_type_ids.values())}** |"]
    L += ["", "## By family", "", "| Family | Count |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in by_family.most_common()]
    L += ["", "## Rejected", "", "| Raw value | Source | Reason |", "|---|---|---|"]
    L += [f"| `{r['raw']}` | {r['source_file']} | {r['reason']} |" for r in rejected]
    L += ["", "## Why indicators were NOT marked actionable", "", "| Reason | Count |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in reasons.most_common()]
    L += ["", "## ATT&CK IDs found in STIX", "",
          f"Raw: {', '.join(attack_raw)}  ", f"Normalised: {', '.join(attack_norm)} (revoked T1158 -> T1564.001)", ""]
    (out_dir / "pipeline_report.md").write_text("\n".join(L), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as-of", default=dt.date.today().isoformat(), help="evaluation date for TTL/decay (YYYY-MM-DD)")
    ap.add_argument("--raw", type=Path, default=RAW_DIR)
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    a = ap.parse_args()
    merged, rejected, steps = run(a.as_of, a.raw, a.out)
    for s, n, note in steps:
        print(f"{s:30} {n:4}  {note}")
    print(f"\nOutputs written to {a.out}")


if __name__ == "__main__":
    main()
