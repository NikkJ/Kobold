#!/usr/bin/env python3
"""
Kobold collector v0 (layers 1 and 2).

Layer 1: family seeds (MalwareBazaar get_siginfo/get_taginfo, ThreatFox malwareinfo).
Layer 2: recent_detections candidates, prefiltered and scored with get_info.
URLhaus: family delivery URLs (tag and signature) and URLs geofenced to the target
(e.g. BRA tag); payloads from those URLs become samples, and their hosts feed the clustering.
The target country or region (Brazil by default) comes from the 'target' block of scope.json.
Layer 3 (content) belongs to the agent triage, not here.

Standard library only. Auth-Key in ABUSECH_AUTH_KEY.

Examples:
  python3 collect.py --since 24h
  python3 collect.py --since 24h --no-threatfox --max-info 30
  python3 collect.py --fixtures fixtures.json --now "2026-10-14 18:00:00" --out data-test -v
"""
import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

MB_URL = "https://mb-api.abuse.ch/api/v1/"
TF_URL = "https://threatfox-api.abuse.ch/api/v1/"
UH_URL = "https://urlhaus-api.abuse.ch/v1/"
UH_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/%s/%s"  # format from the API's public page
MB_EXPORT = "https://mb-api.abuse.ch/v2/files/exports/%s/%s"       # same, MalwareBazaar exports page
TS_FMT = "%Y-%m-%d %H:%M:%S"


# ---------------------------------------------------------------- clients

class AbuseClient:
    """Real client. MalwareBazaar and URLhaus take form-encoded bodies, ThreatFox takes JSON.

    Thread-safe: a global limiter allows at most `rate` requests per second across all
    threads, replacing the old fixed 1 s pause per call.
    """

    def __init__(self, key, rate=4.0):
        self.key = key
        self.interval = 1.0 / max(rate, 0.1)
        self._lock = threading.Lock()
        self._next = 0.0
        self.calls = 0

    def _wait_turn(self):
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval
            self.calls += 1
        if start > now:
            time.sleep(start - now)

    def mb(self, payload):
        data = urllib.parse.urlencode(payload).encode()
        return self._post(MB_URL, data, "application/x-www-form-urlencoded")

    def tf(self, payload):
        return self._post(TF_URL, json.dumps(payload).encode(), "application/json")

    def uh(self, endpoint, params):
        """URLhaus: form-encoded POST to /v1/<endpoint>/ (tag, signature, url, host)."""
        data = urllib.parse.urlencode(params).encode()
        return self._post(UH_URL + endpoint + "/", data, "application/x-www-form-urlencoded")

    def uh_export(self, name="recent.csv"):
        """Official URLhaus export (last 30 days)."""
        return self._export(UH_EXPORT, name)

    def mb_export(self, name="recent.csv"):
        """Official MalwareBazaar export (samples from the last 48 h, labeled and unlabeled)."""
        return self._export(MB_EXPORT, name)

    def _export(self, pattern, name):
        """The Auth-Key goes in the path (as documented), so the URL is never printed:
        error messages only show the status code."""
        url = pattern % (urllib.parse.quote(self.key, safe=""), name)
        req = urllib.request.Request(url, headers={"User-Agent": "kobold-collector/0.1"})
        for attempt in range(3):
            self._wait_turn()
            try:
                with urllib.request.urlopen(req, timeout=180) as r:
                    raw = r.read()
                if raw[:2] == b"PK":  # compressed response
                    import io
                    import zipfile
                    with zipfile.ZipFile(io.BytesIO(raw)) as z:
                        raw = z.read(z.namelist()[0])
                return {"query_status": "ok", "text": raw.decode("utf-8", "replace")}
            except urllib.error.HTTPError as e:
                if e.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(float(e.headers.get("Retry-After") or 0) or 10)
                    continue
                return {"query_status": "error: HTTP %s" % e.code}
            except Exception as e:
                if attempt == 2:
                    return {"query_status": "error: %s" % type(e).__name__}
                time.sleep(5)

    def _post(self, url, data, ctype):
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Auth-Key": self.key, "Content-Type": ctype, "User-Agent": "kobold-collector/0.1"})
        for attempt in range(4):
            self._wait_turn()
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as e:
                if e.code in (429, 502, 503, 504) and attempt < 3:
                    # API asking us to slow down: honor Retry-After and throttle every thread
                    wait = float(e.headers.get("Retry-After") or 0) or 5 * (attempt + 1)
                    with self._lock:
                        self._next = max(self._next, time.monotonic() + wait)
                    continue
                return {"query_status": "error: HTTP %s" % e.code}
            except Exception as e:  # flaky network: retry
                if attempt == 3:
                    return {"query_status": "error: %s" % e}
                time.sleep(2 * (attempt + 1))


class FixtureClient:
    """Reads responses from a single JSON file. Key: '<api>:<query>:<parameter>', e.g. 'mb:get_siginfo:grandoreiro'."""

    def __init__(self, path):
        self.data = json.loads(Path(path).read_text(encoding="utf-8"))

    def _load(self, api, payload):
        q = payload.get("query")
        param = next((str(v) for k, v in payload.items() if k not in ("query", "limit")), "")
        key = "%s:%s:%s" % (api, q, slug(param)) if param else "%s:%s" % (api, q)
        return self.data.get(key, {"query_status": "no_results"})

    def mb(self, payload):
        return self._load("mb", payload)

    def tf(self, payload):
        return self._load("tf", payload)

    def uh(self, endpoint, params):
        return self._load("uh", dict(params, query=endpoint))

    def uh_export(self, name="recent.csv"):
        text = self.data.get("uh:export:" + name)
        return {"query_status": "ok", "text": text} if text else {"query_status": "no_results"}

    def mb_export(self, name="recent.csv"):
        text = self.data.get("mb:export:" + name)
        return {"query_status": "ok", "text": text} if text else {"query_status": "no_results"}


SHA256_RX = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_mb_export(text):
    """MalwareBazaar 'recent' export (CSV), parsed without blindly trusting its format.

    Uses the header (commented or not) when there is one. Without a header, finds the columns
    by content: sha256 (64 hex), date, signature and file name. Returns (rows, diagnostics);
    empty rows mean 'could not be parsed'."""
    import csv
    diag = {"rows_raw": 0, "rows_valid": 0, "header": None, "start": text[:80].replace("\n", " ")}
    names = {"first_seen_utc": "first_seen", "first_seen": "first_seen", "sha256_hash": "sha256",
             "sha256": "sha256", "file_name": "file_name", "filename": "file_name", "signature": "signature",
             "file_type_guess": "file_type", "file_type": "file_type", "reporter": "reporter"}
    header, lines = None, []
    for line in text.splitlines():
        if line.startswith("#"):
            cols = [names.get(re.sub(r"[^a-z0-9_]", "", c.strip().lower())) for c in line.lstrip("#").split(",")]
            if "sha256" in cols:
                header = cols
            continue
        if line.strip():
            lines.append(line)
    parsed = [[c.strip() for c in r] for r in csv.reader(lines, skipinitialspace=True)]
    if parsed and not header:
        first = [names.get(re.sub(r"[^a-z0-9_]", "", c.lower())) for c in parsed[0]]
        if "sha256" in first:
            header, parsed = first, parsed[1:]
    if header:
        diag["header"] = "read"
    elif parsed:
        sample = parsed[:300]
        width = max(len(r) for r in sample)
        if width < 3:
            return [], diag  # not the expected CSV (e.g. an HTML login page)

        def share(i, test):
            vals = [r[i] for r in sample if len(r) > i]
            return sum(1 for v in vals if test(v)) / max(len(vals), 1)

        sha_i = max(range(width), key=lambda i: share(i, lambda v: bool(SHA256_RX.match(v))))
        date_i = max(range(width), key=lambda i: share(i, lambda v: bool(DATE_RX.match(v))))
        # file name: has a dot, is not a hash, a mime type or a date
        name_i = max((i for i in range(width) if i not in (sha_i, date_i)),
                     key=lambda i: share(i, lambda v: "." in v and "/" not in v and not SHA256_RX.match(v)
                                         and not DATE_RX.match(v) and not re.fullmatch(r"[\d.]+", v)))
        header = [None] * width
        header[sha_i], header[date_i], header[name_i] = "sha256", "first_seen", "file_name"
        diag["header"] = "inferred (no signature)"
    rows = []
    for r in parsed:
        d = {h: v for h, v in zip(header or [], r) if h}
        sig = d.get("signature")
        rows.append({"sha256_hash": (d.get("sha256") or "").lower(), "first_seen": d.get("first_seen"),
                     "file_name": d.get("file_name"), "file_type": d.get("file_type"),
                     "signature": None if (sig or "").lower() in ("", "n/a", "none", "null") else sig})
    valid = [r for r in rows if SHA256_RX.match(r["sha256_hash"] or "")]
    diag["rows_raw"], diag["rows_valid"] = len(rows), len(valid)
    if not rows or len(valid) < 0.5 * len(rows):
        return [], diag
    return valid, diag


URL_RX = re.compile(r"^(https?|ftp)://", re.I)
DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _norm_col(c):
    c = re.sub(r"[^a-z_]", "", c.strip().lower())
    return {"date_added": "dateadded", "firstseen": "dateadded", "urlstatus": "url_status"}.get(c, c)


def parse_urlhaus_export(text):
    """Parses the URLhaus export without blindly trusting its format.

    Accepts JSON (a list, or a dict id -> list of entries) or CSV with a commented header,
    a plain header or no header. Without a header, finds the columns by content: URLs,
    dates and tags (the column right after 'malware_download').
    Returns (rows, diagnostics). Empty rows mean 'could not be parsed'."""
    import csv
    diag = {"format": None, "rows_raw": 0, "rows_valid": 0, "header": None, "start": text[:80].replace("\n", " ")}
    stripped = text.lstrip()

    def finish(rows):
        valid = [r for r in rows if r.get("url") and URL_RX.match(r["url"])]
        diag["rows_raw"], diag["rows_valid"] = len(rows), len(valid)
        if not rows or len(valid) < 0.5 * len(rows):
            return [], diag
        return valid, diag

    def as_tags(v):
        if isinstance(v, list):
            return [str(t).strip() for t in v if str(t).strip()]
        return [t.strip() for t in str(v or "").split(",") if t.strip() and t.strip().lower() != "none"]

    if stripped[:1] in "[{":
        diag["format"] = "json"
        try:
            data = json.loads(stripped)
        except ValueError:
            return [], diag
        entries = []
        if isinstance(data, dict):
            for v in data.values():
                entries.extend(v if isinstance(v, list) else [v])
        elif isinstance(data, list):
            entries = data
        rows = [{"url": e.get("url"), "url_status": e.get("url_status"), "threat": e.get("threat"),
                 "tags": as_tags(e.get("tags")),
                 "date_added": e.get("dateadded") or e.get("date_added") or e.get("firstseen")}
                for e in entries if isinstance(e, dict)]
        return finish(rows)

    diag["format"] = "csv"
    header, lines = None, []
    for line in text.splitlines():
        if line.startswith("#"):
            cols = [_norm_col(c) for c in line.lstrip("#").split(",")]
            if "url" in cols and ("dateadded" in cols or "tags" in cols):
                header = cols
            continue
        if line.strip():
            lines.append(line)
    parsed = list(csv.reader(lines))
    if parsed and not header:
        first = [_norm_col(c) for c in parsed[0]]
        if "url" in first and ("dateadded" in first or "tags" in first):
            header, parsed = first, parsed[1:]
    if not header and parsed:
        # No header: infer the columns from the content of the first rows.
        sample = parsed[:200]
        width = max(len(r) for r in sample)

        def share(i, test):
            vals = [r[i] for r in sample if len(r) > i]
            return sum(1 for v in vals if test(v)) / max(len(vals), 1)

        url_i = max(range(width), key=lambda i: share(i, lambda v: bool(URL_RX.match(v))))
        date_i = max(range(width), key=lambda i: share(i, lambda v: bool(DATE_RX.match(v))))
        threat_i = max(range(width), key=lambda i: share(i, lambda v: v.strip() == "malware_download"))
        status_i = max(range(width), key=lambda i: share(i, lambda v: v.strip() in ("online", "offline", "unknown")))
        tags_i = threat_i + 1 if share(threat_i, lambda v: v.strip() == "malware_download") > 0.5 else None
        header = [None] * width
        for name, i in (("url", url_i), ("dateadded", date_i), ("threat", threat_i), ("url_status", status_i)):
            header[i] = name
        if tags_i is not None and tags_i < width and header[tags_i] is None:
            header[tags_i] = "tags"
        diag["header"] = "inferred"
    else:
        diag["header"] = "read"
    rows = []
    for row in parsed:
        d = {h: v for h, v in zip(header, row) if h}
        rows.append({"url": d.get("url"), "url_status": d.get("url_status"), "threat": d.get("threat"),
                     "tags": as_tags(d.get("tags")), "date_added": d.get("dateadded")})
    return finish(rows)


class Cache:
    """Disk cache for responses that depend only on a hash or a URL (get_info,
    URLhaus URL lookups). It lives outside the --out folder, so it serves every run, including
    tests in new folders. Only 'ok' responses are stored. Default lifetime: 7 days."""

    def __init__(self, folder, ttl_days=7.0, enabled=True):
        self.folder = Path(folder)
        self.ttl = ttl_days * 86400
        self.enabled = enabled
        self.hits = 0

    def _path(self, kind, key):
        h = hashlib.sha1(key.encode("utf-8")).hexdigest()
        return self.folder / kind / h[:2] / (h + ".json")

    def get(self, kind, key):
        if not self.enabled:
            return None
        p = self._path(kind, key)
        try:
            if time.time() - p.stat().st_mtime > self.ttl:
                return None
            out = json.loads(p.read_text(encoding="utf-8"))
            self.hits += 1
            return out
        except (OSError, ValueError):
            return None

    def put(self, kind, key, value):
        if not self.enabled or value.get("query_status") != "ok":
            return
        p = self._path(kind, key)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp%d" % threading.get_ident())
            tmp.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, p)
        except OSError:
            pass


class Progress:
    """A single progress line on stderr (only when it is a terminal), for long runs."""

    def __init__(self, label, total):
        self.label, self.total, self.done = label, total, 0
        self.lock = threading.Lock()
        self.tty = sys.stderr.isatty() and total > 5

    def tick(self):
        with self.lock:
            self.done += 1
            if self.tty:
                sys.stderr.write("\r  %s: %d/%d   " % (self.label, self.done, self.total))
                sys.stderr.flush()

    def close(self):
        if self.tty:
            sys.stderr.write("\r" + " " * (len(self.label) + 30) + "\r")
            sys.stderr.flush()


def fetch_all(fn, items, workers, label=None):
    """Runs fn(item) in parallel and returns the results in the same order as items."""
    items = list(items)
    if not items:
        return []
    prog = Progress(label or "queries", len(items))

    def run_one(it):
        try:
            return fn(it)
        finally:
            prog.tick()

    if workers <= 1:
        out = [run_one(it) for it in items]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            out = list(pool.map(run_one, items))
    prog.close()
    return out


# ---------------------------------------------------------------- helpers

def slug(s):
    return re.sub(r"[^a-z0-9.]+", "-", s.lower()).strip("-")


def norm(text):
    """Lowercase, accents stripped, separators become spaces: 'NF-e_DANFE' -> 'nf e danfe'."""
    t = unicodedata.normalize("NFKD", text or "")
    t = "".join(ch for ch in t if not unicodedata.combining(ch)).lower()
    return re.sub(r"[^a-z0-9]+", " ", t).strip()


def parse_ts(s):
    """Accepts '2026-10-14 17:40:12', with or without ' UTC', 'T', 'Z' or fractional seconds."""
    if not s:
        return None
    t = str(s).strip()
    if t.upper().endswith(" UTC"):
        t = t[:-4]
    t = re.sub(r"^(\d{4}-\d{2}-\d{2})T", r"\1 ", t).rstrip("Zz")
    t = t.split(".")[0].split("+")[0].strip()
    try:
        return datetime.strptime(t, TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(t, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def parse_since(s):
    m = re.fullmatch(r"(\d+)([hd])", s.strip().lower())
    if not m:
        sys.exit("--since must look like 24h or 3d")
    n = int(m.group(1))
    return timedelta(hours=n) if m.group(2) == "h" else timedelta(days=n)


def vendor_families(vendor_intel):
    """Collects family names from any vendor, regardless of each vendor's format."""
    found = set()
    keys = {"malware_family", "family", "detection", "malware"}

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in keys and isinstance(v, str) and v:
                    found.add(norm(v).replace(" ", ""))
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(vendor_intel or {})
    return found


# ---------------------------------------------------------------- target

# Generic TLDs often seen in domain tags; the target's ccTLDs are added on top of these.
GENERIC_TLDS = ("com", "net", "org", "click", "shop", "xyz", "top", "online", "site", "info", "store", "live",
                "app", "dev", "cloud", "icu", "lat", "vip", "sbs", "cfd", "io", "me", "co", "ru", "biz", "cc",
                "pro", "life", "fun", "space", "website")


class Target:
    """The country or region Kobold tracks, read from the 'target' block of scope.json.

    Without that block, the defaults reproduce the original Brazil setup, so older scope
    files keep working. Every field is optional:
      name                  label used in the console and in the summary
      country               ISO 3166-1 alpha-2 code compared with origin_country (e.g. "BR")
      cctlds                ccTLDs that count as local infrastructure (e.g. ["br"], ["pt"], ["co.uk"])
      registry              where to check local domains before publishing (e.g. "registro.br")
      geo_tags              URLhaus geofence tags, ISO alpha-3 (e.g. ["BRA"]); urlhaus_geo_tags overrides it
      accent_regex          characters typical of the target language in file names
      accent_exclude_regex  characters that cancel the accent signal (another language that shares it)
    """

    BRAZIL = {
        "name": "Brazil",
        "country": "BR",
        "cctlds": ["br"],
        "registry": "registro.br",
        "geo_tags": ["BRA"],
        # 'ã' and 'õ' exist in Portuguese but not in Spanish, Italian or French. Only ã/õ: 'ê', 'â'
        # and 'ô' are also French and Vietnamese ('BIÊN LAI GIAO HÀNG' is Vietnamese). Vietnamese
        # also uses ã/õ, but almost always together with its own letters (đ, ư, ơ, ạ, ấ...): if
        # any of them is present, the accent does not count.
        "accent_regex": "[ãõÃÕ]",
        "accent_exclude_regex": "[đĐưƯơƠẠ-ỹ]",
    }

    def __init__(self, cfg=None):
        cfg = self.BRAZIL if cfg is None else cfg
        self.name = cfg.get("name") or cfg.get("country") or "target"
        self.country = (cfg.get("country") or "").upper() or None
        self.cctlds = sorted({t.lower().strip(".") for t in cfg.get("cctlds", []) if t.strip(".")},
                             key=len, reverse=True)
        self.registry = cfg.get("registry")
        self.geo_tags = list(cfg.get("geo_tags", []))
        self.accent = re.compile(cfg["accent_regex"]) if cfg.get("accent_regex") else None
        self.accent_exclude = re.compile(cfg["accent_exclude_regex"]) if cfg.get("accent_exclude_regex") else None

        alt = "|".join(re.escape(t) for t in self.cctlds)
        self.url_rx = re.compile(r"https?://[^\s\"'/]+\.(?:%s)(?::\d+)?(?:/|\b)" % alt, re.I) if alt else None

        # MalwareBazaar reporters often tag domains with the dot replaced by a hyphen
        # (e.g. 'saladeouroriopreto-shop'). Heuristic: only matches when the tag ends in a known TLD.
        local = []
        for cc in self.cctlds:
            dashed = cc.replace(".", "-")
            local += [p + "-" + dashed for p in ("com", "net", "org", "gov", "edu")] + [dashed]
        tlds = tuple(local) + GENERIC_TLDS
        self.infra_tag = re.compile(r"^([a-z0-9][a-z0-9-]{2,})-(" + "|".join(re.escape(t) for t in tlds) + r")$")

    def local_tld(self, host):
        """The target ccTLD the host belongs to, or None."""
        host = (host or "").lower().rstrip(".")
        return next((t for t in self.cctlds if host.endswith("." + t)), None)

    def is_local_host(self, host):
        return self.local_tld(host) is not None

    def has_accent(self, text):
        """True when the text carries the target language accent. A missing accent says
        nothing: file names usually come without accents."""
        if not self.accent:
            return False
        text = text or ""
        if self.accent_exclude and self.accent_exclude.search(text):
            return False
        return bool(self.accent.search(text))


TARGET = Target()  # replaced in run() by the target of the scope file


def infra_hints(tags):
    out = []
    for t in tags or []:
        m = TARGET.infra_tag.match(str(t).lower())
        if m:
            out.append(m.group(1) + "." + m.group(2).replace("-", "."))
    return sorted(set(out))


# ---------------------------------------------------------------- scoring

# Weight names of the first, Brazil-only scope.json, mapped to the neutral ones.
WEIGHT_ALIASES = {"br_tag": "target_tag", "br_infra": "target_infra", "origin_br": "origin_target",
                  "lure_ptbr": "lure_strong", "lure_pt": "lure_language", "accent_pt": "accent"}


def normalize_weights(weights):
    w = dict(weights)
    for old, new in WEIGHT_ALIASES.items():
        if old in w and new not in w:
            w[new] = w[old]
    return w


class Scorer:
    def __init__(self, scope):
        self.scope = scope
        self.families = {norm(f).replace(" ", "") for f in scope["families"]}
        self.watch = {norm(f).replace(" ", "") for f in scope["watch_signatures"]}
        # Neutral key names first; the Brazil-specific names of the first scope.json still work.
        self.target_tags = {t.lower() for t in scope.get("target_tags", scope.get("br_tags", []))}
        self.lure = self._terms(scope["lure_terms"])
        self.lure_lang = self._terms(scope.get("lure_terms_language", scope.get("lure_terms_pt", [])))
        self.lure_weak = self._terms(scope.get("lure_terms_weak", []))
        self.lure_hint = self._terms(scope.get("lure_terms_hint", []))
        self.other_lang = self._terms(scope.get("other_language_terms", []))
        self.w = normalize_weights(scope["weights"])
        self.th = scope["thresholds"]
        self.aliases = {norm(k).replace(" ", ""): v for k, v in scope.get("aliases", {}).items()}

    def canonical(self, name):
        """Canonical family name (e.g. Astaroth -> Guildma), so the tracker does not count twice."""
        if not name:
            return None
        return self.aliases.get(norm(name).replace(" ", ""), name)

    @staticmethod
    def _terms(terms):
        terms = sorted((norm(t) for t in terms if norm(t)), key=len, reverse=True)
        if not terms:
            return None
        # Boundary against letters only: 'NFe2341...' matches 'nfe', 'pixel' does not match 'pix'.
        return re.compile(r"(?<![a-z])(" + "|".join(re.escape(t) for t in terms) + r")(?![a-z])")

    def is_family(self, name):
        return norm(name or "").replace(" ", "") in self.families

    def is_watched(self, name):
        """'RemcosRAT' matches 'Remcos': MalwareBazaar often appends the type to the name."""
        sig = norm(name or "").replace(" ", "")
        return bool(sig) and any(sig == w or sig.startswith(w) for w in self.watch)

    def lure_hit(self, file_name):
        m = self.lure.search(norm(file_name)) if self.lure else None
        return m.group(1) if m else None

    def weak_lure_hit(self, file_name):
        m = self.lure_weak.search(norm(file_name)) if self.lure_weak else None
        return m.group(1) if m else None

    @staticmethod
    def _hit(rx, file_name):
        m = rx.search(norm(file_name)) if rx else None
        return m.group(1) if m else None

    def lure_level(self, file_name):
        """Lure in the file name, from strongest to weakest: strong (exists only in the target,
        e.g. NF-e for Brazil), language (the target language, also used elsewhere), weak (shared
        with neighbouring languages), hint."""
        for level, rx in (("strong", self.lure), ("language", self.lure_lang),
                          ("weak", self.lure_weak), ("hint", self.lure_hint)):
            t = self._hit(rx, file_name)
            if t:
                return level, t
        return None, None

    @staticmethod
    def accent_hit(file_name):
        """Accent typical of the target language (see Target.has_accent)."""
        return TARGET.has_accent(file_name)

    def tag_hit(self, tags):
        return [t for t in (tags or []) if str(t).lower() in self.target_tags]

    def priority(self, s):
        """Order for spending the get_info budget: visible target signal first."""
        name = s.get("file_name") or ""
        level, _ = self.lure_level(name)
        p = {"strong": 100, "language": 75, "weak": 50, "hint": 20}.get(level, 0)
        if self.accent_hit(name):
            p += 30
        if self._hit(self.other_lang, name) and level != "strong":
            p -= 30  # lure clearly in Spanish or Italian: goes to the back of the queue
        if self.tag_hit(s.get("tags")):
            p += 40
        if re.fullmatch(r"[0-9a-fA-F]{24,}(\.\w{1,4})?", name) or name.lower() in ("file", "file.exe", "file.bin", ""):
            p -= 5  # name carries no information
        return p

    def prefilter(self, s):
        """Decides whether this candidate is worth a get_info call."""
        name = s.get("file_name")
        return bool(self.lure_level(name)[0] or self.accent_hit(name)
                    or self.is_watched(s.get("signature")) or self.is_family(s.get("signature")))

    def lure_points(self, text):
        """Lure points in a text (file name or URL)."""
        pts, why = 0, []
        level, term = self.lure_level(text)
        if level:
            key = {"strong": "lure_strong", "language": "lure_language", "weak": "lure_weak", "hint": "lure_hint"}[level]
            pts += self.w.get(key, 0); why.append("%s:%s" % (key, term))
        if self.accent_hit(text):
            pts += self.w.get("accent", 20); why.append("accent")
        other = self._hit(self.other_lang, text)
        if other and level != "strong":
            # 'factura', 'bonifico', 'justificante'...: the lure is in another language, not the target's
            pts += self.w.get("other_language", -30); why.append("other_language:" + other)
        return pts, why

    def score_url(self, url):
        """Target signal in the URL itself: a host under a target ccTLD and lures in the host and path."""
        try:
            parts = urllib.parse.urlsplit(url)
            text = urllib.parse.unquote(parts.netloc + " " + parts.path + " " + parts.query)
        except ValueError:
            return 0, []
        pts, why = self.lure_points(text)
        if TARGET.is_local_host(host_of(url)):
            pts += self.w["target_infra"]; why.append("target_host")
        return pts, why

    def score(self, info):
        pts, why = 0, []
        fams = vendor_families(info.get("vendor_intel")) & self.families
        if fams:
            pts += self.w["vendor_family"]; why.append("vendor_family:" + ",".join(sorted(fams)))
        tags = self.tag_hit(info.get("tags"))
        if tags:
            pts += self.w["target_tag"]; why.append("target_tag:" + ",".join(tags))
        p, w = self.lure_points(info.get("file_name"))
        pts += p; why += w
        if (TARGET.url_rx and TARGET.url_rx.search(json.dumps(info, ensure_ascii=False))) or any(
                TARGET.is_local_host(h) for h in infra_hints(info.get("tags"))):
            pts += self.w["target_infra"]; why.append("target_infra")
        if TARGET.country and (info.get("origin_country") or "").upper() == TARGET.country:
            pts += self.w["origin_target"]; why.append("origin_target")
        return pts, (why or ["no_signal"])

    def decide(self, pts):
        if pts >= self.th["triage"]:
            return "triage"
        if pts >= self.th["maybe"]:
            return "maybe"
        return "drop"


# ---------------------------------------------------------------- collector

SC = None  # active Scorer, set in run()


def record(s, decision, score, why, layer):
    fam = None
    for w in why:
        if w.startswith("family_seed:"):
            fam = w.split(":", 1)[1]
        elif w.startswith("vendor_family:") and not fam:
            fam = w.split(":", 1)[1].split(",")[0]
    return {
        "sha256": s.get("sha256_hash"),
        "first_seen": s.get("first_seen"),
        "file_name": s.get("file_name"),
        "file_type": s.get("file_type"),
        "signature": s.get("signature"),
        "family": SC.canonical(fam) if (SC and fam) else fam,
        "infra_hints": infra_hints(s.get("tags")),
        "tags": s.get("tags"),
        "origin_country": s.get("origin_country"),
        "layer": layer,
        "score": score,
        "why": why,
        "decision": decision,
    }


def run(args):
    global SC, TARGET
    scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    TARGET = Target(scope.get("target"))
    sc = SC = Scorer(scope)
    now = parse_ts(args.now) if args.now else datetime.now(timezone.utc)
    cutoff = now - parse_since(args.since)

    if args.fixtures:
        client = FixtureClient(args.fixtures)
    else:
        key = os.environ.get("ABUSECH_AUTH_KEY")
        if not key:
            sys.exit("Set ABUSECH_AUTH_KEY to your abuse.ch Auth-Key (auth.abuse.ch).")
        client = AbuseClient(key, rate=args.rate)
    W = max(1, args.workers)
    cache = Cache(args.cache_dir or Path(__file__).with_name("cache"), args.cache_days,
                  enabled=not (args.no_cache or args.fixtures))
    timing = {}
    t_start = t_phase = time.monotonic()

    def lap(name):
        nonlocal t_phase
        t = time.monotonic()
        timing[name] = t - t_phase
        t_phase = t

    def cached(kind, key, fn, ttl_days=None):
        """Returns the stored response if it exists and is still valid; otherwise queries and stores it."""
        if ttl_days is not None:
            old_ttl, cache.ttl = cache.ttl, ttl_days * 86400
        try:
            hit = cache.get(kind, key)
        finally:
            if ttl_days is not None:
                cache.ttl = old_ttl
        if hit is not None:
            return hit
        value = fn()
        cache.put(kind, key, value)
        return value

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    seen_file = out / "seen.json"
    seen = set(json.loads(seen_file.read_text(encoding="utf-8"))) if seen_file.exists() else set()

    results, warnings, stats = {}, [], {"seed": 0, "candidates": 0, "info_calls": 0, "old": 0, "dup": 0}

    def in_window(s):
        ts = parse_ts(s.get("first_seen"))
        return ts is not None and ts >= cutoff

    # ---- Layer 1: family seeds
    quiet, unknown = [], []   # recognized name without activity / unrecognized name
    # Dormant families (no sample for more than N days) are queried only once a week.
    # Nothing is lost: if one comes back, layer 2's recent_detections picks up the labeled sample
    # and the family is queried daily again.
    state_file = Path(cache.folder) / "family_state.json"
    try:
        fstate = json.loads(state_file.read_text(encoding="utf-8")) if cache.enabled and state_file.exists() else {}
    except ValueError:
        fstate = {}
    dormant_after = timedelta(days=scope.get("dormant_after_days", 90))
    dormant_every = timedelta(days=scope.get("dormant_check_every_days", 7))
    query_families, skipped = [], []
    for fam in scope["families"]:
        st = fstate.get(fam, {})
        last_seen, last_checked = parse_ts(st.get("last_seen")), parse_ts(st.get("last_checked"))
        # Dormant: no sample for more than N days, or a name MalwareBazaar never recognized.
        dormant = (not st.get("known")) or last_seen is None or now - last_seen > dormant_after
        if dormant and last_checked and now - last_checked < dormant_every and not args.check_all:
            nxt = (last_checked + dormant_every - now).days + 1
            skipped.append("%s (next in %dd)" % (fam, nxt))
            continue
        query_families.append(fam)
    stats["families_skipped"] = skipped

    l1_queries = [(fam, q) for fam in query_families for q in ("get_siginfo", "get_taginfo")]
    l1_resp = dict(zip(l1_queries, fetch_all(
        lambda it: client.mb({"query": it[1], ("signature" if it[1] == "get_siginfo" else "tag"):
                              (it[0] if it[1] == "get_siginfo" else it[0].lower()), "limit": args.limit}),
        l1_queries, W, "layer 1")))
    for fam in query_families:
        in_win, recognized, last, failed = 0, False, None, False
        for q in ("get_siginfo", "get_taginfo"):
            r = l1_resp[(fam, q)]
            if str(r.get("query_status", "")).startswith("error"):
                failed = True
            if r.get("query_status") != "ok":
                continue
            recognized = recognized or bool(r.get("data"))
            for s in r.get("data") or []:
                ts = parse_ts(s.get("first_seen"))
                if ts and (last is None or ts > last):
                    last = ts
                if not in_window(s):
                    stats["old"] += 1
                    continue
                in_win += 1
                h = s.get("sha256_hash")
                if h in results:
                    continue
                if h in seen:
                    stats["dup"] += 1
                    continue
                results[h] = record(s, "triage", 100, ["family_seed:" + fam], 1)
                stats["seed"] += 1
        st = fstate.setdefault(fam, {})
        if failed:
            # A network or API error is not a check: the family is queried again on the next run.
            warnings.append("query for family %s failed; it will be retried on the next run" % fam)
        else:
            st["last_checked"] = now.strftime(TS_FMT)
        st["known"] = st.get("known") or recognized
        if last and (not parse_ts(st.get("last_seen")) or last > parse_ts(st.get("last_seen"))):
            st["last_seen"] = last.strftime(TS_FMT)
        if in_win == 0:
            if recognized:
                quiet.append("%s (last: %s)" % (fam, last.strftime("%Y-%m-%d") if last else "?"))
            else:
                unknown.append(fam)
    if quiet:
        warnings.append("recognized name, no samples in the window: " + ", ".join(quiet))
    if unknown:
        warnings.append("MalwareBazaar returned nothing for these names (probably a different name): "
                        + ", ".join(unknown))
    lap("layer 1")

    # ---- Layer 2: recent_detections -> prefilter -> get_info -> scoring
    hours = max(1, min(168, int(parse_since(args.since).total_seconds() // 3600)))
    r = client.mb({"query": "recent_detections", "hours": hours})
    recent = (r.get("data") or []) if r.get("query_status") == "ok" else []
    if r.get("query_status") != "ok":
        warnings.append("recent_detections: " + str(r.get("query_status")))
    stats["recent"] = len(recent)

    # Samples WITHOUT a family label do not show up in recent_detections. To avoid missing the
    # first-stage downloader that arrives unsigned (VBS, JS, MSI), the MalwareBazaar
    # 'recent' export (48 h, labeled and unlabeled) is downloaded at most once an hour and
    # filtered here by file name. No extra query per sample: only the ones with a target
    # signal in the name enter the get_info queue.
    export_cands = []
    if not args.no_mb_export:
        exp = cached("mb_export", "recent.csv", client.mb_export, ttl_days=1 / 24.0)
        problem, mbx = None, {"rows": 0, "unlabeled": 0, "in_window": 0, "with_signal": 0}
        if exp.get("query_status") != "ok":
            problem = "download: %s" % exp.get("query_status")
        else:
            rows, diag = parse_mb_export(exp.get("text") or "")
            if not rows:
                problem = "unexpected format (%d of %d rows with a valid sha256; start: %r)" % (
                    diag["rows_valid"], diag["rows_raw"], diag["start"])
            else:
                mbx.update(rows=len(rows), header=diag["header"])
                dates = sorted(t for t in (parse_ts(x["first_seen"]) for x in rows) if t)
                mbx["from"] = dates[0].strftime(TS_FMT) if dates else None
                mbx["to"] = dates[-1].strftime(TS_FMT) if dates else None
                if not dates:
                    problem = "no readable date in the export"
                for x in rows if not problem else []:
                    if x["signature"] and not sc.is_family(x["signature"]):
                        continue  # labeled ones already come through recent_detections
                    mbx["unlabeled"] += 0 if x["signature"] else 1
                    if not in_window(x):
                        continue
                    mbx["in_window"] += 1
                    if sc.is_family(x["signature"]) or sc.lure_level(x["file_name"])[0] or sc.accent_hit(x["file_name"]):
                        x["_src"] = "mb_export"
                        export_cands.append(x)
                mbx["with_signal"] = len(export_cands)
        if problem:
            warnings.append("MalwareBazaar export not used (%s); unlabeled samples were left out"
                            % problem)
        elif parse_since(args.since) > timedelta(hours=48):
            warnings.append("the MalwareBazaar export only covers 48 h: unlabeled samples older "
                            "than that are left out of this window")
        stats["mb_export"] = mbx

    # recent_detections is already cut by the API (hours parameter) and lists samples that
    # recently got a family label, even when their first_seen is older.
    # That is why we do not filter by first_seen again here: seen.json prevents repeats.
    # Candidates that did not fit the previous run's budget come back from pending.json.
    pending_file = out / "pending.json"
    try:
        pending_prev = json.loads(pending_file.read_text(encoding="utf-8")) if pending_file.exists() else []
    except ValueError:
        pending_prev = []
    # Queue lifetime: old leftovers do not take up today's budget.
    max_age = timedelta(days=scope.get("pending_max_age_days", 3))
    fresh, expired = [], 0
    for s in pending_prev:
        queued = parse_ts(s.get("_queued"))
        if queued and now - queued > max_age:
            expired += 1
            if s.get("sha256_hash") and s["sha256_hash"] not in seen:
                results[s["sha256_hash"]] = record(s, "drop", None, ["queue_expired"], 2)
            continue
        fresh.append(s)
    pending_prev = fresh
    for s in pending_prev:
        if s.get("_src") == "exportacao_mb":  # value written before the English rename
            s["_src"] = "mb_export"
    stats["pending_prev"], stats["pending_expired"] = len(pending_prev), expired

    candidates = {}
    for s in pending_prev + recent + export_cands:
        h = s.get("sha256_hash")
        if not h or h in results or h in candidates:
            continue
        if h in seen:
            stats["dup"] += 1
            continue
        if sc.is_family(s.get("signature")):
            results[h] = record(s, "triage", 100, ["family_seed:" + s["signature"]], 1)
            stats["seed"] += 1
            continue
        if not sc.prefilter(s):
            results[h] = record(s, "drop", 0, ["prefilter"], 2)
            continue
        candidates[h] = s

    # The get_info budget goes first to candidates that already show a target signal in the
    # name or tags. On the first real run, 150 queries went to RATs whose file name was the hash,
    # while 'DANFE-NFe...' and 'Pedido.vbs' were never queried.
    #
    # Watched RAT with no signal in the name (no lure, no accent, no tag): in the first real week,
    # ~300 queries in this group brought no target signal at all. A small daily quota remains
    # as a control sample (the most recent ones); the rest is dropped without a query, with its
    # own reason, and is counted in the summary.
    def name_signal(s):
        return bool(sc.lure_level(s.get("file_name"))[0] or sc.accent_hit(s.get("file_name"))
                    or sc.tag_hit(s.get("tags")) or s.get("_src") == "mb_export")

    with_signal = [s for s in candidates.values() if name_signal(s)]
    watch_only = sorted((s for s in candidates.values() if not name_signal(s)),
                        key=lambda s: s.get("first_seen") or "", reverse=True)
    quota = max(0, int(scope.get("watch_only_daily_quota", 10)))
    watch_take, watch_skip = watch_only[:quota], watch_only[quota:]
    for s in watch_skip:
        results[s["sha256_hash"]] = record(s, "drop", None, ["watched_no_signal"], 2)
    for s in watch_take:
        s["_quota"] = True
    stats["watch_only"] = {"total": len(watch_only), "quota": len(watch_take), "not_queried": len(watch_skip)}

    ordered = sorted(with_signal + watch_take, key=lambda s: -sc.priority(s))
    selected, rest = ordered[:args.max_info], ordered[args.max_info:]
    now_s = now.strftime(TS_FMT)
    pending_next = [dict({k: s.get(k) for k in ("sha256_hash", "first_seen", "file_name", "signature", "tags", "_src")},
                         _queued=s.get("_queued") or now_s)
                    for s in rest if not s.get("_quota")]  # the quota is per day: it does not go to the queue
    hits_before = cache.hits
    infos = fetch_all(
        lambda s: cached("mb_get_info", s["sha256_hash"],
                         lambda: client.mb({"query": "get_info", "hash": s["sha256_hash"]})),
        selected, W, "get_info")
    report_api_problems("MalwareBazaar get_info", infos, warnings)
    for s, info in zip(selected, infos):  # same priority order as before
        h = s["sha256_hash"]
        stats["candidates"] += 1
        stats["info_calls"] += 1
        data = (info.get("data") or [{}])[0] if info.get("query_status") == "ok" else dict(s)
        merged = {**s, **data}
        pts, why = sc.score(merged)
        if s.get("_src") == "mb_export":
            why = why + ["source:unlabeled"]  # came from the export, unsigned in recent_detections
        if s.get("_quota"):
            why = why + ["watch_quota"]
            stats["watch_only"]["queried"] = stats["watch_only"].get("queried", 0) + 1
            if sc.decide(pts) != "drop":
                stats["watch_only"]["with_signal"] = stats["watch_only"].get("with_signal", 0) + 1
        results[h] = record(merged, sc.decide(pts), pts, why, 2)
    for s in rest:
        if s.get("_quota"):  # quota sample with no get_info budget left today
            results[s["sha256_hash"]] = record(s, "drop", None, ["watched_no_signal"], 2)
    stats["info_cached"] = cache.hits - hits_before
    stats["pending"] = len(pending_next)
    pending_file.write_text(json.dumps(pending_next[:3000], ensure_ascii=False), encoding="utf-8")
    lap("layer 2")

    # ---- URLhaus: the delivery layer
    urls = {}
    uh = {"family_urls": 0, "geo_urls": 0, "signal_urls": 0, "url_info": 0, "info_skipped": 0,
          "payloads_new": 0, "old": 0}
    if not args.no_urlhaus:
        def add_url(u, source, family=None):
            link = u.get("url")
            if not link:
                return None
            added = u.get("date_added") or u.get("dateadded") or u.get("firstseen")
            ts = parse_ts(added)
            if ts is not None and ts < cutoff:
                uh["old"] += 1
                return None
            rec = urls.get(link)
            if rec is None:
                if "url:" + link in seen:
                    return None
                host = host_of(link) or bare_host(u.get("host"))
                kind, note = classify_host(host, link)
                rec = urls[link] = {
                    "url": link, "host": host, "host_kind": kind, "host_note": note,
                    "url_status": u.get("url_status"), "threat": u.get("threat"),
                    "tags": u.get("tags") or [], "date_added": added,
                    "family": None, "sources": [], "payloads": [], "url_score": 0, "url_why": []}
                pts, why = sc.score_url(link)
                rec["url_score"], rec["url_why"] = pts, why
                uh["geo_urls" if source.startswith("geo:") else
                   "signal_urls" if source.startswith("signal:") else "family_urls"] += 1
            if family and not rec["family"]:
                rec["family"] = sc.canonical(family)
            if source not in rec["sources"]:
                rec["sources"].append(source)
            return rec

        def add_payload(rec, p, why_extra):
            """A payload served by a URL becomes a sample (if new) and is linked to the URL's host."""
            h = p.get("sha256_hash") or p.get("response_sha256")
            if not h:
                return
            if h not in rec["payloads"]:
                rec["payloads"].append(h)
            if h in results:
                hosts = results[h].setdefault("delivery_hosts", [])
                if rec["host"] and rec["host"] not in hosts:
                    hosts.append(rec["host"])
                return
            if h in seen:
                return
            sig = p.get("signature") or (rec["family"] if why_extra.startswith("urlhaus_signature") else None)
            s = {"sha256_hash": h, "first_seen": p.get("firstseen") or rec["date_added"],
                 "file_name": p.get("filename"), "file_type": p.get("file_type"),
                 "signature": sig, "tags": rec["tags"]}
            if sc.is_family(sig):
                new = record(s, "triage", 100, ["family_seed:" + sig, why_extra], 1)
            else:
                pts, why = sc.score(s)
                why = [w for w in why if w != "no_signal"]
                if why_extra == "urlhaus_geo":
                    # A geofence to the target is explicit targeting: in scope by definition.
                    pts += sc.w.get("urlhaus_geo", 20)
                if rec.get("url_score", 0) > 0:
                    # The URL that delivered the file already had a target signal (local ccTLD host, lure in the path):
                    # the payload inherits those points, without double counting what came from the file name.
                    extra = [w for w in rec["url_why"] if w not in why]
                    if len(extra) == len(rec["url_why"]):
                        pts += rec["url_score"]           # nothing in common with the file name
                    elif "target_host" in extra:
                        pts += sc.w["target_infra"]       # the lure already counted; only the local host is new
                    why += ["url:" + w for w in extra]
                new = record(s, sc.decide(pts), pts, why + [why_extra], 2)
            new["delivery_hosts"] = [rec["host"]] if rec["host"] else []
            results[h] = new
            uh["payloads_new"] += 1

        # 1. URL discovery. Preferred path: the official URLhaus export (URLs from the
        # last 30 days, regenerated every 5 min), downloaded at most once an hour and filtered
        # here by tag. One request replaces the ~37 tag queries without losing anything.
        # If the export fails, fall back to tag queries, as before.
        geo_tags = {t.lower(): t for t in scope.get("urlhaus_geo_tags", TARGET.geo_tags)}
        fam_by_tag = {f.lower(): f for f in scope["families"]}
        export_rows = None
        if not args.urlhaus_by_tag:
            exp = cached("uh_export", "recent.csv", client.uh_export, ttl_days=1 / 24.0)
            problem = None
            if exp.get("query_status") != "ok":
                problem = "download: %s" % exp.get("query_status")
            else:
                export_rows, diag = parse_urlhaus_export(exp.get("text") or "")
                tagged = sum(1 for r in export_rows if r["tags"])
                dates = sorted(t for t in (parse_ts(r["date_added"]) for r in export_rows) if t)
                counts = {}
                for r in export_rows:
                    for t in r["tags"]:
                        counts[t.lower()] = counts.get(t.lower(), 0) + 1
                uh["export"] = {
                    "format": diag["format"], "header": diag["header"], "rows": diag["rows_raw"],
                    "valid": diag["rows_valid"], "with_tags": tagged,
                    "from": dates[0].strftime("%Y-%m-%d") if dates else None,
                    "to": dates[-1].strftime("%Y-%m-%d") if dates else None,
                    "top_tags": sorted(counts.items(), key=lambda kv: -kv[1])[:8],
                    "families": {f: counts.get(f.lower(), 0) for f in scope["families"] if counts.get(f.lower())},
                    "geo": {g: counts.get(g, 0) for g in geo_tags if counts.get(g)},
                }
                if not export_rows:
                    problem = "unexpected format (%d of %d rows with a valid URL; start: %r)" % (
                        diag["rows_valid"], diag["rows_raw"], diag["start"])
                elif tagged == 0:
                    problem = "none of the %d rows had tags; the tags column was probably not found" % len(export_rows)
                elif not dates:
                    problem = "no readable date; the date column was probably not found"
            if problem:
                warnings.append("URLhaus export not used (%s); fell back to tag queries" % problem)
                export_rows = None
            elif parse_since(args.since) > timedelta(days=30):
                warnings.append("the URLhaus export only covers 30 days; the requested window is longer")
        uh["mode"] = "export" if export_rows is not None else "by tag"

        uh_queries = []
        if export_rows is not None:
            fam_window = {}
            for u in export_rows:
                tags = [str(t).lower() for t in u.get("tags") or []]
                fam = next((fam_by_tag[t] for t in tags if t in fam_by_tag), None)
                geo = next((geo_tags[t] for t in tags if t in geo_tags), None)
                ts = parse_ts(u.get("date_added"))
                in_win = ts is None or ts >= cutoff
                if fam and in_win:
                    fam_window[fam] = fam_window.get(fam, 0) + 1
                if fam:
                    add_url(u, "tag:" + fam, fam)
                if geo:
                    add_url(u, "geo:" + geo)
                if not fam and not geo and in_win:
                    # No useful tag: look for a target signal in the URL itself (local ccTLD host, lures in
                    # the path). Done here, on the export already downloaded: no extra call.
                    pts, _ = sc.score_url(u.get("url") or "")
                    if pts >= sc.th["maybe"]:
                        add_url(u, "signal:url")
            uh["export"]["families_in_window"] = fam_window
            # Payloads by signature are not in the export: query only the active families.
            for fam in query_families:
                uh_queries.append(("signature", fam, fam))
        else:
            for fam in scope["families"]:
                for tag in sorted({fam, fam.lower()}):
                    uh_queries.append(("tag", tag, fam))
                uh_queries.append(("signature", fam, fam))
            for tag in scope.get("urlhaus_geo_tags", TARGET.geo_tags):
                uh_queries.append(("geo", tag, None))
        uh_resp = fetch_all(
            lambda q: client.uh("signature" if q[0] == "signature" else "tag",
                                {("signature" if q[0] == "signature" else "tag"): q[1]}),
            uh_queries, W, "URLhaus")
        report_api_problems("URLhaus tag/signature", uh_resp, warnings)
        for (kind, value, fam), r in zip(uh_queries, uh_resp):
            for u in (r.get("urls") or []) if r.get("query_status") == "ok" else []:
                if kind == "tag":
                    add_url(u, "tag:" + value, fam)
                elif kind == "signature":
                    rec = add_url(u, "signature:" + fam, fam)
                    if rec is not None:
                        add_payload(rec, u, "urlhaus_signature")
                else:
                    add_url(u, "geo:" + value)

        # 3. For URLs with no known payload, ask what they served (capped).
        # Short cache (1 day): the online/offline status changes quickly.
        # Order: family and geofence first, then the URLs with the most target signal in the address.
        def url_priority(rec):
            strong = any(s.startswith(("tag:", "geo:", "signature:")) for s in rec["sources"])
            return (0 if strong else 1, -rec.get("url_score", 0))
        need = sorted((rec for rec in urls.values() if not rec["payloads"]), key=url_priority)
        ask, uh["info_skipped"] = need[:args.max_urlinfo], max(0, len(need) - args.max_urlinfo)
        for rec in ask:
            rec["asked"] = True
        uh["url_info"] = len(ask)
        infos = fetch_all(
            lambda rec: cached("uh_url", rec["url"], lambda: client.uh("url", {"url": rec["url"]}), ttl_days=1),
            ask, W, "URLhaus URLs")
        report_api_problems("URLhaus URL lookup", infos, warnings)
        for rec, info in zip(ask, infos):
            if info.get("query_status") != "ok":
                continue
            rec["url_status"] = info.get("url_status") or rec["url_status"]
            if any(s.startswith("geo:") for s in rec["sources"]):
                source = "urlhaus_geo"
            elif any(s.startswith(("tag:", "signature:")) for s in rec["sources"]):
                source = "urlhaus_family_url"
            else:
                source = "urlhaus_url_signal"
            for p in info.get("payloads") or []:
                add_payload(rec, p, source)
    lap("URLhaus")

    # ---- ThreatFox: family IOCs (optional)
    iocs = []
    if not args.no_threatfox:
        known = cached("tf_list", "malware_list", lambda: client.tf({"query": "malware_list"}))  # rarely changes: 7 days
        catalog = (known.get("data") or {}) if known.get("query_status") == "ok" else {}
        valid = []
        for mal in scope["threatfox_malware"]:
            if catalog and mal not in catalog:
                hint = threatfox_suggest(mal, catalog)
                warnings.append("ThreatFox does not know the malware name: %s%s" % (
                    mal, (" | maybe: " + ", ".join(hint)) if hint else ""))
                continue
            valid.append(mal)
        tf_resp = fetch_all(
            lambda mal: client.tf({"query": "malwareinfo", "malware": mal, "limit": args.limit}),
            valid, W, "ThreatFox")
        report_api_problems("ThreatFox", tf_resp + [known], warnings)
        for mal, r in zip(valid, tf_resp):
            for i in (r.get("data") or []) if r.get("query_status") == "ok" else []:
                ts = parse_ts((i.get("first_seen") or "").replace(" UTC", ""))
                key = "ioc:" + str(i.get("ioc"))
                if key in seen:
                    stats["dup"] += 1
                    continue
                if ts and ts >= cutoff:
                    seen.add(key)
                    iocs.append({k: i.get(k) for k in (
                        "ioc", "ioc_type", "threat_type", "malware", "malware_printable",
                        "confidence_level", "first_seen", "tags", "reference")})

    lap("ThreatFox")

    # A dormant family that reappeared (via recent_detections or URLhaus) is queried daily again.
    canon = {norm(f).replace(" ", ""): f for f in scope["families"]}
    for rec in results.values():
        for w in rec["why"]:
            if w.startswith("family_seed:"):
                fam = canon.get(norm(w.split(":", 1)[1]).replace(" ", ""))
                ts = parse_ts(rec.get("first_seen"))
                if fam and ts:
                    st = fstate.setdefault(fam, {"known": True})
                    if not parse_ts(st.get("last_seen")) or ts > parse_ts(st.get("last_seen")):
                        st["last_seen"] = ts.strftime(TS_FMT)
    if cache.enabled:
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text(json.dumps(fstate, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass

    # ---- Output
    day = now.strftime("%Y-%m-%d")
    # samples: only what matters (triage and maybe).
    # drops: candidates that were queried and then dropped, with the reason; this is the
    # calibration material (a drop with score 0 is what revealed the 'NFe2341...' bug).
    # Prefilter drops (Mirai and the like, ~2,400 a week) only become counts in the summary,
    # unless --keep-drops is used.
    samples_file = out / ("samples_%s.jsonl" % day)
    drops_file = out / ("drops_%s.jsonl" % day)
    n_drop_written = 0
    with samples_file.open("a", encoding="utf-8") as f, drops_file.open("a", encoding="utf-8") as fd:
        for rec in results.values():
            if rec["decision"] != "drop":
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            elif rec["why"] not in NOT_CONSULTED or args.keep_drops:
                fd.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n_drop_written += 1
    if n_drop_written == 0 and drops_file.stat().st_size == 0:
        drops_file.unlink()
    if iocs:
        with (out / ("iocs_%s.jsonl" % day)).open("a", encoding="utf-8") as f:
            for i in iocs:
                f.write(json.dumps(i, ensure_ascii=False) + "\n")
    if urls:
        with (out / ("urls_%s.jsonl" % day)).open("a", encoding="utf-8") as f:
            for u in urls.values():
                u["pending"] = not (u["payloads"] or u.get("asked"))
                f.write(json.dumps(u, ensure_ascii=False) + "\n")
        # Only resolved URLs go into seen. The ones left out by the query cap
        # stay in the export (30 days) and come back on the next run.
        seen |= {"url:" + k for k, u in urls.items() if not u["pending"]}

    # Everything evaluated goes into seen, drops included, so get_info is never spent twice.
    # Whatever did not fit the budget is not in results: it stays in pending.json for the next run.
    seen_file.write_text(json.dumps(sorted(seen | set(results))), encoding="utf-8")

    by = {"triage": [], "maybe": [], "drop": []}
    for rec in results.values():
        by[rec["decision"]].append(rec)

    print("Kobold collector | target: %s | window: %s to %s UTC" % (
        TARGET.name, cutoff.strftime(TS_FMT), now.strftime(TS_FMT)))
    print("  triage: %d | maybe: %d | dropped: %d | ThreatFox IOCs: %d" % (
        len(by["triage"]), len(by["maybe"]), len(by["drop"]), len(iocs)))
    print("  recent_detections received: %d | get_info: %d (%d from cache) | seeds outside the window: %d | already seen: %d" % (
        stats.get("recent", 0), stats["info_calls"], stats.get("info_cached", 0), stats["old"], stats["dup"]))
    mbx = stats.get("mb_export")
    if mbx and mbx.get("rows"):
        print("  MalwareBazaar export (48 h): %d samples (%s to %s) | %d unlabeled | %d in window | "
              "%d with target signal in the name -> get_info queue" % (
                  mbx["rows"], mbx.get("from"), mbx.get("to"), mbx["unlabeled"], mbx["in_window"], mbx["with_signal"]))
    if stats.get("families_skipped"):
        print("  dormant families not queried today (once a week; recent_detections covers them): "
              + ", ".join(stats["families_skipped"]))
    wo = stats.get("watch_only")
    if wo and wo["total"]:
        print("  watched RATs with no signal in the name: %d | %d queried in the daily quota, %d with signal | %d dropped without a query" % (
            wo["total"], wo.get("queried", 0), wo.get("with_signal", 0), wo["total"] - wo.get("queried", 0)))
    if stats.get("pending") or stats.get("pending_prev") or stats.get("pending_expired"):
        print("  query queue: %d carried over from the previous run | %d expired | %d left for the next one (pending.json)" % (
            stats.get("pending_prev", 0), stats.get("pending_expired", 0), stats.get("pending", 0)))
    if not args.no_urlhaus:
        print("  URLhaus (%s): %d family URLs | %d with target geofence | %d with target signal in the URL | "
              "URL lookups: %d%s | new payloads: %d" % (
            uh.get("mode", "-"), uh["family_urls"], uh["geo_urls"], uh["signal_urls"], uh["url_info"],
            (" (%d left for the next run)" % uh["info_skipped"]) if uh["info_skipped"] else "", uh["payloads_new"]))
        e = uh.get("export")
        if e:
            # Export diagnostics: shows what was parsed, so "no data" is not confused with "parsed wrong".
            print("    export: %s (header %s) | %d rows, %d with tags | %s to %s" % (
                e["format"], e["header"], e["valid"], e["with_tags"], e["from"], e["to"]))
            fw = e.get("families_in_window", {})
            print("    family tags in the export (30 days / in window): %s | geofence: %s" % (
                ", ".join("%s %d/%d" % (k, v, fw.get(k, 0)) for k, v in e["families"].items()) or "none",
                ", ".join("%s %d" % kv for kv in e["geo"].items()) or "none"))
            if args.verbose:
                print("    most common tags: " + ", ".join("%s %d" % kv for kv in e["top_tags"]))
    for label in ("triage", "maybe"):
        for rec in by[label]:
            print("  [%-6s] %3s  %-34s %-12s %s" % (
                label, rec["score"] if rec["score"] is not None else "-",
                (rec["file_name"] or "")[:34], (rec["signature"] or "-")[:12], " ".join(rec["why"])))
    if args.verbose:
        def top_sigs(recs):
            counts = {}
            for r in recs:
                counts[r["signature"] or "-"] = counts.get(r["signature"] or "-", 0) + 1
            return ", ".join("%s %d" % kv for kv in sorted(counts.items(), key=lambda kv: -kv[1])[:6])

        pre = [r for r in by["drop"] if r["why"] == ["prefilter"]]
        nosig = [r for r in by["drop"] if r["why"] in (["no_signal"], ["no_signal", "watch_quota"])]
        for rec in by["drop"]:
            if rec["why"] in NOT_CONSULTED or rec["why"] in (["no_signal"], ["no_signal", "watch_quota"]):
                continue  # near misses only: some signal, but not enough for "maybe"
            print("  [drop  ] %3s  %-34s %-12s %s" % (
                rec["score"], (rec["file_name"] or "")[:34], (rec["signature"] or "-")[:12], " ".join(rec["why"])))
        if nosig:
            print("  queried with no target signal: %d (most common: %s)" % (len(nosig), top_sigs(nosig)))
        if pre:
            print("  prefilter dropped %d without a query (most common: %s)" % (len(pre), top_sigs(pre)))
    clusters = infra_clusters(by["triage"] + by["maybe"], urls.values())
    if clusters:
        cl_file = out / ("clusters_%s.json" % day)
        cl_file.write_text(json.dumps(clusters, ensure_ascii=False, indent=2), encoding="utf-8")
        print("  campaign candidates (shared infra; hypothesis, not conclusion):")
        for c in clusters:
            print("    %d samples, %d URLs | %s | %s to %s | types: %s" % (
                len(c["samples"]), len(c["urls"]), ", ".join(c["families"]) or "-",
                c["first"], c["last"], ", ".join(c["file_types"]) or "-"))
            print("      infra: " + ", ".join(c["infra"]))

    review = host_review(by["triage"] + by["maybe"], urls.values())
    if review:
        (out / ("hosts_%s.json" % day)).write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8")
        sensitive = [e for e in review if e["kind"] in ("compromised_cms", "target_domain", "verify")]
        print("  delivery and infra hosts (%d total, %d need review before publishing):" % (len(review), len(sensitive)))
        for e in review[:40]:
            mark = "!" if e in sensitive else " "
            print("   %s %-38s %-17s urls:%-3d samples:%-3d %s%s" % (
                mark, e["host"][:38], e["kind"], e["urls"], e["samples"], ", ".join(e["families"]) or "-",
                (" | " + "/".join(e["status"])) if e["status"] else ""))
        if len(review) > 40:
            print("     ... and %d more in hosts_%s.json" % (len(review) - 40, day))
        print("     legend: ! = may be a legitimate third-party site; see host_note in hosts_%s.json" % day)
    for w in warnings:
        print("  warning: " + w)
    total = time.monotonic() - t_start
    api_calls = getattr(client, "calls", None)
    print("  time: %s | total %.0fs%s | cache: %d responses reused" % (
        " | ".join("%s %.0fs" % (k, v) for k, v in timing.items()), total,
        (" | API calls: %d" % api_calls) if api_calls is not None else "", cache.hits))

    # Run summary: the count of everything, including what was not written line by line.
    prefilter_by_sig = {}
    for r in by["drop"]:
        if r["why"] == ["prefilter"]:
            k = r["signature"] or "-"
            prefilter_by_sig[k] = prefilter_by_sig.get(k, 0) + 1
    summary = {
        "target": TARGET.name,
        "window": {"from": cutoff.strftime(TS_FMT), "to": now.strftime(TS_FMT)},
        "counts": {"triage": len(by["triage"]), "maybe": len(by["maybe"]),
                   "drops_queried": sum(1 for r in by["drop"] if r["why"] not in NOT_CONSULTED),
                   "drops_prefilter": sum(prefilter_by_sig.values()),
                   "watched_not_queried": sum(1 for r in by["drop"] if r["why"] == ["watched_no_signal"]),
                   "queue_expired": stats.get("pending_expired", 0),
                   "threatfox_iocs": len(iocs), "urlhaus_urls": len(urls)},
        "prefilter_by_signature": dict(sorted(prefilter_by_sig.items(), key=lambda kv: -kv[1])),
        "pending_queue": stats.get("pending", 0),
        "watch_quota": stats.get("watch_only"),  # 'with_signal' over the weeks tells whether the quota still makes sense
        "malwarebazaar_export": stats.get("mb_export"),
        "urlhaus": {k: v for k, v in uh.items() if k != "export"},
        "urlhaus_export": uh.get("export"),
        "dormant_families_skipped": stats.get("families_skipped", []),
        "warnings": warnings,
        "time_s": {k: round(v, 1) for k, v in timing.items()},
        "api_calls": api_calls,
        "cache_reused": cache.hits,
    }
    (out / ("summary_%s.json" % day)).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print("  output: %s (triage and maybe) | queried drops in drops_%s.jsonl | summary in summary_%s.json"
          % (samples_file, day, day))


# Drops that did not use a query: only counted in the summary (or written as rows with --keep-drops).
NOT_CONSULTED = (["prefilter"], ["watched_no_signal"], ["queue_expired"])

OK_STATUSES = {"ok", "no_results", "unknown_signature", "unknown_tag", "illegal_tag", "tag_not_found",
               "signature_not_found", "no_result", "hash_not_found", "unknown_url", "not_found"}


def report_api_problems(label, responses, warnings):
    """Warns when queries come back with an error or unexpected status (e.g. a rejected Auth-Key),
    instead of letting it look like there was simply no data."""
    bad = [str(r.get("query_status")) for r in responses
           if str(r.get("query_status", "")).lower() not in OK_STATUSES]
    if bad:
        counts = {}
        for b in bad:
            counts[b] = counts.get(b, 0) + 1
        top = ", ".join("%s (%d)" % kv for kv in sorted(counts.items(), key=lambda kv: -kv[1])[:3])
        warnings.append("%s: %d of %d queries failed or returned an unexpected status: %s. "
                        "If it is an authentication error, check the Auth-Key." % (label, len(bad), len(responses), top))


def threatfox_suggest(name, catalog):
    """Looks for the term (e.g. 'casbaneiro') in the names, printable names and aliases of the ThreatFox catalog."""
    import difflib
    term = name.split(".")[-1].lower()
    hits = []
    for key, meta in catalog.items():
        meta = meta or {}
        text = " ".join(str(meta.get(k) or "") for k in ("malware_printable", "malware_alias")).lower()
        if term in key.lower() or term in text:
            hits.append(key)
    if not hits:
        hits = difflib.get_close_matches(name, list(catalog.keys()), n=3, cutoff=0.6)
    return sorted(hits)[:5]


def bare_host(h):
    h = (h or "").strip().lower().rstrip(".")
    return h[4:] if h.startswith("www.") else h


CHEAP_TLDS = {"click", "shop", "xyz", "top", "online", "site", "store", "live", "icu", "lat", "vip", "sbs",
              "cfd", "fun", "space", "website", "life", "pro", "cc", "biz", "buzz", "rest", "monster", "cyou"}
PLATFORMS = ("github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "discordapp.", "discord.com",
             "dropbox", "drive.google.", "docs.google.", "googleusercontent.com", "storage.googleapis.com",
             "firebasestorage", "onedrive.", "1drv.ms", "sharepoint.com", "mediafire.com", "amazonaws.com",
             "blob.core.windows.net", "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app",
             "blogspot.", "wixsite.com", "weebly.com", "000webhostapp.com", "pastebin.com", "catbox.moe",
             "transfer.sh", "ngrok", "trycloudflare.com", "bit.ly", "tinyurl.com")
CMS_PATH = re.compile(r"/(wp-content|wp-includes|wp-admin|administrator|components|modules|sites/default|"
                      r"plugins|themes|images/stories)/", re.I)

# Display order: what needs the most care before publishing comes first.
HOST_KINDS = ["compromised_cms", "target_domain", "verify", "disposable_tld", "ip", "platform", "unknown"]


def classify_host(host, url=""):
    """Heuristic for the pre-publication review. It decides nothing: it only orders your review."""
    if not host:
        return "unknown", "no host"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or ":" in host:
        return "ip", "direct IP; no owner identifiable by name"
    if any(p in host for p in PLATFORMS):
        return "platform", "abused legitimate service; report it to the service, the file owner is the operator"
    path = urllib.parse.urlsplit(url).path if url else ""
    if CMS_PATH.search(path):
        return "compromised_cms", "CMS path (e.g. wp-content): likely a hacked legitimate site"
    tld = TARGET.local_tld(host)
    if tld:
        return "target_domain", ".%s domain: check %s for a real company before publishing" % (
            tld, TARGET.registry or "the national registry")
    if host.rsplit(".", 1)[-1] in CHEAP_TLDS:
        return "disposable_tld", "cheap TLD, common in operator-registered infrastructure"
    return "verify", "regular domain: may be a hacked real company or registered by the operator"


def host_review(records, urls):
    """List of hosts for you to review before publishing, with the likely kind of each one."""
    hosts = {}

    def entry(h):
        return hosts.setdefault(h, {"host": h, "kind": None, "note": None, "urls": 0, "samples": 0,
                                    "families": set(), "status": set(), "seen_as": set()})

    for u in urls:
        if not u.get("host"):
            continue
        e = entry(u["host"])
        e["kind"], e["note"] = u.get("host_kind"), u.get("host_note")
        e["urls"] += 1
        e["seen_as"].add("url_urlhaus")
        if u.get("family"):
            e["families"].add(u["family"])
        if u.get("url_status"):
            e["status"].add(u["url_status"])
    for r in records:
        for h in (r.get("infra_hints") or []) + (r.get("delivery_hosts") or []):
            h = bare_host(h)
            if not h:
                continue
            e = entry(h)
            if e["kind"] is None:
                e["kind"], e["note"] = classify_host(h)
            e["samples"] += 1
            e["seen_as"].add("tag_malwarebazaar" if h in (r.get("infra_hints") or []) else "urlhaus_delivery")
            if r.get("family"):
                e["families"].add(r["family"])
    out = []
    for e in hosts.values():
        out.append(dict(e, families=sorted(e["families"]), status=sorted(e["status"]), seen_as=sorted(e["seen_as"])))
    rank = {k: i for i, k in enumerate(HOST_KINDS)}
    return sorted(out, key=lambda e: (rank.get(e["kind"], 99), -(e["urls"] + e["samples"]), e["host"]))


def host_of(url):
    try:
        return bare_host(urllib.parse.urlsplit(url).hostname)
    except ValueError:
        return ""


def infra_clusters(records, urls=()):
    """Groups samples and URLs linked by a shared host (domain tags, delivery host,
    payload served by a URL). Simple union-find."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def link(a, b):
        parent[find(a)] = find(b)

    sample_ids = {"s:" + r["sha256"] for r in records}
    for rec in records:
        for h in (rec.get("infra_hints") or []) + (rec.get("delivery_hosts") or []):
            if h:
                link("s:" + rec["sha256"], "d:" + bare_host(h))
    url_list = list(urls)
    for u in url_list:
        if u.get("host"):
            link("u:" + u["url"], "d:" + u["host"])
        for h in u.get("payloads") or []:
            if "s:" + h in sample_ids:
                link("s:" + h, "u:" + u["url"])

    groups = {}
    for rec in records:
        if ("s:" + rec["sha256"]) in parent:
            groups.setdefault(find("s:" + rec["sha256"]), {"s": [], "u": []})["s"].append(rec)
    for u in url_list:
        if ("u:" + u["url"]) in parent:
            groups.setdefault(find("u:" + u["url"]), {"s": [], "u": []})["u"].append(u)

    out = []
    for g in groups.values():
        if len(g["s"]) < 2 and len(g["u"]) < 2:
            continue  # one sample and the URL that delivered it is not a campaign, it is the same fact seen from two sides
        stamps = [parse_ts(r.get("first_seen")) for r in g["s"]] + [parse_ts(u.get("date_added")) for u in g["u"]]
        times = sorted(t.strftime(TS_FMT) for t in stamps if t)
        hosts = {bare_host(h) for r in g["s"] for h in (r.get("infra_hints") or []) + (r.get("delivery_hosts") or [])}
        hosts |= {u["host"] for u in g["u"] if u.get("host")}
        out.append({
            "samples": [r["sha256"] for r in g["s"]],
            "urls": [u["url"] for u in g["u"]],
            "families": sorted({r["family"] for r in g["s"] if r.get("family")}
                               | {u["family"] for u in g["u"] if u.get("family")}),
            "file_types": sorted({r["file_type"] for r in g["s"] if r.get("file_type")}),
            "infra": sorted(h for h in hosts if h),
            "first": times[0] if times else None,
            "last": times[-1] if times else None,
        })
    return sorted(out, key=lambda c: -(len(c["samples"]) + len(c["urls"])))


def main():
    # Windows console (cp1252) or output redirected by Task Scheduler:
    # a character outside the encoding becomes '?' instead of crashing the script.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(description="Kobold collector v0")
    p.add_argument("--since", default="24h", help="time window, e.g. 24h, 3d (default 24h)")
    p.add_argument("--scope", default=str(Path(__file__).with_name("scope.json")))
    p.add_argument("--out", default="data", help="output folder (default data)")
    p.add_argument("--limit", type=int, default=100, help="limit per family query (max 1000)")
    p.add_argument("--max-info", type=int, default=50, help="cap on get_info calls per run")
    p.add_argument("--no-threatfox", action="store_true")
    p.add_argument("--no-urlhaus", action="store_true")
    p.add_argument("--workers", type=int, default=3, help="parallel queries (default 3; 1 = sequential)")
    p.add_argument("--rate", type=float, default=2.0,
                   help="maximum requests per second across all threads (default 2)")
    p.add_argument("--keep-drops", action="store_true",
                   help="also write prefilter drops (Mirai and the like) to drops_*.jsonl")
    p.add_argument("--check-all", action="store_true",
                   help="also query dormant families, normally checked once a week")
    p.add_argument("--no-mb-export", action="store_true",
                   help="skip the MalwareBazaar export (samples without a family label are left out)")
    p.add_argument("--urlhaus-by-tag", action="store_true",
                   help="use URLhaus tag queries instead of the export (more calls)")
    p.add_argument("--no-cache", action="store_true", help="ignore the get_info and URL cache")
    p.add_argument("--cache-dir", help="cache folder (default: cache/ next to collect.py)")
    p.add_argument("--cache-days", type=float, default=7.0, help="get_info cache lifetime in days (default 7)")
    p.add_argument("--max-urlinfo", type=int, default=30,
                   help="cap on URLhaus URL lookups per run (default 30)")
    p.add_argument("--fixtures", help="JSON with test responses instead of the real API")
    p.add_argument("--now", help="pin 'now' in UTC, e.g. '2026-10-14 18:00:00' (for tests)")
    p.add_argument("-v", "--verbose", action="store_true", help="also show dropped samples")
    run(p.parse_args())


if __name__ == "__main__":
    main()