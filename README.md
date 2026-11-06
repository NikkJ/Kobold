# Kobold

Kobold is a threat intelligence collector that tracks malware linked to a country or
region, whether that place is the origin or the target of the activity. It pulls fresh
data from the abuse.ch platforms (MalwareBazaar, URLhaus and ThreatFox), scores every
candidate for signals tied to the target and produces a daily set of samples, delivery
URLs, IOCs and hosts ready for analyst triage.

The target is defined entirely in `scope.json`. Kobold was born tracking Brazil, so the
defaults reproduce that setup: Brazilian banking trojans (Grandoreiro, Mispadu, Guildma and
similar), payloads geofenced to Brazil and lures built around NF-e, DANFE and boleto
documents. Swapping the scope file points the same pipeline at Mexico, Portugal, Spain or
any other target.

> **Status:** early development. The collector works and runs daily, but sources, scoring
> and output format may still change.

## How it works

Kobold runs in layers, from the cheapest and most certain signal to the most expensive.

**Layer 1: family seeds.** Every tracked family is queried on MalwareBazaar by signature
and by tag. Anything inside the time window goes straight to triage. Families with no
activity for a long time are treated as dormant and checked only once a week, so they do
not waste API calls every day.

**Layer 2: candidates.** Samples from `recent_detections` and from the MalwareBazaar
`recent` export (which also covers unlabeled samples, such as first-stage VBS, JS and MSI
downloaders) are prefiltered by file name and signature. Only candidates with a visible
target signal spend a `get_info` call, within a per-run budget. Each one is then scored
and classified as `triage`, `maybe` or `drop`. Candidates that do not fit the budget are
queued for the next run.

**URLhaus: the delivery layer.** Delivery URLs are taken from the official URLhaus export,
filtered by family tags and by the target's geofence tags, plus URLs whose address itself
carries a target signal (a host under a target ccTLD or a lure in the path). Payloads
served by those URLs become samples, and their hosts feed the infrastructure clustering.

**ThreatFox.** Optional IOCs for the tracked families.

**Layer 3** (content analysis) is not part of the collector. It belongs to the analyst or
agent triage that consumes Kobold's output.

### Scoring signals

| Signal | Reason in `why` | Weight key |
| --- | --- | --- |
| Family named by a vendor | `vendor_family:grandoreiro` | `vendor_family` |
| Target tag (e.g. `BRA`) | `target_tag:BRA` | `target_tag` |
| Lure found only in the target (e.g. `danfe`) | `lure_strong:danfe` | `lure_strong` |
| Lure in the target language, also used elsewhere | `lure_language:pedido` | `lure_language` |
| Weaker lures and hints | `lure_weak:...`, `lure_hint:...` | `lure_weak`, `lure_hint` |
| Accent typical of the target language | `accent` | `accent` |
| Target infrastructure (ccTLD host or domain tag) | `target_infra` | `target_infra` |
| Origin country is the target | `origin_target` | `origin_target` |
| Lure in another language (negative weight) | `other_language:factura` | `other_language` |
| Payload from a URL geofenced to the target | `urlhaus_geo` | `urlhaus_geo` |

Weights and thresholds live in `scope.json`, so the scoring can be tuned without touching
the code. Every record keeps the list of reasons (`why`) behind its score.

## Requirements

- Python 3.7 or newer
- No third-party packages: Kobold uses only the standard library
- An abuse.ch Auth-Key, free at [auth.abuse.ch](https://auth.abuse.ch/)

## Setup

```bash
git clone https://github.com/NikkJ/Kobold.git
cd Kobold
```

Set the Auth-Key as an environment variable.

Windows (PowerShell):

```powershell
$env:ABUSECH_AUTH_KEY = "your-key"
```

Linux / macOS:

```bash
export ABUSECH_AUTH_KEY="your-key"
```

Never commit the key. Keep it in the environment or in a local `.env` file, which is
ignored by git.

## Usage

```bash
# Last 24 hours with the default scope.json
python3 collect.py --since 24h

# Another target, with its own output folder
python3 collect.py --scope scope-mx.json --out data-mx --since 24h

# Last 3 days, without ThreatFox, with a larger get_info budget
python3 collect.py --since 3d --no-threatfox --max-info 100

# Offline test run with recorded responses and a fixed clock
python3 collect.py --fixtures fixtures.json --now "2026-10-14 18:00:00" --out data-test -v
```

Use a separate `--out` folder per target, since `seen.json` and `pending.json` live there.

### Main options

| Option | Default | Description |
| --- | --- | --- |
| `--since` | `24h` | Time window, e.g. `24h` or `3d` |
| `--scope` | `scope.json` | Scope file (target, families, lures, weights) |
| `--out` | `data` | Output folder |
| `--max-info` | `50` | Cap on `get_info` calls per run |
| `--max-urlinfo` | `30` | Cap on URLhaus URL lookups per run |
| `--workers` | `3` | Parallel queries (`1` = sequential) |
| `--rate` | `2.0` | Maximum requests per second across all threads |
| `--check-all` | off | Also query dormant families |
| `--keep-drops` | off | Also write prefilter drops to `drops_*.jsonl` |
| `--no-threatfox` | off | Skip ThreatFox |
| `--no-urlhaus` | off | Skip URLhaus |
| `--no-mb-export` | off | Skip the MalwareBazaar export (unlabeled samples are left out) |
| `--urlhaus-by-tag` | off | Use URLhaus tag queries instead of the export (more calls) |
| `--no-cache` | off | Ignore the local cache |
| `--fixtures` | | JSON file with recorded responses instead of the real API |
| `--now` | | Pin the current time in UTC (for tests) |
| `-v` | off | Verbose output, including near-miss drops |

Run `python3 collect.py --help` for the full list.

## Configuration: `scope.json`

### The target

The `target` block describes the country or region being tracked. Every field is
optional, and without the block Kobold falls back to Brazil.

```json
"target": {
  "name": "Brazil",
  "country": "BR",
  "cctlds": ["br"],
  "registry": "registro.br",
  "geo_tags": ["BRA"],
  "accent_regex": "[ãõÃÕ]",
  "accent_exclude_regex": "[đĐưƯơƠẠ-ỹ]"
}
```

| Field | Purpose |
| --- | --- |
| `name` | Label shown in the console and in the summary |
| `country` | ISO 3166-1 alpha-2 code compared with the sample's origin country |
| `cctlds` | ccTLDs that count as local infrastructure (e.g. `["mx"]`, `["co.uk"]`) |
| `registry` | Where to check local domains before publishing |
| `geo_tags` | URLhaus geofence tags, ISO alpha-3 (e.g. `["MEX"]`) |
| `accent_regex` | Characters typical of the target language in file names |
| `accent_exclude_regex` | Characters that cancel the accent signal (another language sharing it) |

The accent signal only helps when the target language has characters that neighbouring
languages lack, as `ã` and `õ` in Portuguese. For many targets, such as Spanish-speaking
countries, it is better left out. Targets without a strong ccTLD (the United States, for
example) also lose one of the best infrastructure signals, so lures and tags carry more
of the weight.

### Other keys

| Key | Purpose |
| --- | --- |
| `families` | Families tracked as seeds |
| `aliases` | Alternative names mapped to one canonical family (e.g. Astaroth to Guildma) |
| `watch_signatures` | Generic signatures (RATs, loaders) watched for target signals |
| `target_tags` | Tags that count as a target signal |
| `lure_terms`, `lure_terms_language`, `lure_terms_weak`, `lure_terms_hint` | File name lures, from strongest to weakest |
| `other_language_terms` | Lures in other languages that lower the score |
| `weights`, `thresholds` | Scoring weights and the `triage` / `maybe` cutoffs |
| `threatfox_malware` | ThreatFox malware names to query |
| `urlhaus_geo_tags` | Overrides the target's `geo_tags` |
| `dormant_after_days`, `dormant_check_every_days` | When a family becomes dormant and how often it is checked |
| `pending_max_age_days` | How long a queued candidate stays valid |
| `watch_only_daily_quota` | Daily control sample of watched RATs with no signal in the name |

Scope files from the first, Brazil-only version still work: `br_tags`, `lure_terms_pt`
and the weights `br_tag`, `br_infra`, `origin_br`, `lure_ptbr`, `lure_pt` and `accent_pt`
are read as their neutral equivalents.

## Output

All files go to the `--out` folder, one set per day.

| File | Content |
| --- | --- |
| `samples_YYYY-MM-DD.jsonl` | Samples classified as `triage` or `maybe` |
| `drops_YYYY-MM-DD.jsonl` | Candidates queried and dropped, with the reason (calibration material) |
| `urls_YYYY-MM-DD.jsonl` | URLhaus delivery URLs and the payloads they served |
| `iocs_YYYY-MM-DD.jsonl` | ThreatFox IOCs for the tracked families |
| `clusters_YYYY-MM-DD.json` | Samples and URLs sharing infrastructure (campaign hypotheses, not conclusions) |
| `hosts_YYYY-MM-DD.json` | Delivery and infrastructure hosts, ordered for review |
| `summary_YYYY-MM-DD.json` | Run summary: target, counts, warnings, timing and API usage |

State files that keep runs incremental:

- `seen.json`: everything already evaluated, so nothing is queried twice
- `pending.json`: candidates waiting for the next run's budget
- `cache/`: cached API responses and `family_state.json` (dormancy tracking)

Output and cache folders are ignored by git.

## Before sharing results

Delivery hosts are often **legitimate websites that were compromised**, not attacker
infrastructure. `hosts_*.json` classifies each host (`compromised_cms`, `target_domain`,
`verify`, `disposable_tld`, `ip`, `platform`) and adds a note, with the ones that need
the most care listed first. Review them before publishing or sharing any result, and
prefer notifying the site owner over exposing them.

## Disclaimer

Kobold is intended for defensive research and threat intelligence. It only collects
metadata already published on the abuse.ch platforms and does not download or execute
malware. Use it in accordance with the abuse.ch terms of service.

## License

MIT
