# Directive: API Blocklist Export Logic

## Goal
Automate the extraction, filtering, and packaging of Indicators of Compromise (IOCs) from MISP for internal defense tools.

## Inputs
- **Source**: MISP Instance (URL + API Key in `.env`)
- **Previous State**: `output/previous_run.json` (if exists, for delta calculation)

## Logic
### 1. Collect & Filter (Server-Side)
Query MISP `/attributes/restSearch` with 3 sets of criteria.
**Filtering is performed entirely by MISP** using strict Tag logic passed in the payload.

#### API Payload Logic
All queries enforce:
- `to_ids=1` (Actionable only)
- `enforceWarninglist=1` (Exclude known false positives)
- `includeEventTags=1` (Include Event-level metadata)
- **Tags (must match ALL of these groups):**
    - Status: `active`
    - TLP: `AMBER` OR `GREEN` OR `CLEAR`
    - Reliability: `A` OR `B`
    - Credibility: `1` OR `2`
    - PAP: `CLEAR` OR `GREEN`

#### Categories
1.  **High Volatility** (IPs)
    - Types: `ip-src`, `ip-dst`
    - Timeframe: Last `14d`
2.  **Medium Volatility** (Domains/URLs)
    - Types: `domain`, `url`, `hostname`
    - Timeframe: Last `30d`
3.  **Permanent** (Hashes)
    - Types: `sha256`, `sha1`, `md5`
    - Timeframe: `None` (All time)

### 2. Process & Deduplicate
- **Deduplicate**: Remove duplicate values.
- **Enrichment**: Parse `Tag` lists (from both Attribute and parent Event) to extract:
    - `tlp`
    - `pap`
    - `reliability`
    - `credibility`
    - `status`
- **Delta Calculation**: Compare current unique values against `output/previous_run.json`.

### 3. Distribute (Output)
Generate outputs in `output/` directory.

#### Text Files (Split by Type)
Generic lists for firewalls/EDR. Includes custom header with timestamp.
- `domains.txt` (from `domain`, `hostname`)
- `urls.txt` (from `url`)
- `src_ips.txt` (from `ip-src`)
- `dest_ips.txt` (from `ip-dst`)
- `md5.txt`, `sha1.txt`, `sha256.txt`

#### Metadata Files (Aggregated by Category)
For auditing and debugging.
- `{Category}.csv`: Full metadata + Enriched columns.
- `{Category}.json`: Full JSON objects.

## Tools
- `execution/process_misp_export.py`

## Error Handling
- **Auth**: Script exits 1 if `.env` is missing or invalid.
- **Connection**: Retries or fails gracefully on timeout (300s).
- **File Locks**: If an output file is open (e.g., in Excel), writes to a timestamped fallback file (e.g., `dest_ips_1768...txt`) to ensure data is preserved.
