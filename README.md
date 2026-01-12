# MISP Tagging & Governance: API Blocklist Export Logic

Automated tooling to extract high-fidelity Indicators of Compromise (IOCs) from MISP for defensive use. This tool uses strict filtering logic (Admiralty Scale, TLP, Status) to ensure only "Blockable" indicators are exported.

## Architecture

- **Directives** (`directives/`): Standard Operating Procedures (SOPs) describing the logic.
- **Execution** (`execution/`): Python scripts to perform the API calls and processing.
- **Output** (`output/`): Generated text, CSV, and JSON files.

## Setup

1.  **Clone the repository**.
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure Environment**:
    Rename `.env.example` to `.env` and configure your MISP credentials:
    ```ini
    MISP_URL=https://your-misp.com
    MISP_KEY=your_key
    VERIFY_SSL=false
    ```

## Usage

Run the main export script:
```bash
python execution/process_misp_export.py
```

## Logic Overview

The script pulls attributes in three volatility buckets:

1.  **High Volatility (IPs)**: 14-day lookback.
2.  **Medium Volatility (Domains/URLs)**: 30-day lookback.
3.  **Permanent (Hashes)**: No expiry.

**Strict Filtering:**
All attributes must match:
- `to_ids=1`
- `enforceWarninglist=1`
- `status=active` AND `reliability=A/B` AND `credibility=1/2` AND `TLP=Amber/Green/Clear`

**Enrichment:**
CSV and JSON exports include enriched columns extracted from MISP attributes and their parent Events:
- `tlp`, `pap`, `reliability`, `credibility`, `status`

## Outputs

Files are generated in `output/` automatically split by type:
- `src_ips.txt`, `dest_ips.txt`
- `domains.txt`, `urls.txt`
- `md5.txt`, `sha1.txt`, `sha256.txt`

Includes CSV and JSON summaries for auditing (with full metadata).
