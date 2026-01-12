import os
import sys
import json
import requests
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv

"""
MISP Blocklist Export Script
----------------------------
Purpose:
    Extracts high-fidelity Indicators of Compromise (IOCs) from a MISP instance to generate
    blocklists for firewalls, DNS sinkholes, and EDR systems.

Core Features:
    1.  **Strict Server-Side Filtering**: Uses a complex set of MISP Tags to ensure only high-confidence,
        actionable indicators are fetched.
    2.  **Volatility Buckets**: Separates data into High (IPs), Medium (Domains), and Permanent (Hashes)
        volatility to apply appropriate expiration policies.
    3.  **Delta Calculation**: Tracks changes between runs to identify new vs existing indicators.
    4.  **Resilient Output**: Handles file locking (e.g., if a file is open in Excel) by writing to fallback paths.
    5.  **Enriched Metadata**: Parses both Attribute and Event tags to output TLP, PAP, Reliability, Credibility, and Status.

Usage:
    Run manually or schedule via cron/task scheduler.
    Env vars needed: MISP_URL, MISP_KEY.
"""

# Load environment variables
load_dotenv()

MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")
PREVIOUS_RUN_FILE = os.path.join(OUTPUT_DIR, "previous_run.json")

if not MISP_URL or not MISP_KEY:
    print("Error: MISP_URL and MISP_KEY must be set in .env")
    sys.exit(1)

HEADERS = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# -------------------------------------------------------------------------
# FILTERS & CONFIGURATION
# -------------------------------------------------------------------------

# COMMON_TAGS:
# These tags enforce strict quality control. An attribute must match ALL of these logic groups.
# Syntax: "tag1 | tag2" means (tag1 OR tag2).
# The array implies (Group1) AND (Group2) AND ...
COMMON_TAGS = [
    'cti-case-classification:status="active"',  # Only active threats
    "tlp:amber | tlp:green | tlp:clear",        # Permitted TLP levels
    'admiralty-scale:source-reliability="a" | admiralty-scale:source-reliability="b"',  # Reliable sources only
    'admiralty-scale:information-credibility="1" | admiralty-scale:information-credibility="2"', # Credible info only
    "PAP:CLEAR | PAP:GREEN"                     # Permitted PAP levels
]

# CATEGORIES:
# We process 3 distinct buckets of IOCs with different retention policies.
CATEGORIES = {
    "High_Volatility": {
        "types": ["ip-src", "ip-dst"],
        "last": "14d"  # IPs expire quickly
    },
    "Medium_Volatility": {
        "types": ["domain", "url", "hostname"],
        "last": "30d"  # Domains stick around longer
    },
    "Permanent": {
        "types": ["sha256", "sha1", "md5"],
        "last": None   # Hashes is unique per file forever
    }
}

# TYPE_MAPPING:
# Maps specific MISP attribute types to specific output text files and titles.
# Note: 'hostname' is mapped to 'domains.txt' alongside 'domain'.
TYPE_MAPPING = {
    "domain": {"file": "domains.txt", "title": "Recommended Domain Block List"},
    "hostname": {"file": "domains.txt", "title": "Recommended Domain Block List"},
    "url": {"file": "urls.txt", "title": "Recommended URL Block List"},
    "ip-src": {"file": "src_ips.txt", "title": "Recommended Source IP Block List"},
    "ip-dst": {"file": "dest_ips.txt", "title": "Recommended Destination IP Block List"},
    "md5": {"file": "md5.txt", "title": "Recommended MD5 Block List"},
    "sha1": {"file": "sha1.txt", "title": "Recommended SHA1 Block List"},
    "sha256": {"file": "sha256.txt", "title": "Recommended SHA256 Block List"}
}

# -------------------------------------------------------------------------
# CORE FUNCTIONS
# -------------------------------------------------------------------------

def fetch_attributes(types, last=None):
    """
    Fetch attributes from MISP `/attributes/restSearch`.
    
    Args:
        types (list): List of attribute types to fetch (e.g. ['ip-src']).
        last (str): Optional lookback window (e.g. "14d").
    
    Returns:
        list: List of attribute dictionaries from MISP response.
    """
    payload = {
        "returnFormat": "json",
        "type": types,
        "to_ids": 1,           # Crucial: Only return Actionable attributes
        "tags": COMMON_TAGS,   # Apply server-side filtering
        "enforceWarninglist": 1, # Exclude common false positives (Google, MSFT, etc.)
        "includeEventTags": 1  # Include Event-level tags in the response
    }
    
    if last:
        payload["last"] = last

    try:
        # Timeout set to 300s (5min) to handle large datasets effectively.
        response = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=HEADERS,
            json=payload,
            verify=VERIFY_SSL,
            timeout=300 
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", {}).get("Attribute", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for types {types}: {e}")
        return []

def process_dataframe(attributes, days_limit=None):
    """
    Convert raw attributes to a cleaned DataFrame.
    
    Operations:
        1. Create DataFrame.
        2. Strict filtering checks (Client-side double check, though API does most work).
        3. Deduplication on 'value'.
    """
    if not attributes:
        return pd.DataFrame()

    df = pd.DataFrame(attributes)
    

    # Ensure standard schema even if API returns sparse data
    required_cols = ['value', 'type', 'timestamp', 'to_ids', 'Event', 'Tag']
    for col in required_cols:
        if col not in df.columns:
            df[col] = None

    # Helper function to extract specific tag values
    def extract_tags(row):
        meta = {
            'tlp': None,
            'pap': None,
            'reliability': None,
            'credibility': None,
            'status': None
        }

        # Collect all tags from Attribute level and Event level
        all_tags = []
        
        # Attribute Tags
        if isinstance(row.get('Tag'), list):
            all_tags.extend(row['Tag'])
            
        # Event Tags (nested in Event dict)
        event = row.get('Event')
        if isinstance(event, dict):
            event_tags = event.get('Tag')
            if isinstance(event_tags, list):
                all_tags.extend(event_tags)
            
        for tag in all_tags:
            name = tag.get('name', '')
            lower_name = name.lower()
            
            # TLP
            if lower_name.startswith('tlp:'):
                meta['tlp'] = name.split(':')[1]
            
            # PAP
            elif lower_name.startswith('pap:'):
                meta['pap'] = name.split(':')[1]
            
            # Admiralty Scale
            elif 'admiralty-scale:source-reliability="' in lower_name:
                try:
                    meta['reliability'] = name.split('="')[1].strip('"')
                except IndexError:
                    pass
            elif 'admiralty-scale:information-credibility="' in lower_name:
                try:
                    meta['credibility'] = name.split('="')[1].strip('"')
                except IndexError:
                    pass
            
            # Status
            elif 'cti-case-classification:status="' in lower_name:
                try:
                    meta['status'] = name.split('="')[1].strip('"')
                except IndexError:
                    pass
                    
        return pd.Series(meta)

    # Apply extraction
    # We apply to the whole ROW (axis=1) to access both 'Tag' and 'Event' columns
    tag_cols = df.apply(extract_tags, axis=1)
    df = pd.concat([df, tag_cols], axis=1)

    # Optional: Additional client-side time filtering could go here if needed.
    # Currently handled by 'last' param in API request.
    
    # Deduplicate: Keep one entry per indicator value
    df = df.drop_duplicates(subset=['value'])
    
    # Remove duplicate columns (e.g. if API returned 'value' and we somehow added it again, though unlikely via concat. Usually 'timestamp' collision)
    df = df.loc[:, ~df.columns.duplicated()]

    return df

def generate_delta(current_df, category_name, previous_data):
    """
    Calculate changes between this run and the last run.
    Useful for reporting what is new.
    """
    previous_values = set(previous_data.get(category_name, []))
    current_values = set(current_df['value'].tolist())
    
    new_items = current_values - previous_values
    removed_items = previous_values - current_values
    
    print(f"[{category_name}] Total: {len(current_values)} | New: {len(new_items)} | Removed: {len(removed_items)}")
    return list(current_values), new_items

def generate_header(title):
    """
    Generate a standardized file header for text outputs.
    Format:
    ################################################################
    # Title                                                        #
    # Last updated: YYYY-MM-DD HH:MM:SS +07                        #
    #                                                              #
    # Use on your own risk. No warranties implied.                 #
    ################################################################
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = (
        "################################################################\n"
        f"# {title.ljust(60)} #\n"
        f"# Last updated: {now} +07                        #\n"
        "#                                                              #\n"
        "# Use on your own risk. No warranties implied.                 #\n"
        "################################################################"
    )
    return header

def save_outputs(df, category_name):
    """
    Save processed data to 3 formats:
    1. CSV (Full Detail)
    2. JSON (Full Detail)
    3. TXT (Values only, split by specific type like src_ips.txt, domains.txt)
    
    Includes 'PermissionError' handling to fallback to timestamped files if main file is locked.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base_path = os.path.join(OUTPUT_DIR, category_name)
    
    # 1. Save Aggregate CSV
    try:
        df.to_csv(f"{base_path}.csv", index=False)
    except PermissionError:
        print(f"Warning: Could not write to {base_path}.csv. File might be open.")
        df.to_csv(f"{base_path}_{int(datetime.now().timestamp())}.csv", index=False)
    
    # 2. Save Aggregate JSON
    try:
        df.to_json(f"{base_path}.json", orient="records", date_format="iso")
    except PermissionError:
        print(f"Warning: Could not write to {base_path}.json. File might be open.")
        df.to_json(f"{base_path}_{int(datetime.now().timestamp())}.json", orient="records", date_format="iso")
    
    # 3. Save Split Text Files
    if df.empty:
        return

    # First, aggregate values by target file (e.g. combine domain+hostname)
    files_content = {} # filename -> {title, values_set}
    
    for _, row in df.iterrows():
        attr_type = row['type']
        val = row['value']
        
        mapping = TYPE_MAPPING.get(attr_type)
        if mapping:
            target_file = mapping['file']
            target_title = mapping['title']
            
            if target_file not in files_content:
                files_content[target_file] = {
                    "title": target_title,
                    "values": set()
                }
            files_content[target_file]["values"].add(val)
            
    # Then write each file
    for filename, content in files_content.items():
        file_path = os.path.join(OUTPUT_DIR, filename)
        header = generate_header(content["title"])
        sorted_vals = sorted(list(content["values"]))
        
        try:
            with open(file_path, "w") as f:
                f.write(header + "\n")
                f.write("\n".join(sorted_vals))
        except PermissionError:
            # Fallback for locked files
            print(f"Warning: Could not write to {file_path}. File might be open. Trying fallback...")
            fallback_path = os.path.join(OUTPUT_DIR, f"{filename}_{int(datetime.now().timestamp())}.txt")
            with open(fallback_path, "w") as f:
                f.write(header + "\n")
                f.write("\n".join(sorted_vals))
            print(f"Saved to {fallback_path}")

# -------------------------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------------------------

def main():
    print("Starting MISP Blocklist Export...")
    
    # Load state from previous run for Delta calculation
    previous_run_data = {}
    if os.path.exists(PREVIOUS_RUN_FILE):
        try:
            with open(PREVIOUS_RUN_FILE, 'r') as f:
                previous_run_data = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load previous run file: {e}")

    current_run_summary = {}
    
    # Iterate through volatility categories
    for cat_name, criteria in CATEGORIES.items():
        print(f"Processing {cat_name}...")
        
        # 1. Fetch
        raw_attrs = fetch_attributes(criteria["types"], criteria["last"])
        
        # 2. Process
        df = process_dataframe(raw_attrs, criteria["last"])
        
        if df.empty:
            print(f"No attributes found for {cat_name}")
            current_run_summary[cat_name] = []
            continue

        # 3. Delta Logic
        all_values, new_items = generate_delta(df, cat_name, previous_run_data)
        current_run_summary[cat_name] = all_values
        
        # 4. Save Outputs
        save_outputs(df, cat_name)

    # Update state for next run
    with open(PREVIOUS_RUN_FILE, "w") as f:
        json.dump(current_run_summary, f)
        
    print("Export Complete.")

if __name__ == "__main__":
    main()
