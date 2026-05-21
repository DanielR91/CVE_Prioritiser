import os
import sys
import json
import time
import datetime
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError

# Ensure directories exist
os.makedirs("src/data", exist_ok=True)
os.makedirs("src/css", exist_ok=True)
os.makedirs("src/js", exist_ok=True)

CVSS_CACHE_PATH = "src/data/cvss-cache.json"
CVE_DATA_PATH = "src/data/cve-data.json"

# Load local CVSS cache
if os.path.exists(CVSS_CACHE_PATH):
    try:
        with open(CVSS_CACHE_PATH, "r") as f:
            cvss_cache = json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load CVSS cache, starting fresh. Error: {e}")
        cvss_cache = {}
else:
    cvss_cache = {}

def make_request(url, timeout=30, retries=3):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CVE Prioritiser/1.0"}
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read()
        except (HTTPError, URLError, TimeoutError) as e:
            print(f"Request failed for {url} (Attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
            else:
                raise e

def extract_cvss_from_nvd_item(cve_item):
    """Extracts CVSS score and version from an NVD CVE item."""
    metrics = cve_item.get("metrics", {})
    
    # Check CVSS V3.1
    if "cvssMetricV31" in metrics:
        for metric in metrics["cvssMetricV31"]:
            # Prefer Primary source, fall back to secondary
            if metric.get("type") == "Primary" or len(metrics["cvssMetricV31"]) == 1:
                return float(metric["cvssData"]["baseScore"]), "V3.1"
                
    # Check CVSS V3.0
    if "cvssMetricV30" in metrics:
        for metric in metrics["cvssMetricV30"]:
            if metric.get("type") == "Primary" or len(metrics["cvssMetricV30"]) == 1:
                return float(metric["cvssData"]["baseScore"]), "V3.0"
                
    # Check CVSS V4.0 (newer vulnerabilities)
    if "cvssMetricV40" in metrics:
        for metric in metrics["cvssMetricV40"]:
            if metric.get("type") == "Primary" or len(metrics["cvssMetricV40"]) == 1:
                return float(metric["cvssData"]["baseScore"]), "V4.0"
                
    # Check CVSS V2.0 (older vulnerabilities)
    if "cvssMetricV2" in metrics:
        for metric in metrics["cvssMetricV2"]:
            if metric.get("type") == "Primary" or len(metrics["cvssMetricV2"]) == 1:
                return float(metric["cvssData"]["baseScore"]), "V2.0"
                
    return None, None

def fetch_cvss_from_circl(cve_id):
    """Fallback fetcher from CIRCL API for a specific CVE."""
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        print(f"Fetching CVSS for {cve_id} from CIRCL API...")
        res = make_request(url, timeout=10)
        data = json.loads(res.decode())
        
        # Check containers for CVSS (JSON 5.0)
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        adp_list = containers.get("adp", [])
        
        # Check CNA first
        metrics = cna.get("metrics", [])
        for metric in metrics:
            for cvss_key in ["cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"]:
                if cvss_key in metric:
                    return float(metric[cvss_key]["baseScore"]), cvss_key.replace("cvss", "V")
                    
        # Check ADP list
        for adp in adp_list:
            metrics = adp.get("metrics", [])
            for metric in metrics:
                for cvss_key in ["cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"]:
                    if cvss_key in metric:
                        return float(metric[cvss_key]["baseScore"]), cvss_key.replace("cvss", "V")
                        
        # Check legacy fields
        if "cvss" in data:
            return float(data["cvss"]), "V2.0/V3.0"
            
    except Exception as e:
        print(f"Error fetching from CIRCL for {cve_id}: {e}")
    return None, None

def fetch_epss_scores(cve_ids):
    """Fetches EPSS scores in batches of 100."""
    epss_map = {}
    cve_list = list(cve_ids)
    batch_size = 100
    
    print(f"Fetching EPSS scores for {len(cve_list)} CVEs in batches of {batch_size}...")
    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i:i+batch_size]
        cve_param = ",".join(batch)
        url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
        
        try:
            res = make_request(url, timeout=15)
            data = json.loads(res.decode())
            epss_data = data.get("data", [])
            for item in epss_data:
                cve = item.get("cve")
                epss_map[cve] = {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0))
                }
        except Exception as e:
            print(f"Error fetching EPSS batch starting at index {i}: {e}")
        time.sleep(0.5)  # Polite delay
        
    return epss_map

def main():
    print("Starting CVE Prioritiser Data Sync...")
    start_time = time.time()
    
    # 1. Fetch CISA KEV JSON (Official Catalog)
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print("Fetching CISA KEV Catalog...")
    try:
        cisa_res = make_request(cisa_url)
        cisa_data = json.loads(cisa_res.decode())
        cisa_vulnerabilities = cisa_data.get("vulnerabilities", [])
        print(f"Loaded {len(cisa_vulnerabilities)} vulnerabilities from CISA KEV.")
    except Exception as e:
        print(f"Critical Error: Failed to fetch CISA KEV catalog: {e}")
        sys.exit(1)
        
    # 2. Fetch NVD KEV dataset to get CVSS scores for CISA KEV
    print("Fetching CVSS data for KEV from NVD API...")
    nvd_kev_map = {}
    try:
        nvd_kev_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"
        nvd_res = make_request(nvd_kev_url, timeout=40)
        nvd_data = json.loads(nvd_res.decode())
        for vuln in nvd_data.get("vulnerabilities", []):
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id")
            score, version = extract_cvss_from_nvd_item(cve_item)
            if score is not None:
                nvd_kev_map[cve_id] = {"cvss": score, "cvss_version": version}
        print(f"Retrieved CVSS details for {len(nvd_kev_map)} KEV vulnerabilities from NVD.")
    except Exception as e:
        print(f"Warning: Failed to fetch NVD KEV details: {e}. Will rely on cache/CIRCL.")

    # 3. Fetch Recent CVEs from NVD (last 7 days)
    print("Fetching recently published CVEs from NVD API...")
    recent_nvd_items = []
    try:
        now = datetime.datetime.utcnow()
        start = now - datetime.timedelta(days=7)
        start_str = start.strftime("%Y-%m-%dT00:00:00")
        end_str = now.strftime("%Y-%m-%dT%H:%M:%S")
        recent_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_str}&pubEndDate={end_str}"
        
        recent_res = make_request(recent_url, timeout=30)
        recent_data = json.loads(recent_res.decode())
        recent_nvd_items = recent_data.get("vulnerabilities", [])
        print(f"Retrieved {len(recent_nvd_items)} recently published CVEs from NVD.")
    except Exception as e:
        print(f"Warning: Failed to fetch recent CVEs from NVD: {e}.")

    # 4. Process and Enrich CVE Data
    enriched_cves = {}
    all_cve_ids = set()
    
    # Process CISA KEV entries
    cisa_cve_ids = set()
    for item in cisa_vulnerabilities:
        cve_id = item["cveID"]
        cisa_cve_ids.add(cve_id)
        all_cve_ids.add(cve_id)
        
        # Determine CVSS
        cvss = None
        cvss_version = "N/A"
        
        # 1. Check current NVD KEV query
        if cve_id in nvd_kev_map:
            cvss = nvd_kev_map[cve_id]["cvss"]
            cvss_version = nvd_kev_map[cve_id]["cvss_version"]
            cvss_cache[cve_id] = {"cvss": cvss, "cvss_version": cvss_version}
        # 2. Check cache
        elif cve_id in cvss_cache:
            cvss = cvss_cache[cve_id]["cvss"]
            cvss_version = cvss_cache[cve_id]["cvss_version"]
        # 3. Query CIRCL API
        else:
            score, version = fetch_cvss_from_circl(cve_id)
            if score is not None:
                cvss = score
                cvss_version = version
                cvss_cache[cve_id] = {"cvss": cvss, "cvss_version": cvss_version}
                # Sleep a short duration to limit rate
                time.sleep(0.2)
        
        enriched_cves[cve_id] = {
            "cve_id": cve_id,
            "vendor": item.get("vendorProject", "Unknown"),
            "product": item.get("product", "Unknown"),
            "title": item.get("vulnerabilityName", "Unknown Vulnerability"),
            "description": item.get("shortDescription", ""),
            "cvss": cvss,
            "cvss_version": cvss_version,
            "in_kev": True,
            "date_added": item.get("dateAdded", ""),
            "due_date": item.get("dueDate", ""),
            "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
            "required_action": item.get("requiredAction", ""),
            "notes": item.get("notes", "")
        }
        
    # Process Recent CVE entries
    recent_added = 0
    for vuln in recent_nvd_items:
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id")
        
        # Skip if already added via KEV
        if cve_id in enriched_cves:
            continue
            
        all_cve_ids.add(cve_id)
        recent_added += 1
        
        score, version = extract_cvss_from_nvd_item(cve_item)
        cvss_version = version if version else "N/A"
        
        # Get description
        desc_text = ""
        for desc in cve_item.get("descriptions", []):
            if desc.get("lang") == "en":
                desc_text = desc.get("value", "")
                break
                
        # Get Vendor & Product (from configuration CPEs if available)
        vendor = "Unknown"
        product = "Unknown"
        configs = cve_item.get("configurations", [])
        if configs and len(configs) > 0:
            nodes = configs[0].get("nodes", [])
            if nodes and len(nodes) > 0:
                cpe_match = nodes[0].get("cpeMatch", [])
                if cpe_match and len(cpe_match) > 0:
                    cpe_uri = cpe_match[0].get("criteria", "")
                    # cpe:2.3:a:vendor:product:version:...
                    parts = cpe_uri.split(":")
                    if len(parts) > 4:
                        vendor = parts[3].capitalize()
                        product = parts[4].replace("_", " ").capitalize()
        
        enriched_cves[cve_id] = {
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "title": cve_item.get("cisaVulnerabilityName", "Unknown Vulnerability"),
            "description": desc_text,
            "cvss": score,
            "cvss_version": cvss_version,
            "in_kev": False,
            "date_added": cve_item.get("published", "").split("T")[0],
            "due_date": "",
            "ransomware": "Unknown",
            "required_action": "",
            "notes": ""
        }
        
    print(f"Added {recent_added} recent CVEs to database.")
    
    # 5. Fetch EPSS scores for all CVEs
    epss_map = fetch_epss_scores(all_cve_ids)
    
    # Merge EPSS scores
    for cve_id, cve in enriched_cves.items():
        if cve_id in epss_map:
            cve["epss"] = epss_map[cve_id]["epss"]
            cve["percentile"] = epss_map[cve_id]["percentile"]
        else:
            cve["epss"] = 0.0
            cve["percentile"] = 0.0
            
    # Save CVSS cache
    try:
        with open(CVSS_CACHE_PATH, "w") as f:
            json.dump(cvss_cache, f, indent=2)
        print("CVSS cache saved successfully.")
    except Exception as e:
        print(f"Error saving CVSS cache: {e}")
        
    # 6. Calculate statistics
    total_cve_count = len(enriched_cves)
    kev_count = len(cisa_cve_ids)
    
    immediate_patch_count = 0
    high_priority_count = 0
    scheduled_patch_count = 0
    watchlist_count = 0
    
    # Categorise CVEs for stats calculation
    for cve in enriched_cves.values():
        cvss = cve["cvss"] if cve["cvss"] is not None else 0.0
        epss = cve["epss"]
        in_kev = cve["in_kev"]
        
        if in_kev:
            immediate_patch_count += 1
        elif cvss >= 7.0 and epss > 0.10:
            high_priority_count += 1
        elif cvss >= 7.0:
            scheduled_patch_count += 1
        else:
            watchlist_count += 1
            
    output_data = {
        "last_updated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stats": {
            "total_cve_count": total_cve_count,
            "confirmed_exploited": kev_count,
            "immediate_patch": immediate_patch_count,
            "high_priority": high_priority_count,
            "scheduled_patch": scheduled_patch_count,
            "watchlist": watchlist_count
        },
        "cves": list(enriched_cves.values())
    }
    
    # Save main CVE data file
    try:
        with open(CVE_DATA_PATH, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Successfully compiled database to {CVE_DATA_PATH}!")
    except Exception as e:
        print(f"Error saving CVE data: {e}")
        
    duration = time.time() - start_time
    print(f"Data Sync finished in {duration:.2f} seconds.")

if __name__ == "__main__":
    main()
