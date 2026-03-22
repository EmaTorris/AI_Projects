import requests
import time


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_DELAY = 6

#faccio una richiesta al nvd api per ottenere i cve
def fetch_cve(product_name : str, max_results : int = 20 ) -> list[dict]:
    params = {"keywordSearch": product_name , "resultsPerPage": max_results}
    req = requests.get(NVD_BASE_URL, params=params, timeout=10)
    req.raise_for_status()
    res = req.json().get("vulnerabilities", [])
    time.sleep(RATE_LIMIT_DELAY)
    parsed_list = []
    for result in res:
        parsed = parse_cve(result)
        parsed_list.append(parsed)
    return parsed_list

#pulisco il contenuto del cve e rimuovo i dati non necessari
def parse_cve(raw : dict) -> dict:
    cve = raw["cve"]

    description = ""
    for entry in cve.get("descriptions", []):
        if entry["lang"] == "en":
            description = entry["value"]
            break

    # --- CVSS Score e Severity ---
    cvss_score = 0.0
    severity = "UNKNOWN"

    metrics = cve.get("metrics", {})

    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss_score = cvss_data["baseScore"]
        severity = cvss_data["baseSeverity"]
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_score = cvss_data["baseScore"]
        severity = "LEGACY"

    return {
        "cve_id": cve.get("id"),
        "published_date": cve.get("published"),
        "last_modified_date": cve.get("lastModified"),
        "description": description,
        "references": cve.get("references"),
        "cvss_metrics": cvss_score,
        "severity": severity,
        "vuln_status": cve.get("vulnStatus"),
    }