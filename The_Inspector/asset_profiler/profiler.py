from cve_rag.explainer import explain_cve
from cve_rag.query import query_cve



def profile_asset(asset: dict) -> dict:
    return {
        "asset_type": asset.get("type"),
        "os": asset.get("os"),
        "software_list": asset.get("software",[]),
        "exposed_ports": asset.get("exposed_ports", []),
        "attack_surface": len(asset.get("exposed_ports", []))
    }

def generate_cve_queries(profile: dict) -> list[str]:

    queries = []
    for software in profile["software_list"]:
        queries.append(f"CVE in {software}")

    if profile["os"]:
        queries.append(f"CVE in {profile['os']}")

    return queries

def analyze_asset(asset: dict) -> dict:
    profile = profile_asset(asset)
    queries = generate_cve_queries(profile)

    findings = []

    for query in queries:
        cve_list = query_cve(query)
        explanation = explain_cve(query, cve_list)
        findings.append({
            "query": query,
            "cves": cve_list,
            "explanation": explanation
        })

    return {
        "profile": profile,
        "findings": findings
    }
