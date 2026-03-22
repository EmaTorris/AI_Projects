'''from cve_rag.fetcher import fetch_cve
from cve_rag.indexer import index_cves
from cve_rag.query import query_cve
from cve_rag.explainer import explain_cve

results = fetch_cve("Apache", max_results=3)
index_cves(results)

query_results = query_cve("buffer overflow remote attack")
explanation = explain_cve("buffer overflow remote attack", query_results)
print(explanation)'''


from cve_rag.fetcher import fetch_cve
from cve_rag.indexer import index_cves
from asset_profiler.profiler import analyze_asset


'''results = fetch_cve("Apache", max_results=10)
index_cves(results)


asset = {
    "type": "server",
    "os": "Ubuntu 20.04",
    "software": ["Apache 2.4.49", "OpenSSH 8.2"],
    "exposed_ports": [22, 80]
}


report = analyze_asset(asset)


print("=== PROFILO ASSET ===")
print(report["profile"])


print("\n=== FINDINGS ===")
for finding in report["findings"]:
    print(f"\n Query: {finding['query']}")
    print(f" CVE trovati: {len(finding['cves'])}")
    print(f" Spiegazione:\n{finding['explanation']}")
    print("-" * 50)

from risk_scoring.scorer import calculate_trust_score

report = analyze_asset(asset)
score = calculate_trust_score(report["profile"], report["findings"])

print("\n=== TRUST SCORE ===")
print(f"Trust Score:          {score['trust_score']}")
print(f"Risk Score:           {score['risk_score']}")
print(f"CVSS Score:           {score['cvss_score']}")
print(f"Severity Score:       {score['severity_score']}")
print(f"Attack Surface Score: {score['attack_surface_score']}")
print(f"Decisione:            {score['decision']}")'''


from cve_rag.fetcher import fetch_cve
from cve_rag.indexer import index_cves
from asset_profiler.profiler import analyze_asset
from risk_scoring.scorer import calculate_trust_score
from sandbox.analyzer import run_sandbox
from policy.engine import apply_policy

# 1. Asset da analizzare
asset = {
    "type": "server",
    "os": "Ubuntu 20.04",
    "software": ["Apache 2.4.49", "OpenSSH 8.2"],
    "exposed_ports": [22, 80]
}

# 2. Scarica e indicizza CVE
print("=== INDICIZZAZIONE CVE ===")
results = fetch_cve("Apache", max_results=10)
index_cves(results)

# 3. Analizza asset
print("\n=== ANALISI ASSET ===")
report = analyze_asset(asset)
print(f"Asset: {report['profile']['asset_type']}")
print(f"Software: {report['profile']['software_list']}")

# 4. Sandbox
print("\n=== SANDBOX ===")
sandbox_result = run_sandbox()
print(f"Pacchetti catturati:  {sandbox_result['packets_captured']}")
print(f"IP unici:             {sandbox_result['outbound_connections']['unique_destinations']}")
print(f"Query DNS:            {sandbox_result['dns_analysis']['total_queries']}")
print(f"Anomaly Score:        {sandbox_result['anomaly_score']}")

# 5. Trust Score
print("\n=== TRUST SCORE ===")
score = calculate_trust_score(
    report["profile"],
    report["findings"],
    sandbox_result["anomaly_score"]
)
print(f"Trust Score:          {score['trust_score']}")
print(f"Risk Score:           {score['risk_score']}")
print(f"CVSS Score:           {score['cvss_score']}")
print(f"Severity Score:       {score['severity_score']}")
print(f"Attack Surface Score: {score['attack_surface_score']}")
print(f"Anomaly Score:        {score['anomaly_score']}")

# 6. Policy Engine
print("\n=== DECISIONE FINALE ===")
decision = apply_policy(score)
print(f"Decisione:            {decision['decision']}")
print(f"Regola applicata:     {decision['rule_triggered']}")
