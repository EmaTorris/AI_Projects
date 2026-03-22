def calculate_cvss_score(findings: list) -> float:
    cvss_scores = []

    for finding in findings:
        for cve in finding["cves"]:
            if cve["cvss_metrics"] is not None:
                cvss_scores.append(cve["cvss_metrics"])

    if not cvss_scores:
        return 0.0

    return (sum(cvss_scores) / len(cvss_scores)) / 10


def calculate_severity_score(findings: list) -> float:
    severity_weights = {
        "CRITICAL": 1.0,
        "HIGH": 0.7,
        "MEDIUM": 0.4,
        "LOW": 0.1,
        "LEGACY": 0.3,
        "UNKNOWN": 0.0
    }

    weights = []

    for finding in findings:
        for cve in finding["cves"]:
            severity = cve["severity"]
            weight = severity_weights.get(severity, 0.0)
            weights.append(weight)

    if not weights:
        return 0.0

    return sum(weights) / len(weights)


def calculate_attack_surface_score(profile: dict) -> float:
    attack_surface = profile.get("attack_surface", 0)
    return min(attack_surface / 10, 1.0)


def calculate_trust_score(profile: dict, findings: list, anomaly_score: float = 0.0) -> dict:
    cvss_score = calculate_cvss_score(findings)
    severity_score = calculate_severity_score(findings)
    attack_surface_score = calculate_attack_surface_score(profile)

    risk_score = (
            cvss_score * 0.50 +
            severity_score * 0.25 +
            attack_surface_score * 0.10 +
            anomaly_score * 0.15
    )

    trust_score = round(1 - risk_score, 2)

    if trust_score >= 0.7:
        decision = "ALLOW"
    elif trust_score >= 0.4:
        decision = "QUARANTINE"
    else:
        decision = "REJECT"

    return {
        "trust_score": trust_score,
        "risk_score": round(risk_score, 2),
        "cvss_score": round(cvss_score, 2),
        "severity_score": round(severity_score, 2),
        "attack_surface_score": round(attack_surface_score, 2),
        "anomaly_score": round(anomaly_score, 2),
        "decision": decision
    }