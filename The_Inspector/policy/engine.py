import yaml
import os

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yaml")


def load_rules() -> list:
    with open(RULES_PATH, "r") as f:
        data = yaml.safe_load(f)
    return data["rules"]


def apply_policy(score_result: dict) -> dict:
    rules = load_rules()

    # Variabili disponibili per eval()
    trust_score = score_result["trust_score"]
    risk_score = score_result["risk_score"]
    cvss_score = score_result["cvss_score"]
    severity_score = score_result["severity_score"]
    anomaly_score = score_result["anomaly_score"]
    attack_surface_score = score_result["attack_surface_score"]

    for rule in rules:
        condition = rule["condition"]
        if eval(condition):
            return {
                "decision": rule["action"],
                "rule_triggered": rule["name"],
                "scores": score_result
            }

    # Fallback se nessuna regola scatta
    return {
        "decision": "QUARANTINE",
        "rule_triggered": "default",
        "scores": score_result
    }