from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cve_rag.fetcher import fetch_cve
from cve_rag.indexer import index_cves
from cve_rag.query import query_cve
from asset_profiler.profiler import analyze_asset
from risk_scoring.scorer import calculate_trust_score
from policy.engine import apply_policy

router = APIRouter()

# --- Modelli Pydantic ---

class AssetRequest(BaseModel):
    type: str
    os: str
    software: list[str]
    exposed_ports: list[int]
    run_sandbox: bool = False

class IndexRequest(BaseModel):
    product: str
    max_results: int = 10

class QueryRequest(BaseModel):
    query: str
    n_results: int = 5


# --- Endpoints ---

@router.get("/health")
def health():
    return {
        "status": "ok",
        "system": "The Inspector",
        "version": "1.0.0"
    }


@router.post("/index")
def index(request: IndexRequest):
    try:
        cves = fetch_cve(request.product, max_results=request.max_results)
        index_cves(cves)
        return {
            "status": "ok",
            "product": request.product,
            "indexed": len(cves)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query")
def query(request: QueryRequest):
    try:
        results = query_cve(request.query, n_results=request.n_results)
        return {
            "status": "ok",
            "query": request.query,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
def analyze(request: AssetRequest):
    try:
        # 1. Costruisci dizionario asset
        asset = {
            "type": request.type,
            "os": request.os,
            "software": request.software,
            "exposed_ports": request.exposed_ports
        }

        # 2. Analisi CVE
        report = analyze_asset(asset)

        # 3. Sandbox opzionale
        anomaly_score = 0.0
        if request.run_sandbox:
            from sandbox.analyzer import run_sandbox
            sandbox_result = run_sandbox()
            anomaly_score = sandbox_result["anomaly_score"]

        # 4. Trust Score
        score = calculate_trust_score(
            report["profile"],
            report["findings"],
            anomaly_score
        )

        # 5. Policy Engine
        decision = apply_policy(score)

        return {
            "status": "ok",
            "profile": report["profile"],
            "scores": score,
            "decision": decision["decision"],
            "rule_triggered": decision["rule_triggered"],
            "findings": [
                {
                    "query": f["query"],
                    "cves_found": len(f["cves"]),
                    "explanation": f["explanation"]
                }
                for f in report["findings"]
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))