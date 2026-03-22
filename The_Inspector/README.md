# The Inspector
### AI-Driven Zero Trust Asset Admission System

An intelligent system for preventive security assessment of new assets 
before they are admitted to the network.

The goal is not to analyze what is already in production, but to 
automatically evaluate the risk of servers, containers, devices, or 
software before they are integrated into the infrastructure.

## Features
-  RAG on vulnerabilities (CVE) with ChromaDB + Ollama
-  Behavioral analysis in sandbox (PyShark)
-  Dynamic risk scoring
-  Zero Trust logic
-  LLM-powered explanations with LangChain + llama3
-  REST API with FastAPI

## Tech Stack
- **Python** — core language
- **FastAPI** — REST API
- **ChromaDB** — vector database for CVE indexing
- **LangChain** — LLM chain for explanations
- **Ollama** — local LLM (llama3:8b) and embeddings (embeddinggemma)
- **PyShark** — real network traffic capture and analysis
- **PyYAML** — configurable policy rules

## Architecture
```
New Asset Request
       │
       ▼
Asset Profiling        → extracts OS, software, exposed ports
       │
       ▼
CVE RAG Correlator     → semantic search on vulnerability database
       │
       ▼
Behavioral Sandbox     → real network traffic analysis (PyShark)
       │
       ▼
Risk Scoring Engine    → aggregates CVSS, severity, anomaly score
       │
       ▼
AI Policy Decision     → Allow / Quarantine / Reject
```

## Getting Started

### Prerequisites
- Python 3.13+
- Ollama installed and running
- Wireshark/tshark installed (for sandbox)

### Installation
```bash
git clone https://github.com/EmaTorris/the-inspector.git
cd the-inspector
pip install -r requirements.txt
```

### Pull Ollama models
```bash
ollama pull llama3:8b
ollama pull embeddinggemma
```

### Run the API
```bash
sudo uvicorn api_main:app --reload
```

### API Docs
Open your browser at:
```
http://localhost:8000/docs
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | System status |
| POST | `/index` | Index CVEs for a product |
| POST | `/query` | Semantic CVE search |
| POST | `/analyze` | Full asset analysis |

### Example: Analyze an asset
```json
POST /analyze
{
    "type": "server",
    "os": "Ubuntu 20.04",
    "software": ["Apache 2.4.49", "OpenSSH 8.2"],
    "exposed_ports": [22, 80],
    "run_sandbox": false
}
```

### Example response
```json
{
    "status": "ok",
    "profile": { ... },
    "scores": {
        "trust_score": 0.44,
        "risk_score": 0.56,
        "cvss_score": 0.78,
        "severity_score": 0.35,
        "attack_surface_score": 0.2,
        "anomaly_score": 0.4
    },
    "decision": "QUARANTINE",
    "rule_triggered": "Trust score medio"
}
```

## Security Paradigm
- **Zero Trust Architecture** — no asset is trusted by default
- **Pre-Deployment Security Assessment** — evaluate before admission
- **Autonomous Risk Evaluation** — AI-driven decision making
- **Policy as Code** — configurable rules via YAML

## Project Structure
```
the-inspector/
│
├── cve_rag/              # CVE RAG Layer
│   ├── fetcher.py        # NVD API client
│   ├── indexer.py        # ChromaDB indexing
│   ├── query.py          # Semantic search
│   └── explainer.py      # LLM explanations
│
├── asset_profiler/       # Asset Profiling Engine
│   └── profiler.py
│
├── risk_scoring/         # Risk Scoring Engine
│   └── scorer.py
│
├── sandbox/              # Behavioral Sandbox
│   └── analyzer.py
│
├── policy/               # Policy Engine
│   ├── engine.py
│   └── rules.yaml
│
├── api/                  # FastAPI
│   └── routes.py
│
├── api_main.py           # Entry point
├── requirements.txt
└── README.md
```
