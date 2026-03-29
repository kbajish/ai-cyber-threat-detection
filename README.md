# 🔐 AI Cyber Threat Detection

![CI](https://github.com/kbajish/ai-cyber-threat-detection/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-compose-blue)

AI Cyber Threat Detection is an end-to-end machine learning system that classifies network traffic into benign and malicious categories using XGBoost and Random Forest models trained on the CICIDS2017 dataset. The system is designed to support faster and more interpretable security triage by combining classical machine learning, explainable AI, and LLM-based reasoning.

Each prediction is enriched with SHAP-based feature attribution and mapped to MITRE ATT&CK tactics and techniques. A LangChain + Ollama LLM module generates SOC-style explanations grounded in model outputs, providing human-readable insights and mitigation context. The system includes DSGVO-aligned audit logging, a production-ready API, and an interactive dashboard.

---

## 🚀 Key Features

- 🔍 Supervised classification using XGBoost and Random Forest
- 📊 SHAP-based explainability (feature-level attribution per prediction)
- 🛡 MITRE ATT&CK mapping (e.g., T1046, T1498, T1110)
- 🤖 LLM-powered SOC explanations using LangChain + Ollama (local, no API key required)
- 🔐 DSGVO-aligned audit logging with SHA-256 pseudonymised IPs
- ⚡ FastAPI backend (`/predict`, `/audit`, `/health`)
- 📈 Streamlit dashboard with live threat feed and visual analytics
- 🔁 DVC for dataset versioning and reproducibility
- 📉 MLflow for experiment tracking
- 🐳 Docker Compose for full-stack deployment
- 🔄 GitHub Actions CI/CD with model accuracy and false-negative rate checks

---

## 🧠 System Architecture

```
CICIDS2017 Dataset (DVC tracked)
        ↓
src/data/preprocess.py
src/features/engineer.py
        ↓
src/models/train.py  →  MLflow tracking
        ↓
src/explainability/shap_explainer.py
src/threat_intel/mitre_mapper.py
        ↓
src/llm/explainer_chain.py  (LangChain + Ollama)
        ↓
api/main.py  (FastAPI)
        ↓
dashboard/app.py  (Streamlit — live feed)
        ↓
src/audit/logger.py  (SQLite, pseudonymised IPs)
```

---

## ⚙️ How It Works

Network flow records from CICIDS2017 are preprocessed into model-ready features and passed through trained classifiers to generate predictions and confidence scores. SHAP computes feature-level contributions for each prediction, while a rule-based mapper links detected attacks to MITRE ATT&CK techniques. These outputs are injected into a structured prompt used by a LangChain + Ollama LLM to generate SOC-style explanations grounded in model reasoning.

The final output — including prediction, confidence, SHAP values, MITRE mapping, and LLM explanation — is returned via the FastAPI `/predict` endpoint, logged to a DSGVO-aligned audit database, and visualised in real time through the Streamlit dashboard using a replay simulator that streams real CICIDS2017 test rows at configurable speed.

---

## 📊 Dashboard Overview

The Streamlit dashboard provides:

- 🚨 Live threat feed with colour-coded severity rows
- 📊 SHAP waterfall chart for the latest detected threat
- 🛡 MITRE ATT&CK technique and tactic badge per detection
- 🧠 LLM-generated SOC analyst explanation
- 📜 DSGVO audit log viewer (pseudonymised)

---

## 🛠 Tech Stack

### Core ML
- Python 3.10
- XGBoost, Scikit-learn (Random Forest)
- SHAP

### Backend
- FastAPI, Uvicorn

### LLM Layer
- LangChain
- Ollama (local LLM — llama3.2, no API key needed)

### Dashboard
- Streamlit

### MLOps
- MLflow (experiment tracking)
- DVC (data versioning)
- Docker Compose
- GitHub Actions (CI/CD)
- pytest (model regression tests)

### Storage
- SQLite (audit log)

---

## 📂 Project Structure

```
ai-cyber-threat-detection/
│
├── data/                          # DVC-tracked, not committed to Git
│   └── CICIDS2017/
│
├── models/                        # Saved model artifacts (.pkl)
│
├── notebooks/
│   └── 01_exploration.ipynb
│
├── src/
│   ├── data/
│   │   └── preprocess.py          # Raw data cleaning and splitting
│   ├── features/
│   │   └── engineer.py            # Feature engineering pipeline
│   ├── models/
│   │   ├── train.py               # XGBoost + RF training with MLflow
│   │   └── evaluate.py            # Metrics and threshold validation
│   ├── explainability/
│   │   └── shap_explainer.py      # SHAP TreeExplainer module
│   ├── threat_intel/
│   │   └── mitre_mapper.py        # CICIDS2017 label → ATT&CK technique
│   ├── audit/
│   │   └── logger.py              # DSGVO audit trail (SQLite)
│   ├── llm/
│   │   └── explainer_chain.py     # LangChain + Ollama chain
│   └── simulation/
│       └── replay.py              # CICIDS2017 row replay simulator
│
├── api/
│   └── main.py                    # FastAPI app
│
├── dashboard/
│   └── app.py                     # Streamlit dashboard
│
├── tests/
│   └── test_model.py              # pytest model regression tests
│
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions pipeline
│
├── mlruns/                        # MLflow tracking (not committed)
├── .dvc/
├── dvc.yaml
├── docker-compose.yml
├── Dockerfile.api
├── Dockerfile.dashboard
├── .env.example
├── requirements.api.txt
├── requirements.dashboard.txt
├── requirements.dev.txt
├── AI_ACT_COMPLIANCE.md
└── README.md
```

---

## ▶️ Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/kbajish/ai-cyber-threat-detection.git
cd ai-cyber-threat-detection
```

### 2. Pull the dataset (DVC)
```bash
dvc pull
```

### 3. Start all services
```bash
docker compose up --build
```

### 4. Access services
| Service | URL |
|---|---|
| API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |
| Dashboard | http://localhost:8501 |
| MLflow | http://localhost:5000 |

### 5. Run the live simulator (optional)
```bash
python -m src.simulation.replay --delay 0.5
```

---

## 🧪 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/predict` | Classify traffic — returns prediction, confidence, SHAP, MITRE, LLM narrative |
| `GET` | `/audit` | Retrieve pseudonymised inference log |
| `GET` | `/health` | Health check |

> SHAP and MITRE ATT&CK output are included directly in the `/predict` response. No separate `/explain` endpoint is needed.

---

## 🔐 Data & Privacy

- Source IP addresses are pseudonymised using SHA-256 hashing before storage — raw IPs are never persisted (DSGVO Art. 25 — privacy by design)
- All inference decisions are logged with timestamp, model version, prediction, confidence, and contributing SHAP features to support accountability (DSGVO Art. 22)
- See `AI_ACT_COMPLIANCE.md` for EU AI Act risk classification and safeguard documentation

---

## 📈 Future Improvements

- Real-time streaming with Kafka (natural next step after replay simulator)
- LSTM / Autoencoder for anomaly-based detection of zero-day threats
- Advanced SIEM integration (Splunk, Elastic SIEM)
- Role-based access control (RBAC) on the API
- Cloud deployment (AWS/GCP) with managed MLflow

---

## 👤 Author

Experienced IT professional with a background in development, cybersecurity, and ERP systems, with expertise in Industrial AI. Focused on building production-ready AI systems with explainability, LLM integration, and MLOps best practices.