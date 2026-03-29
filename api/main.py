import os
import json
import joblib
import pandas as pd
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from src.explainability.shap_explainer import ThreatShapExplainer
from src.threat_intel.mitre_mapper import map_to_mitre
from src.audit.logger import log_inference, get_recent_logs
from src.llm.explainer_chain import build_chain, format_features

load_dotenv()

MODELS = Path("models")

app = FastAPI(
    title       = "AI Cyber Threat Detection API",
    description = "Network traffic classification with SHAP, MITRE ATT&CK, and LLM explanations",
    version     = "1.0.0"
)

# ── Load models at startup ────────────────────────────────────────
model         = joblib.load(MODELS / "xgboost_threat.pkl")
feature_names = joblib.load(MODELS / "feature_names.pkl")
le            = joblib.load(MODELS / "label_encoder.pkl")
shap_explainer = ThreatShapExplainer(model, feature_names, le)
llm_chain      = build_chain()


# ── Request / Response schemas ────────────────────────────────────
class InferenceRequest(BaseModel):
    features:  dict
    source_ip: str = "0.0.0.0"

class MitreResponse(BaseModel):
    technique_id:   str
    technique_name: str
    tactic:         str
    mitre_url:      str

class PredictResponse(BaseModel):
    prediction:   str
    confidence:   float
    top_features: list
    mitre:        dict | None
    narrative:    str | None


# ── Endpoints ─────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "model": "xgboost", "version": "1.0.0"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: InferenceRequest):
    try:
        X = pd.DataFrame([req.features])

        # Align columns to training feature order
        for col in feature_names:
            if col not in X.columns:
                X[col] = 0
        X = X[feature_names]

        # Predict
        pred_enc   = model.predict(X)[0]
        prediction = le.inverse_transform([pred_enc])[0]
        confidence = float(model.predict_proba(X).max())

        # SHAP explanation
        shap_result = shap_explainer.explain(X, prediction, confidence)

        # MITRE mapping
        mitre   = map_to_mitre(prediction)
        mitre_d = {
            "technique_id":   mitre.technique_id,
            "technique_name": mitre.technique_name,
            "tactic":         mitre.tactic,
            "mitre_url":      mitre.mitre_url
        } if mitre else None

        # LLM narrative — only for threats
        narrative = None
        if prediction != "BENIGN":
            try:
                narrative = llm_chain.invoke({
                    "prediction":   prediction,
                    "technique":    f"{mitre.technique_name} ({mitre.technique_id})" if mitre else "Unknown",
                    "tactic":       mitre.tactic if mitre else "Unknown",
                    "confidence":   f"{confidence:.2f}",
                    "top_features": format_features(shap_result.top_features)
                })
            except Exception as e:
                narrative = f"LLM unavailable: {str(e)}"

        # DSGVO audit log
        log_inference(
            source_ip    = req.source_ip,
            prediction   = prediction,
            confidence   = confidence,
            top_features = shap_result.top_features,
            technique_id = mitre.technique_id if mitre else None,
            tactic       = mitre.tactic if mitre else None
        )

        return PredictResponse(
            prediction   = prediction,
            confidence   = confidence,
            top_features = shap_result.top_features,
            mitre        = mitre_d,
            narrative    = narrative
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit")
def audit(limit: int = 100):
    return get_recent_logs(limit)