# EU AI Act & DSGVO Compliance Notes

## Risk classification
This system performs automated threat classification on network traffic.
Under EU AI Act Annex III, AI systems used in critical infrastructure
security may qualify as high-risk. This project implements the following
safeguards accordingly.

## DSGVO measures
- Source IP addresses are pseudonymised using SHA-256 hashing before
  storage. Raw IPs are never persisted (Art. 25 — privacy by design).
- All inference decisions are logged with timestamp, model version,
  and contributing features to support accountability (Art. 22).

## Explainability
- Per-prediction SHAP values are computed and stored, enabling human
  review of any automated decision.
- A human-readable narrative is generated via LLM for all threat
  detections above 0.7 confidence.

## Model governance
- Model version is recorded in every audit log entry.
- Accuracy and false-negative rate are enforced via CI regression tests.
- Experiment tracking via MLflow retains full training lineage.