import shap
import numpy as np
import pandas as pd
from dataclasses import dataclass
from typing import List
import joblib
from pathlib import Path

MODELS = Path("models")

@dataclass
class ShapResult:
    prediction: str
    confidence: float
    top_features: List[dict]
    base_value: float


class ThreatShapExplainer:
    def __init__(self, model, feature_names: List[str], label_encoder):
        self.explainer     = shap.TreeExplainer(model)
        self.feature_names = feature_names
        self.le            = label_encoder

    def explain(self, X_row: pd.DataFrame, predicted_class: str, confidence: float) -> ShapResult:
        shap_values = self.explainer.shap_values(X_row)

        # For multi-class XGBoost shap_values shape is (n_samples, n_features, n_classes)
        if isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            class_idx = list(self.le.classes_).index(predicted_class)
            values    = shap_values[0, :, class_idx]
            base_val  = float(self.explainer.expected_value[class_idx])
        elif isinstance(shap_values, list):
            class_idx = list(self.le.classes_).index(predicted_class)
            values    = shap_values[class_idx][0]
            base_val  = float(self.explainer.expected_value[class_idx])
        else:
            values   = shap_values[0]
            base_val = float(self.explainer.expected_value)

        # Top 5 features by absolute SHAP value
        top_idx      = np.argsort(np.abs(values))[::-1][:5]
        top_features = [
            {
                "feature":    self.feature_names[i],
                "shap_value": round(float(values[i]), 4)
            }
            for i in top_idx
        ]

        return ShapResult(
            prediction   = predicted_class,
            confidence   = confidence,
            top_features = top_features,
            base_value   = round(base_val, 4)
        )


if __name__ == "__main__":
    model         = joblib.load(MODELS / "xgboost_threat.pkl")
    feature_names = joblib.load(MODELS / "feature_names.pkl")
    le            = joblib.load(MODELS / "label_encoder.pkl")

    explainer = ThreatShapExplainer(model, feature_names, le)

    # Quick smoke test with a dummy row
    X_dummy = pd.DataFrame(
        [np.zeros(len(feature_names))],
        columns=feature_names
    )
    result = explainer.explain(X_dummy, "BENIGN", 0.99)
    print(f"Prediction:   {result.prediction}")
    print(f"Confidence:   {result.confidence}")
    print(f"Top features: {result.top_features}")
    print(f"Base value:   {result.base_value}")