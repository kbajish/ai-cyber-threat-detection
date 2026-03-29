import pytest
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.metrics import accuracy_score, f1_score

MODELS    = Path("models")
PROCESSED = Path("data/processed")


@pytest.fixture(scope="module")
def model_and_data():
    model         = joblib.load(MODELS / "xgboost_threat.pkl")
    feature_names = joblib.load(MODELS / "feature_names.pkl")
    le            = joblib.load(MODELS / "label_encoder.pkl")
    X_test        = pd.read_parquet(PROCESSED / "X_test_eng.parquet")
    y_test        = pd.read_parquet(PROCESSED / "y_test_eng.parquet").squeeze()
    return model, feature_names, le, X_test, y_test


def test_model_files_exist():
    assert (MODELS / "xgboost_threat.pkl").exists(),   "xgboost model missing"
    assert (MODELS / "feature_names.pkl").exists(),    "feature_names missing"
    assert (MODELS / "label_encoder.pkl").exists(),    "label_encoder missing"


def test_accuracy_threshold(model_and_data):
    model, _, le, X_test, y_test = model_and_data
    preds   = le.inverse_transform(model.predict(X_test))
    acc     = accuracy_score(y_test, preds)
    assert acc >= 0.98, f"Accuracy {acc:.4f} below threshold 0.98"


def test_f1_threshold(model_and_data):
    model, _, le, X_test, y_test = model_and_data
    preds = le.inverse_transform(model.predict(X_test))
    f1    = f1_score(y_test, preds, average="weighted")
    assert f1 >= 0.98, f"F1 {f1:.4f} below threshold 0.98"


def test_false_negative_rate(model_and_data):
    """Attack traffic must not be misclassified as BENIGN above 2%."""
    model, _, le, X_test, y_test = model_and_data
    preds       = le.inverse_transform(model.predict(X_test))
    attack_mask = y_test != "BENIGN"
    fn_rate     = (preds[attack_mask] == "BENIGN").mean()
    assert fn_rate <= 0.02, f"False negative rate {fn_rate:.4f} too high"


def test_predict_output_shape(model_and_data):
    """Model returns one prediction per input row."""
    model, feature_names, _, X_test, _ = model_and_data
    sample = X_test.head(10)
    preds  = model.predict(sample)
    assert len(preds) == 10


def test_all_classes_predicted(model_and_data):
    """Model can predict all expected classes."""
    model, _, le, X_test, _ = model_and_data
    preds   = le.inverse_transform(model.predict(X_test))
    predicted_classes = set(preds)
    expected_classes  = {
        "BENIGN", "DDoS", "PortScan",
        "FTP-Patator", "SSH-Patator", "Bot", "Web Attack"
    }
    assert expected_classes.issubset(predicted_classes), \
        f"Missing classes: {expected_classes - predicted_classes}"