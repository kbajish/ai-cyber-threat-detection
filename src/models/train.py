import pandas as pd
import numpy as np
from pathlib import Path
import logging
import joblib
import mlflow
import mlflow.sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, f1_score,
    classification_report
)
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

logging.basicConfig(level=logging.INFO, format="%(asctime)s — %(message)s")
log = logging.getLogger(__name__)

PROCESSED = Path("data/processed")
MODELS    = Path("models")

def load_data():
    log.info("Loading engineered features...")
    X_train = pd.read_parquet(PROCESSED / "X_train_eng.parquet")
    X_test  = pd.read_parquet(PROCESSED / "X_test_eng.parquet")
    y_train = pd.read_parquet(PROCESSED / "y_train_eng.parquet").squeeze()
    y_test  = pd.read_parquet(PROCESSED / "y_test_eng.parquet").squeeze()
    log.info(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    return X_train, X_test, y_train, y_test


def encode_labels(y_train, y_test):
    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    y_test_enc  = le.transform(y_test)
    joblib.dump(le, MODELS / "label_encoder.pkl")
    log.info(f"Classes: {list(le.classes_)}")
    return y_train_enc, y_test_enc, le


def train_xgboost(X_train, y_train, X_test, y_test, le):
    log.info("Training XGBoost...")

    mlflow.set_experiment("cyber-threat-detection")

    with mlflow.start_run(run_name="xgboost"):
        params = {
            "n_estimators":     300,
            "max_depth":        8,
            "learning_rate":    0.1,
            "subsample":        0.8,
            "use_label_encoder": False,
            "eval_metric":      "mlogloss",
            "random_state":     42,
            "n_jobs":           -1,
        }
        mlflow.log_params(params)

        model = XGBClassifier(**params)
        model.fit(X_train, y_train)

        preds      = model.predict(X_test)
        acc        = accuracy_score(y_test, preds)
        f1         = f1_score(y_test, preds, average="weighted")

        mlflow.log_metric("accuracy", acc)
        mlflow.log_metric("f1_weighted", f1)
        mlflow.sklearn.log_model(model, "xgboost_model")

        log.info(f"XGBoost — Accuracy: {acc:.4f} | F1: {f1:.4f}")
        log.info("\n" + classification_report(
            y_test, preds, target_names=le.classes_
        ))

        MODELS.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, MODELS / "xgboost_threat.pkl")
        log.info("Saved models/xgboost_threat.pkl")

    return model


def train_random_forest(X_train, y_train, X_test, y_test, le):
    log.info("Training Random Forest...")

    mlflow.set_experiment("cyber-threat-detection")

    with mlflow.start_run(run_name="random_forest"):
        params = {
            "n_estimators": 200,
            "max_depth":    20,
            "random_state": 42,
            "n_jobs":       -1,
        }
        mlflow.log_params(params)

        model = RandomForestClassifier(**params)
        model.fit(X_train, y_train)

        preds = model.predict(X_test)
        acc   = accuracy_score(y_test, preds)
        f1    = f1_score(y_test, preds, average="weighted")

        mlflow.log_metric("accuracy", acc)
        mlflow.log_metric("f1_weighted", f1)
        mlflow.sklearn.log_model(model, "rf_model")

        log.info(f"Random Forest — Accuracy: {acc:.4f} | F1: {f1:.4f}")
        log.info("\n" + classification_report(
            y_test, preds, target_names=le.classes_
        ))

        joblib.dump(model, MODELS / "rf_threat.pkl")
        log.info("Saved models/rf_threat.pkl")

    return model


if __name__ == "__main__":
    X_train, X_test, y_train, y_test = load_data()
    y_train_enc, y_test_enc, le = encode_labels(y_train, y_test)

    train_xgboost(X_train, y_train_enc, X_test, y_test_enc, le)
    train_random_forest(X_train, y_train_enc, X_test, y_test_enc, le)

    log.info("Day 1 complete — both models trained and saved.")