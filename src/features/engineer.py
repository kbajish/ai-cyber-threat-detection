import pandas as pd
import numpy as np
from pathlib import Path
import logging
import joblib

logging.basicConfig(level=logging.INFO, format="%(asctime)s — %(message)s")
log = logging.getLogger(__name__)

PROCESSED = Path("data/processed")
MODELS    = Path("models")

# Features to drop — non-informative or leaky
DROP_COLS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
]

def load_processed():
    log.info("Loading processed data...")
    X_train = pd.read_parquet(PROCESSED / "X_train.parquet")
    X_test  = pd.read_parquet(PROCESSED / "X_test.parquet")
    y_train = pd.read_parquet(PROCESSED / "y_train.parquet").squeeze()
    y_test  = pd.read_parquet(PROCESSED / "y_test.parquet").squeeze()
    log.info(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    return X_train, X_test, y_train, y_test


def drop_irrelevant(df: pd.DataFrame) -> pd.DataFrame:
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    log.info(f"Dropping columns: {cols_to_drop}")
    return df.drop(columns=cols_to_drop)


def engineer(df: pd.DataFrame) -> pd.DataFrame:
    # Ratio features
    if "Total Fwd Packets" in df.columns and "Total Backward Packets" in df.columns:
        df = df.copy()
        total_packets = df["Total Fwd Packets"] + df["Total Backward Packets"]
        df["fwd_bwd_ratio"] = df["Total Fwd Packets"] / (total_packets + 1e-9)

    if "Total Length of Fwd Packets" in df.columns and "Total Length of Bwd Packets" in df.columns:
        total_bytes = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
        df["fwd_bytes_ratio"] = df["Total Length of Fwd Packets"] / (total_bytes + 1e-9)

    # Packet rate
    if "Flow Duration" in df.columns and "Total Fwd Packets" in df.columns:
        df["pkt_rate"] = (
            df["Total Fwd Packets"] + df["Total Backward Packets"]
        ) / (df["Flow Duration"] + 1e-9)

    return df


def save_features(X_train, X_test, y_train, y_test, feature_names):
    PROCESSED.mkdir(parents=True, exist_ok=True)
    MODELS.mkdir(parents=True, exist_ok=True)

    X_train.to_parquet(PROCESSED / "X_train_eng.parquet", index=False)
    X_test.to_parquet(PROCESSED  / "X_test_eng.parquet",  index=False)
    y_train.to_frame().to_parquet(PROCESSED / "y_train_eng.parquet", index=False)
    y_test.to_frame().to_parquet(PROCESSED  / "y_test_eng.parquet",  index=False)

    joblib.dump(feature_names, MODELS / "feature_names.pkl")
    log.info(f"Saved engineered features — {len(feature_names)} features")


if __name__ == "__main__":
    X_train, X_test, y_train, y_test = load_processed()

    X_train = drop_irrelevant(X_train)
    X_test  = drop_irrelevant(X_test)

    X_train = engineer(X_train)
    X_test  = engineer(X_test)

    feature_names = list(X_train.columns)
    log.info(f"Final feature count: {len(feature_names)}")

    save_features(X_train, X_test, y_train, y_test, feature_names)