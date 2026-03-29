import pandas as pd
import numpy as np
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s — %(message)s")
log = logging.getLogger(__name__)

RAW_DIR   = Path("data/CICIDS2017")
PROCESSED = Path("data/processed")

# CICIDS2017 column name after stripping whitespace
LABEL_COL = "Label"

def load_raw() -> pd.DataFrame:
    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {RAW_DIR}")

    log.info(f"Loading {len(files)} CSV files...")
    frames = []
    for f in files:
        log.info(f"  Reading {f.name}")
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = df.columns.str.strip()  # remove leading/trailing spaces
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    log.info(f"Combined shape: {combined.shape}")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    log.info("Cleaning data...")

    # Drop duplicates
    before = len(df)
    df = df.drop_duplicates()
    log.info(f"  Dropped {before - len(df)} duplicates")

    # Replace infinity values with NaN then drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df = df.dropna()
    log.info(f"  Dropped {before - len(df)} rows with NaN/Inf")

    # Normalise label column
    df[LABEL_COL] = df[LABEL_COL].str.strip()

    # Consolidate label variants
    label_map = {
        "Web Attack \xef\xbf\xbd Brute Force":  "Web Attack",
        "Web Attack \xef\xbf\xbd XSS":          "Web Attack",
        "Web Attack \xef\xbf\xbd Sql Injection": "Web Attack",
        "DoS Hulk":                              "DDoS",
        "DoS GoldenEye":                         "DDoS",
        "DoS slowloris":                         "DDoS",
        "DoS Slowhttptest":                      "DDoS",
        "DDoS":                                  "DDoS",
    }
    df[LABEL_COL] = df[LABEL_COL].replace(label_map)

    log.info(f"  Label distribution:\n{df[LABEL_COL].value_counts()}")
    return df


def split_and_save(df: pd.DataFrame):
    from sklearn.model_selection import train_test_split

    PROCESSED.mkdir(parents=True, exist_ok=True)

    feature_cols = [c for c in df.columns if c != LABEL_COL]
    X = df[feature_cols]
    y = df[LABEL_COL]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    log.info(f"Train size: {len(X_train)} | Test size: {len(X_test)}")

    X_train.to_parquet(PROCESSED / "X_train.parquet", index=False)
    X_test.to_parquet(PROCESSED  / "X_test.parquet",  index=False)
    y_train.to_frame().to_parquet(PROCESSED / "y_train.parquet", index=False)
    y_test.to_frame().to_parquet(PROCESSED  / "y_test.parquet",  index=False)

    log.info(f"Saved processed files to {PROCESSED}")


if __name__ == "__main__":
    df = load_raw()
    df = clean(df)
    split_and_save(df)