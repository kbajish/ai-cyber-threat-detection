import pandas as pd
import requests
import time
import random
import argparse
from pathlib import Path

API_URL   = "http://localhost:8000"
PROCESSED = Path("data/processed")


def wait_for_api(retries: int = 10):
    for i in range(retries):
        try:
            requests.get(f"{API_URL}/health", timeout=2)
            print("API is ready.")
            return
        except Exception:
            print(f"Waiting for API... ({i+1}/{retries})")
            time.sleep(3)
    raise RuntimeError("API did not start in time.")


def replay(delay: float = 0.5, attack_boost: bool = True):
    X_test = pd.read_parquet(PROCESSED / "X_test_eng.parquet")
    y_test = pd.read_parquet(PROCESSED / "y_test_eng.parquet").squeeze()

    df = X_test.copy()
    df["label"] = y_test.values

    if attack_boost:
        benign  = df[df["label"] == "BENIGN"]
        attacks = df[df["label"] != "BENIGN"]
        n       = min(len(benign), len(attacks))
        df      = pd.concat([
            benign.sample(n, random_state=42),
            attacks.sample(n, random_state=42)
        ]).sample(frac=1, random_state=42).reset_index(drop=True)

    feature_cols = [c for c in df.columns if c != "label"]
    print(f"Replaying {len(df)} rows at {1/delay:.1f} rows/sec...")
    print("-" * 60)

    for i, row in df.iterrows():
        features  = row[feature_cols].to_dict()
        source_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"

        try:
            resp   = requests.post(
                f"{API_URL}/predict",
                json    = {"features": features, "source_ip": source_ip},
                timeout = 30
            )
            result     = resp.json()
            prediction = result.get("prediction", "?")
            confidence = result.get("confidence", 0)
            mitre      = result.get("mitre") or {}
            icon       = "THREAT" if prediction != "BENIGN" else "ok    "

            print(
                f"[{i:05d}] {icon} | "
                f"{prediction:20s} | "
                f"conf={confidence:.2f} | "
                f"{mitre.get('technique_id', ''):10s} | "
                f"{mitre.get('tactic', '')}"
            )

        except requests.exceptions.ConnectionError:
            print("API not reachable — is uvicorn running?")
            break

        time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CICIDS2017 replay simulator")
    parser.add_argument("--delay",     type=float, default=0.5,  help="Seconds between requests")
    parser.add_argument("--no-boost",  action="store_true",       help="Disable attack oversampling")
    args = parser.parse_args()

    wait_for_api()
    replay(args.delay, not args.no_boost)