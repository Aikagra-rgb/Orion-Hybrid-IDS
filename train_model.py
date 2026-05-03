# --- IDS_project2/train_model.py ---
"""
ORION ML Model Training Pipeline
==================================
Trains a Random-Forest classifier on the NSL-KDD dataset (or a carefully
engineered synthetic dataset) and saves it as model.pkl.

Feature vector — MUST match detectors/anomaly.py's extract_features():
  [packet_length, protocol, ttl, dport, sport, tcp_flags, payload_size]

Improvements over v1:
  • 7 features instead of 3 → better discrimination
  • Synthetic data that mirrors real attack patterns (SYN flood, exfil, scans)
  • Class-balanced training via class_weight='balanced'
  • Calibrated probabilities via CalibratedClassifierCV (for predict_proba)
  • Cross-validation F1 score reported before saving
  • Hyperparameter-tuned Random Forest (200 trees, min_samples_leaf=5)
  • NSL-KDD mapping updated to 7 features (TTL + dport + sport + flags)
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

FEATURES    = ["length", "proto", "ttl", "dport", "sport", "tcp_flags", "payload_size"]
MODEL_PATH  = "model.pkl"
N_ESTIMATORS = 200
RANDOM_STATE = 42


# ═════════════════════════════════════════════════════════════════════════════
#  NSL-KDD LOADER  (optional — used if the dataset file exists)
# ═════════════════════════════════════════════════════════════════════════════

def _load_nsl_kdd(file_path: str) -> tuple[pd.DataFrame, pd.Series] | None:
    """
    Attempt to load NSL-KDD KDDTrain+.txt and map it to our 7-feature space.
    Returns (X_df, y_series) or None if loading fails.
    """
    try:
        df = pd.read_csv(file_path, header=None)
        print(f"[+] Loaded NSL-KDD: {len(df):,} rows, {df.shape[1]} columns.")

        # Protocol column (index 1): tcp=1, udp=2, icmp/other=0
        proto_map = {"tcp": 1, "udp": 2}
        df["proto"] = df[1].map(proto_map).fillna(0).astype(int)

        # src_bytes (index 4) as proxy for packet length
        df["length"] = pd.to_numeric(df[4], errors="coerce").fillna(100)

        # NSL-KDD has no real TTL / port data — use realistic synthetic distributions
        n = len(df)
        df["ttl"]          = np.where(df["proto"] == 1,
                                      np.random.choice([64, 128], n),   # TCP
                                      np.random.choice([64, 255], n))   # UDP/other
        df["dport"]        = np.where(df["proto"] == 1,
                                      np.random.choice([22, 80, 443, 8080, 3306], n),
                                      np.random.choice([53, 123, 9999], n))
        df["sport"]        = np.random.randint(1024, 65536, n)
        df["tcp_flags"]    = np.where(df["proto"] == 1,
                                      np.random.choice([2, 18, 24], n),   # SYN, SYN-ACK, PSH-ACK
                                      0)
        df["payload_size"] = (df["length"] - 40).clip(lower=0)

        # Label: 'normal' → 0, anything else → 1
        df["label"] = df[41].apply(lambda x: 0 if str(x).strip().lower() == "normal" else 1)

        X = df[FEATURES]
        y = df["label"]
        print(f"[+] Class distribution — Normal: {(y==0).sum():,} | Attack: {(y==1).sum():,}")
        return X, y

    except Exception as e:
        print(f"[-] NSL-KDD loading failed: {e}")
        return None


# ═════════════════════════════════════════════════════════════════════════════
#  SYNTHETIC DATA GENERATOR  (fallback / always blended in)
# ═════════════════════════════════════════════════════════════════════════════

def _generate_synthetic(n_per_class: int = 3000) -> tuple[pd.DataFrame, pd.Series]:
    """
    Generate labelled synthetic traffic that closely mirrors the attack types
    the IDS is trained to detect.

    Normal traffic: varied but plausible TCP/UDP conversations
    Attack traffic: SYN floods, large UDP exfil, odd-TTL anomalies, brute-force, scans
    """
    rng = np.random.default_rng(RANDOM_STATE)
    rows_normal = []
    rows_attack = []

    # ── Normal traffic ────────────────────────────────────────────────────────
    for _ in range(n_per_class):
        proto      = rng.choice([1, 2])
        ttl        = rng.choice([64, 128])
        dport      = rng.choice([80, 443, 22, 53, 8080])
        sport      = int(rng.integers(1024, 65536))
        length     = int(rng.integers(60, 1400))
        tcp_flags  = rng.choice([24, 18]) if proto == 1 else 0   # PSH-ACK or SYN-ACK
        payload    = max(0, length - 40)
        rows_normal.append([length, proto, ttl, dport, sport, int(tcp_flags), payload])

    # ── Attack: SYN Flood ─────────────────────────────────────────────────────
    for _ in range(n_per_class // 4):
        dport = int(rng.integers(1, 65535))
        rows_attack.append([60, 1, 64, dport, int(rng.integers(20000, 65000)), 2, 0])

    # ── Attack: UDP Exfiltration ──────────────────────────────────────────────
    for _ in range(n_per_class // 4):
        length = int(rng.integers(1100, 9000))
        rows_attack.append([length, 2, 64, 9999, int(rng.integers(20000, 65000)), 0, length - 28])

    # ── Attack: Low-TTL anomaly (tunneling / traceroute abuse) ────────────────
    for _ in range(n_per_class // 4):
        length = int(rng.integers(400, 900))
        rows_attack.append([length, 1, 1, 443, int(rng.integers(20000, 65000)), 24, length - 40])

    # ── Attack: Port scan (tiny SYN packets, many unique ports) ──────────────
    for _ in range(n_per_class // 4):
        dport = int(rng.integers(1, 1024))
        rows_attack.append([60, 1, 128, dport, int(rng.integers(20000, 65000)), 2, 0])

    X_normal = pd.DataFrame(rows_normal, columns=FEATURES)
    y_normal = pd.Series([0] * len(rows_normal))

    X_attack = pd.DataFrame(rows_attack, columns=FEATURES)
    y_attack = pd.Series([1] * len(rows_attack))

    X = pd.concat([X_normal, X_attack], ignore_index=True)
    y = pd.concat([y_normal, y_attack], ignore_index=True)

    print(f"[+] Synthetic dataset — Normal: {len(X_normal):,} | Attack: {len(X_attack):,}")
    return X, y


# ═════════════════════════════════════════════════════════════════════════════
#  MODEL TRAINING
# ═════════════════════════════════════════════════════════════════════════════

def train_model():
    print("=" * 60)
    print("  ORION ML Training Pipeline v2.0")
    print("=" * 60)
    print(f"  Features : {FEATURES}")
    print(f"  Trees    : {N_ESTIMATORS}")
    print()

    # ── Try to load NSL-KDD ───────────────────────────────────────────────────
    nsl_kdd_dirs = [
        os.path.join(os.path.expanduser("~"), "Desktop", "NSL_KDD"),
        os.path.join(os.path.expanduser("~"), "Desktop", "NSL-KDD"),
        os.path.join(os.path.expanduser("~"), "Downloads", "NSL-KDD"),
    ]

    X_nsl, y_nsl = None, None
    for d in nsl_kdd_dirs:
        fp = os.path.join(d, "KDDTrain+.txt")
        if os.path.exists(fp):
            print(f"[+] NSL-KDD found at: {fp}")
            result = _load_nsl_kdd(fp)
            if result:
                X_nsl, y_nsl = result
            break

    if X_nsl is None:
        print("[-] NSL-KDD dataset not found — using enhanced synthetic data only.")
        print("    (Download from https://www.unb.ca/cic/datasets/nsl.html for production use)\n")

    # ── Build combined dataset ────────────────────────────────────────────────
    X_syn, y_syn = _generate_synthetic(n_per_class=3000)

    if X_nsl is not None:
        # Blend: NSL-KDD + synthetic for richer generalisation
        X = pd.concat([X_nsl, X_syn], ignore_index=True)
        y = pd.concat([y_nsl, y_syn], ignore_index=True)
        print(f"[+] Blended dataset — {len(X):,} samples total.")
    else:
        X, y = X_syn, y_syn

    # ── Build model pipeline ──────────────────────────────────────────────────
    print("\n[*] Building model pipeline (StandardScaler + RandomForest)...")
    base_rf = RandomForestClassifier(
        n_estimators     = N_ESTIMATORS,
        max_depth        = 20,
        min_samples_leaf = 5,
        class_weight     = "balanced",   # handles class imbalance automatically
        n_jobs           = -1,
        random_state     = RANDOM_STATE,
    )

    # CalibratedClassifierCV wraps the RF to produce well-calibrated predict_proba()
    calibrated_rf = CalibratedClassifierCV(base_rf, method="sigmoid", cv=3)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    calibrated_rf),
    ])

    # ── Cross-validation ──────────────────────────────────────────────────────
    print("[*] Running 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(pipeline, X, y, cv=cv, scoring="f1", n_jobs=-1)
    print(f"[+] CV F1 scores : {cv_scores.round(3)}")
    print(f"[+] Mean F1      : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    if cv_scores.mean() < 0.70:
        print("[!] Warning: Mean F1 < 0.70 — consider collecting more real data.")

    # ── Final fit on full dataset ─────────────────────────────────────────────
    print("\n[*] Training final model on full dataset...")
    pipeline.fit(X, y)

    # ── Quick classification report ───────────────────────────────────────────
    y_pred = pipeline.predict(X)
    print("\n[+] Training-set report (expect near-perfect — use CV scores above for real accuracy):")
    print(classification_report(y, y_pred, target_names=["Normal", "Attack"]))

    # ── Save ──────────────────────────────────────────────────────────────────
    joblib.dump(pipeline, MODEL_PATH)
    print(f"[+] Model saved to '{MODEL_PATH}'")
    print("=" * 60)
    print("  Training complete! Restart the ORION engine to use the new model.")
    print("=" * 60)


if __name__ == "__main__":
    train_model()