"""
Trains a multiclass network-intrusion classifier on CICIDS2017 flow data.
Predicts BENIGN vs the specific attack type (DoS Hulk, PortScan, DDoS,
FTP-Patator, Bot, etc.) rather than just "intrusion or not."

Usage:
    python train_model.py

Reads every *.csv in ./data (real CICIDS2017 files if present, otherwise
auto-generates a small synthetic stand-in). Writes the trained model,
scaler, label encoder, and metadata to ./model/ for app.py to serve.
"""
import glob
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from features import FEATURE_ORDER, LABEL_COLUMN_CANDIDATES, BENIGN_LABEL

DATA_DIR = Path(__file__).parent / "data"
MODEL_DIR = Path(__file__).parent / "model"

# CICIDS2017 has ~15 raw attack labels split across DoS/DDoS/PortScan/etc.
# subtypes. Collapsing extremely rare ones (a handful of rows each in the
# original dataset, e.g. Heartbleed, Infiltration) into a shared "Other
# Attack" bucket keeps every class large enough to actually learn and
# evaluate. Everything else keeps its own label.
MIN_CLASS_COUNT = 20
OTHER_ATTACK_LABEL = "Other Attack"


def load_raw_data() -> pd.DataFrame:
    csv_files = sorted(glob.glob(str(DATA_DIR / "*.csv")))
    if not csv_files:
        print("No CSVs found in ./data — generating a synthetic demo dataset.")
        from generate_sample_data import generate

        csv_files = [str(generate())]

    frames = []
    for f in csv_files:
        print(f"Loading {f} ...")
        df = pd.read_csv(f, low_memory=False, encoding="latin1")
        # CICIDS2017's real CSVs have a leading space in most headers.
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def find_label_column(df: pd.DataFrame) -> str:
    for cand in LABEL_COLUMN_CANDIDATES:
        if cand.strip() in df.columns:
            return cand.strip()
    raise ValueError(
        f"Could not find a label column. Looked for {LABEL_COLUMN_CANDIDATES}, "
        f"got columns: {list(df.columns)[:10]}..."
    )


def clean(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in FEATURE_ORDER if c not in df.columns]
    if missing:
        raise ValueError(
            f"Dataset is missing expected CICIDS2017 columns: {missing}\n"
            "If you're using a different CSV export, update FEATURE_ORDER "
            "in features.py to match your column names."
        )

    label_col = find_label_column(df)
    keep_cols = FEATURE_ORDER + [label_col]
    df = df[keep_cols].copy()
    df = df.rename(columns={label_col: "Label"})

    # CICIDS2017 is notorious for inf/-inf in Flow Bytes/s and Flow Packets/s
    df[FEATURE_ORDER] = df[FEATURE_ORDER].apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    df["Label"] = df["Label"].astype(str).str.strip()
    return df


def collapse_rare_classes(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["Label"].value_counts()
    rare = counts[counts < MIN_CLASS_COUNT].index
    rare = [c for c in rare if c != BENIGN_LABEL]
    if len(rare):
        print(f"Collapsing {len(rare)} rare attack labels into '{OTHER_ATTACK_LABEL}': {rare}")
        df["Label"] = df["Label"].replace({c: OTHER_ATTACK_LABEL for c in rare})
    return df


def train():
    t0 = time.time()
    raw = load_raw_data()
    print(f"Raw rows: {len(raw)}")

    df = clean(raw)
    df = collapse_rare_classes(df)
    print(f"Rows after cleaning: {len(df)}")
    print("Class balance:\n", df["Label"].value_counts())

    encoder = LabelEncoder()
    y = encoder.fit_transform(df["Label"])
    class_names = list(encoder.classes_)
    benign_idx = class_names.index(BENIGN_LABEL) if BENIGN_LABEL in class_names else None

    X = df[FEATURE_ORDER].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=250,
        max_depth=24,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_s, y_train)

    y_pred = model.predict(X_test_s)

    # Multiclass metrics (macro-averaged across attack types)
    multiclass_metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
        "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
        "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
    }

    # Binary view (BENIGN vs any attack), collapsed from the multiclass
    # predictions, so the dashboard can still show a simple confusion matrix.
    if benign_idx is not None:
        y_test_bin = (y_test != benign_idx).astype(int)
        y_pred_bin = (y_pred != benign_idx).astype(int)
    else:
        y_test_bin = np.ones_like(y_test)
        y_pred_bin = np.ones_like(y_pred)

    binary_metrics = {
        "accuracy": accuracy_score(y_test_bin, y_pred_bin),
        "precision": precision_score(y_test_bin, y_pred_bin, zero_division=0),
        "recall": recall_score(y_test_bin, y_pred_bin, zero_division=0),
        "f1": f1_score(y_test_bin, y_pred_bin, zero_division=0),
        "confusion_matrix": confusion_matrix(y_test_bin, y_pred_bin).tolist(),
    }

    per_class_report = classification_report(
        y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0
    )

    metrics = {
        **binary_metrics,
        "multiclass": multiclass_metrics,
        "class_names": class_names,
        "per_class": {
            name: {
                "precision": per_class_report[name]["precision"],
                "recall": per_class_report[name]["recall"],
                "f1": per_class_report[name]["f1-score"],
                "support": int(per_class_report[name]["support"]),
            }
            for name in class_names
        },
        "n_train": len(X_train),
        "n_test": len(X_test),
        "trained_on_synthetic_data": not any(
            "ISCX" in f or "workingHours" in f for f in glob.glob(str(DATA_DIR / "*.csv"))
        ),
    }

    print("\n=== Evaluation on held-out test set ===")
    print(f"Binary accuracy: {binary_metrics['accuracy']:.4f}")
    print(f"Multiclass accuracy: {multiclass_metrics['accuracy']:.4f}")
    print("\nBinary confusion matrix [[TN, FP], [FN, TP]]:")
    print(np.array(binary_metrics["confusion_matrix"]))
    print("\n" + classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    importances = sorted(zip(FEATURE_ORDER, model.feature_importances_), key=lambda x: -x[1])
    print("\nTop 10 most important features:")
    for name, imp in importances[:10]:
        print(f"  {name:35s} {imp:.4f}")

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_DIR / "model.pkl")
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")
    joblib.dump(encoder, MODEL_DIR / "label_encoder.pkl")
    with open(MODEL_DIR / "metadata.json", "w") as f:
        json.dump(
            {
                "feature_order": FEATURE_ORDER,
                "metrics": metrics,
                "feature_importances": {n: float(i) for n, i in importances},
                "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            f,
            indent=2,
        )

    print(f"\nSaved model + scaler + label encoder + metadata to {MODEL_DIR}/  ({time.time()-t0:.1f}s)")


if __name__ == "__main__":
    train()
