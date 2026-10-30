
from pathlib import Path
import json

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = ROOT / "data" / "iam" / "synthetic_iam_dataset.csv"
MODEL_PATH = ROOT / "models" / "cloudsentinel_iam_synthetic_random_forest.joblib"
METRICS_PATH = ROOT / "reports" / "synthetic_iam_model_metrics.json"

FEATURES = [
    "num_statements",
    "num_allow",
    "num_deny",
    "has_wildcard_action",
    "has_wildcard_resource",
    "has_full_admin",
    "has_public_principal",
    "has_passrole_wildcard",
    "priv_esc_action_count",
    "has_mfa_condition",
    "has_ip_condition",
    "has_encryption_condition",
    "num_conditions",
    "uses_notaction",
    "total_action_count",
    "cross_account_trust",
    "mfa_enabled",
    "access_key_age_days",
    "is_prod",
]

def main():
    df = pd.read_csv(DATA_PATH)
    df = df[FEATURES + ["label"]].apply(pd.to_numeric, errors="coerce")
    df = df.dropna()

    X = df[FEATURES]
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        min_samples_leaf=2,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    cm = confusion_matrix(y_test, predictions, labels=[0, 1])

    metrics = {
        "dataset": str(DATA_PATH),
        "dataset_rows": int(len(df)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "features": FEATURES,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "confusion_matrix_labels": ["NORMAL", "MISCONFIGURED"],
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["NORMAL", "MISCONFIGURED"],
            output_dict=True,
            zero_division=0,
        ),
        "label_definition": "Synthetic labels generated using a predefined risk-scoring rule.",
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "features": FEATURES,
            "target": "label",
            "metrics": metrics,
        },
        MODEL_PATH,
    )

    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("SYNTHETIC IAM MODEL TRAINING COMPLETE")
    print(f"Dataset rows: {len(df)}")
    print(f"Training rows: {len(X_train)}")
    print(f"Testing rows: {len(X_test)}")
    print(f"Accuracy:  {metrics['accuracy']:.2%}")
    print(f"Precision: {metrics['precision']:.2%}")
    print(f"Recall:    {metrics['recall']:.2%}")
    print(f"F1-score:  {metrics['f1_score']:.2%}")
    print("Confusion matrix (actual rows, predicted columns):")
    print(cm)
    print(f"Model saved: {MODEL_PATH}")
    print(f"Metrics saved: {METRICS_PATH}")

if __name__ == "__main__":
    main()
