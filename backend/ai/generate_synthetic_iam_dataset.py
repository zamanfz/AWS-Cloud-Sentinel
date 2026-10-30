from pathlib import Path

import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = ROOT / "data" / "iam" / "synthetic_iam_dataset.csv"

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

def generate_dataset(n=2000, seed=42):
    rng = np.random.default_rng(seed)
    rows = []

    for i in range(n):
        is_prod = int(rng.random() < 0.45)
        mfa_enabled = int(rng.random() < 0.75)
        num_statements = int(rng.integers(1, 8))
        num_allow = int(rng.integers(0, num_statements + 1))
        num_deny = num_statements - num_allow
        has_wildcard_action = int(rng.random() < 0.15)
        has_wildcard_resource = int(rng.random() < 0.20)
        has_full_admin = int(
            has_wildcard_action and has_wildcard_resource and rng.random() < 0.70
        )
        has_public_principal = int(rng.random() < 0.04)
        has_passrole_wildcard = int(rng.random() < 0.08)
        priv_esc_action_count = int(rng.integers(0, 5))
        has_mfa_condition = int(rng.random() < 0.35)
        has_ip_condition = int(rng.random() < 0.30)
        has_encryption_condition = int(rng.random() < 0.30)
        num_conditions = int(rng.integers(0, 6))
        uses_notaction = int(rng.random() < 0.08)
        total_action_count = int(rng.integers(1, 30))
        cross_account_trust = int(rng.random() < 0.10)
        access_key_age_days = int(rng.integers(0, 1000))

        risk_score = (
            3 * has_wildcard_action
            + 3 * has_wildcard_resource
            + 4 * has_full_admin
            + 4 * has_public_principal
            + 3 * has_passrole_wildcard
            + 2 * (1 - mfa_enabled)
            + 2 * (access_key_age_days > 180)
            + 2 * cross_account_trust
            + priv_esc_action_count
            + int(is_prod and not mfa_enabled)
        )

        misconfigured = int(risk_score >= 7)

        rows.append({
            "profile_id": f"SYN-{i + 1:05d}",
            "entity_name": f"synthetic_iam_entity_{i + 1:05d}",
            "entity_type": rng.choice(["IAM_USER", "IAM_ROLE", "IAM_POLICY"]),
            "environment": "PRODUCTION" if is_prod else "DEVELOPMENT",
            "num_statements": num_statements,
            "num_allow": num_allow,
            "num_deny": num_deny,
            "has_wildcard_action": has_wildcard_action,
            "has_wildcard_resource": has_wildcard_resource,
            "has_full_admin": has_full_admin,
            "has_public_principal": has_public_principal,
            "has_passrole_wildcard": has_passrole_wildcard,
            "priv_esc_action_count": priv_esc_action_count,
            "has_mfa_condition": has_mfa_condition,
            "has_ip_condition": has_ip_condition,
            "has_encryption_condition": has_encryption_condition,
            "num_conditions": num_conditions,
            "uses_notaction": uses_notaction,
            "total_action_count": total_action_count,
            "cross_account_trust": cross_account_trust,
            "mfa_enabled": mfa_enabled,
            "access_key_age_days": access_key_age_days,
            "is_prod": is_prod,
            "label": misconfigured,
        })

    return pd.DataFrame(rows)

def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = generate_dataset()
    df.to_csv(OUTPUT_PATH, index=False)

    print("SYNTHETIC IAM DATASET CREATED")
    print(f"Dataset path: {OUTPUT_PATH}")
    print(f"Total profiles: {len(df)}")
    print(f"Features: {len(FEATURES)}")
    print("\nLabel counts:")
    print(df["label"].value_counts().sort_index().rename(index={
        0: "NORMAL",
        1: "MISCONFIGURED"
    }))
    print("\nFirst five profiles:")
    print(df.head().to_string(index=False))

if __name__ == "__main__":
    main()