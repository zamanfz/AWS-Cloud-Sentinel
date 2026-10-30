import json
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "cloudsentinel_isolation_forest.joblib")

FEATURE_NAMES = [
    "mfa_disabled",
    "active_access_keys",
    "oldest_access_key_age_days",
    "password_policy_missing",
    "admin_access",
    "wildcard_action",
    "wildcard_resource",
    "public_ingress_ports",
    "critical_public_ports",
    "all_ports_public",
    "s3_public_policy",
    "s3_public_acl",
    "s3_public_access_block_incomplete",
    "s3_versioning_disabled",
    "s3_encryption_missing",
    "ec2_public_ip",
    "ec2_imdsv1",
    "ec2_unencrypted_volume",
]


class CloudSentinelAnomalyModel:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.feature_names = FEATURE_NAMES

    def train(self, random_state=42, n_samples=1200):
        rng = np.random.default_rng(random_state)

        normal = np.zeros(
            (n_samples, len(FEATURE_NAMES)),
            dtype=float
        )

        normal[:, 0] = rng.binomial(1, 0.05, n_samples)
        normal[:, 1] = rng.poisson(0.6, n_samples)
        normal[:, 2] = rng.integers(0, 75, n_samples)
        normal[:, 3] = rng.binomial(1, 0.05, n_samples)
        normal[:, 4] = rng.binomial(1, 0.02, n_samples)
        normal[:, 5] = rng.binomial(1, 0.02, n_samples)
        normal[:, 6] = rng.binomial(1, 0.02, n_samples)
        normal[:, 7] = rng.poisson(0.2, n_samples)
        normal[:, 8] = rng.binomial(1, 0.01, n_samples)
        normal[:, 9] = rng.binomial(1, 0.005, n_samples)
        normal[:, 10] = rng.binomial(1, 0.01, n_samples)
        normal[:, 11] = rng.binomial(1, 0.01, n_samples)
        normal[:, 12] = rng.binomial(1, 0.02, n_samples)
        normal[:, 13] = rng.binomial(1, 0.08, n_samples)
        normal[:, 14] = rng.binomial(1, 0.03, n_samples)
        normal[:, 15] = rng.binomial(1, 0.03, n_samples)
        normal[:, 16] = rng.binomial(1, 0.03, n_samples)
        normal[:, 17] = rng.binomial(1, 0.04, n_samples)

        model = IsolationForest(
            n_estimators=300,
            contamination=0.08,
            random_state=random_state,
            n_jobs=-1,
        )

        model.fit(normal)

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        joblib.dump(
            {
                "model": model,
                "feature_names": FEATURE_NAMES,
            },
            self.model_path,
        )

        self.model = model

        return {
            "model_path": self.model_path,
            "algorithm": "Isolation Forest",
            "training_samples": n_samples,
            "features": len(FEATURE_NAMES),
        }

    def load(self):
        if not os.path.exists(self.model_path):
            return False

        data = joblib.load(self.model_path)

        self.model = data["model"]
        self.feature_names = data.get(
            "feature_names",
            FEATURE_NAMES,
        )

        return True

    def ensure_model(self):
        if self.model is not None:
            return True

        if self.load():
            return True

        self.train()

        return True

    def vectorize(self, features):
        return np.array(
            [
                float(features.get(name, 0))
                for name in self.feature_names
            ],
            dtype=float,
        ).reshape(1, -1)

    def predict(self, features):
        self.ensure_model()

        vector = self.vectorize(features)

        prediction = int(
            self.model.predict(vector)[0]
        )

        decision_score = float(
            self.model.decision_function(vector)[0]
        )

        anomaly_score = max(
            0.0,
            min(
                100.0,
                50.0 - (decision_score * 100.0),
            ),
        )

        is_anomaly = prediction == -1

        if anomaly_score >= 75:
            risk = "HIGH"
        elif anomaly_score >= 50:
            risk = "MEDIUM"
        elif anomaly_score >= 25:
            risk = "LOW"
        else:
            risk = "NORMAL"

        return {
            "is_anomaly": is_anomaly,
            "prediction": prediction,
            "decision_score": round(
                decision_score,
                4,
            ),
            "anomaly_score": round(
                anomaly_score,
                2,
            ),
            "risk": risk,
        }


def extract_iam_features(user, password_policy):
    access_keys = user.get(
        "access_keys",
        [],
    )

    active_keys = [
        key
        for key in access_keys
        if key.get("status") == "Active"
    ]

    ages = [
        key.get("age_days")
        for key in active_keys
        if isinstance(key.get("age_days"), int)
    ]

    password_policy_missing = 1 if (
        isinstance(password_policy, dict)
        and password_policy.get("error")
    ) else 0

    policies = [
        str(policy).lower()
        for policy in user.get(
            "attached_policies",
            [],
        )
    ]

    admin_access = int(
        any(
            "administratoraccess" in policy
            for policy in policies
        )
    )

    return {
        "mfa_disabled": int(
            not user.get(
                "mfa_enabled",
                False,
            )
        ),
        "active_access_keys": len(active_keys),
        "oldest_access_key_age_days": max(
            ages,
            default=0,
        ),
        "password_policy_missing": password_policy_missing,
        "admin_access": admin_access,
        "wildcard_action": 0,
        "wildcard_resource": 0,
    }


def extract_security_group_features(group):
    public_ports = []
    critical_ports = 0
    all_ports_public = 0

    for rule in group.get(
        "ingress_rules",
        [],
    ):
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        is_public = any(
            permission.get("CidrIp") == "0.0.0.0/0"
            for permission in rule.get(
                "IpRanges",
                [],
            )
        )

        if not is_public:
            continue

        if from_port is None and to_port is None:
            all_ports_public = 1
            continue

        if from_port is not None and to_port is not None:
            public_ports.append(
                max(
                    0,
                    int(to_port) - int(from_port) + 1,
                )
            )

            if any(
                from_port <= port <= to_port
                for port in [22, 3389, 3306, 5432, 27017]
            ):
                critical_ports += 1

    return {
        "public_ingress_ports": sum(public_ports),
        "critical_public_ports": critical_ports,
        "all_ports_public": all_ports_public,
    }


def extract_s3_features(bucket):
    pab = bucket.get(
        "public_access_block",
        {},
    )

    pab_incomplete = int(
        not all(
            pab.get(key, False)
            for key in [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
        )
    )

    return {
        "s3_public_policy": int(
            bucket.get(
                "policy_public",
                False,
            )
        ),
        "s3_public_acl": int(
            bucket.get(
                "acl_public",
                False,
            )
        ),
        "s3_public_access_block_incomplete": pab_incomplete,
        "s3_versioning_disabled": int(
            bucket.get(
                "versioning",
                "Disabled",
            ) != "Enabled"
        ),
        "s3_encryption_missing": int(
            bucket.get(
                "encryption",
                "NotConfigured",
            ) != "Enabled"
        ),
    }


def extract_ec2_features(instance):
    unencrypted = int(
        any(
            not volume.get(
                "encrypted",
                False,
            )
            for volume in instance.get(
                "volumes",
                [],
            )
        )
    )

    return {
        "ec2_public_ip": int(
            bool(
                instance.get(
                    "public_ip"
                )
            )
        ),
        "ec2_imdsv1": int(
            instance.get(
                "metadata_http_tokens"
            ) == "optional"
        ),
        "ec2_unencrypted_volume": unencrypted,
    }


def analyze_inventory(inventory, model=None):
    model = model or CloudSentinelAnomalyModel()
    model.ensure_model()

    results = []

    iam = inventory.get(
        "iam",
        {},
    )

    password_policy = iam.get(
        "password_policy",
        {},
    )

    for user in iam.get(
        "users",
        [],
    ):
        features = extract_iam_features(
            user,
            password_policy,
        )

        result = model.predict(features)

        results.append(
            {
                "resource_type": "IAM_USER",
                "resource": user.get(
                    "username",
                    "Unknown",
                ),
                "features": features,
                "model": result,
            }
        )

    for group in inventory.get(
        "security_groups",
        [],
    ):
        features = extract_security_group_features(
            group
        )

        result = model.predict(features)

        results.append(
            {
                "resource_type": "SECURITY_GROUP",
                "resource": group.get(
                    "group_id",
                    group.get(
                        "group_name",
                        "Unknown",
                    ),
                ),
                "features": features,
                "model": result,
            }
        )

    for bucket in inventory.get(
        "s3_buckets",
        [],
    ):
        features = extract_s3_features(
            bucket
        )

        result = model.predict(features)

        results.append(
            {
                "resource_type": "S3_BUCKET",
                "resource": bucket.get(
                    "name",
                    "Unknown",
                ),
                "features": features,
                "model": result,
            }
        )

    for instance in inventory.get(
        "ec2_instances",
        [],
    ):
        features = extract_ec2_features(
            instance
        )

        result = model.predict(features)

        results.append(
            {
                "resource_type": "EC2_INSTANCE",
                "resource": instance.get(
                    "instance_id",
                    "Unknown",
                ),
                "features": features,
                "model": result,
            }
        )

    return results


def get_model_summary(results):
    anomalies = [
        result
        for result in results
        if result.get("model", {}).get(
            "is_anomaly",
            False,
        )
    ]

    return {
        "algorithm": "Isolation Forest",
        "resources_analyzed": len(results),
        "anomalies_detected": len(anomalies),
        "model_status": "Ready",
    }
