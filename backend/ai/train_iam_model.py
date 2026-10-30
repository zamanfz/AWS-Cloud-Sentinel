import os
from urllib.parse import unquote

import boto3
import joblib


MODEL_PATH = "models/cloudsentinel_iam_random_forest.joblib"

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

PRIV_ESC_ACTIONS = {
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
}


class IAMRandomForest:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.features = FEATURES

    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"IAM model not found: {self.model_path}"
            )

        data = joblib.load(self.model_path)

        if isinstance(data, dict):
            self.model = data["model"]
            self.features = data.get(
                "features",
                FEATURES,
            )
        else:
            self.model = data
            self.features = FEATURES

        return True

    def _document(self, iam, policy_arn):
        try:
            policy = iam.get_policy(
                PolicyArn=policy_arn
            )

            version_id = policy["Policy"]["DefaultVersionId"]

            response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )

            document = response["PolicyVersion"]["Document"]

            if isinstance(document, str):
                import json
                document = json.loads(
                    unquote(document)
                )

            return document
        except Exception:
            return {}

    def _inline_documents(self, iam, username):
        documents = []

        try:
            response = iam.list_user_policies(
                UserName=username
            )

            for policy_name in response.get(
                "PolicyNames",
                [],
            ):
                try:
                    response = iam.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name,
                    )

                    document = response.get(
                        "PolicyDocument",
                        {},
                    )

                    if isinstance(document, str):
                        import json
                        document = json.loads(
                            unquote(document)
                        )

                    documents.append(document)

                except Exception:
                    pass

        except Exception:
            pass

        return documents

    def _attached_documents(self, iam, username):
        documents = []

        try:
            response = iam.list_attached_user_policies(
                UserName=username
            )

            for policy in response.get(
                "AttachedPolicies",
                [],
            ):
                arn = policy.get(
                    "PolicyArn"
                )

                if arn:
                    documents.append(
                        self._document(
                            iam,
                            arn,
                        )
                    )

        except Exception:
            pass

        return documents

    def _statements(self, documents):
        statements = []

        for document in documents:
            if not isinstance(document, dict):
                continue

            raw = document.get(
                "Statement",
                [],
            )

            if isinstance(raw, dict):
                raw = [raw]

            if isinstance(raw, list):
                statements.extend(raw)

        return statements

    def _as_list(self, value):
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]

    def _condition_count(self, condition):
        if not isinstance(condition, dict):
            return 0

        return sum(
            len(value)
            if isinstance(value, dict)
            else 1
            for value in condition.values()
        )

    def _condition_has(self, condition, terms):
        if not isinstance(condition, dict):
            return False

        text = str(condition).lower()

        return any(
            term in text
            for term in terms
        )

    def extract_features(
        self,
        user,
        password_policy=None,
        iam=None,
    ):
        statements = []

        if iam is not None:
            documents = (
                self._attached_documents(
                    iam,
                    user.get(
                        "username"
                    ),
                )
                + self._inline_documents(
                    iam,
                    user.get(
                        "username"
                    ),
                )
            )

            statements = self._statements(
                documents
            )

        num_allow = 0
        num_deny = 0
        wildcard_action = 0
        wildcard_resource = 0
        full_admin = 0
        public_principal = 0
        passrole_wildcard = 0
        priv_esc_count = 0
        mfa_condition = 0
        ip_condition = 0
        encryption_condition = 0
        condition_count = 0
        notaction = 0
        total_actions = 0
        cross_account = 0

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            effect = str(
                statement.get(
                    "Effect",
                    ""
                )
            ).lower()

            if effect == "allow":
                num_allow += 1

            if effect == "deny":
                num_deny += 1

            actions = self._as_list(
                statement.get(
                    "Action"
                )
            )

            resources = self._as_list(
                statement.get(
                    "Resource"
                )
            )

            if statement.get(
                "NotAction"
            ) is not None:
                notaction = 1

            total_actions += len(actions)

            if any(
                action == "*"
                or (
                    isinstance(action, str)
                    and action.endswith(":*")
                )
                for action in actions
            ):
                wildcard_action = 1

            if any(
                resource == "*"
                for resource in resources
            ):
                wildcard_resource = 1

            if (
                effect == "allow"
                and any(
                    action == "*"
                    for action in actions
                )
                and any(
                    resource == "*"
                    for resource in resources
                )
            ):
                full_admin = 1

            principal = statement.get(
                "Principal"
            )

            if principal == "*":
                public_principal = 1

            if isinstance(principal, dict):
                principal_text = str(
                    principal
                )

                if (
                    '"AWS": "*"' in principal_text
                    or '"AWS": [' in principal_text
                ):
                    public_principal = 1

            for action in actions:
                if not isinstance(
                    action,
                    str
                ):
                    continue

                normalized = action.lower()

                if (
                    normalized
                    == "iam:passrole"
                    and any(
                        resource == "*"
                        for resource in resources
                    )
                ):
                    passrole_wildcard = 1

                if (
                    normalized
                    in {
                        item.lower()
                        for item in PRIV_ESC_ACTIONS
                    }
                ):
                    priv_esc_count += 1

            condition = statement.get(
                "Condition",
                {}
            )

            condition_count += self._condition_count(
                condition
            )

            if self._condition_has(
                condition,
                [
                    "multifactorauth",
                    "mfa",
                ],
            ):
                mfa_condition = 1

            if self._condition_has(
                condition,
                [
                    "sourceip",
                    "sourcevpc",
                    "sourcevpce",
                ],
            ):
                ip_condition = 1

            if self._condition_has(
                condition,
                [
                    "encryption",
                    "kms",
                    "server-side-encryption",
                ],
            ):
                encryption_condition = 1

            if principal is not None:
                cross_account = 1

        access_keys = user.get(
            "access_keys",
            []
        )

        active_ages = [
            key.get("age_days")
            for key in access_keys
            if key.get("status") == "Active"
            and isinstance(
                key.get("age_days"),
                int,
            )
        ]

        username = str(
            user.get(
                "username",
                ""
            )
        ).lower()

        attached = [
            str(policy).lower()
            for policy in user.get(
                "attached_policies",
                []
            )
        ]

        if any(
            "administratoraccess" in policy
            for policy in attached
        ):
            full_admin = 1
            wildcard_action = 1
            wildcard_resource = 1

        return {
            "num_statements": len(
                statements
            ),
            "num_allow": num_allow,
            "num_deny": num_deny,
            "has_wildcard_action": wildcard_action,
            "has_wildcard_resource": wildcard_resource,
            "has_full_admin": full_admin,
            "has_public_principal": public_principal,
            "has_passrole_wildcard": passrole_wildcard,
            "priv_esc_action_count": priv_esc_count,
            "has_mfa_condition": mfa_condition,
            "has_ip_condition": ip_condition,
            "has_encryption_condition": encryption_condition,
            "num_conditions": condition_count,
            "uses_notaction": notaction,
            "total_action_count": total_actions,
            "cross_account_trust": cross_account,
            "mfa_enabled": int(
                bool(
                    user.get(
                        "mfa_enabled",
                        False
                    )
                )
            ),
            "access_key_age_days": max(
                active_ages,
                default=0,
            ),
            "is_prod": int(
                "prod" in username
                or "production" in username
            ),
        }

    def predict(
        self,
        user,
        password_policy=None,
        iam=None,
    ):
        if self.model is None:
            self.load()

        features = self.extract_features(
            user,
            password_policy,
            iam,
        )

        row = [
            features.get(
                name,
                0
            )
            for name in self.features
        ]

        prediction = int(
            self.model.predict(
                [row]
            )[0]
        )

        probability = None

        if hasattr(
            self.model,
            "predict_proba"
        ):
            probability = float(
                self.model.predict_proba(
                    [row]
                )[0][1]
            )

        return {
            "prediction": prediction,
            "status": (
                "MISCONFIGURED"
                if prediction == 1
                else "NORMAL"
            ),
            "misconfiguration_probability": (
                round(
                    probability * 100,
                    2,
                )
                if probability is not None
                else None
            ),
            "features": features,
        }
