import json
import os
from urllib.parse import unquote

import boto3
import joblib
import pandas as pd


MODEL_PATH = "models/cloudsentinel_iam_synthetic_random_forest.joblib"

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
        self.features = FEATURES.copy()

    def load(self):
        """Load the trained Random Forest model and its feature list."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"IAM model not found: {self.model_path}"
            )

        data = joblib.load(self.model_path)

        if isinstance(data, dict) and "model" in data:
            self.model = data["model"]
            self.features = data.get("features", FEATURES)
        else:
            self.model = data
            self.features = FEATURES.copy()

        return True

    def _document(self, iam, policy_arn):
        """Return the default version of an attached managed policy."""
        try:
            policy = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy["Policy"]["DefaultVersionId"]
            response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            document = response["PolicyVersion"]["Document"]

            if isinstance(document, str):
                document = json.loads(unquote(document))

            return document if isinstance(document, dict) else {}
        except Exception:
            # Keep scans running if a policy cannot be read; missing policy
            # documents may mean the model has incomplete feature information.
            return {}

    def _inline_documents(self, iam, username):
        """Collect inline policy documents attached directly to a user."""
        documents = []
        if not username:
            return documents

        try:
            response = iam.list_user_policies(UserName=username)
            for policy_name in response.get("PolicyNames", []):
                try:
                    response = iam.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name,
                    )
                    document = response.get("PolicyDocument", {})

                    if isinstance(document, str):
                        document = json.loads(unquote(document))

                    if isinstance(document, dict):
                        documents.append(document)
                except Exception:
                    continue
        except Exception:
            pass

        return documents

    

    def _attached_documents(self, iam, username):
        """Collect managed policies attached to a user and their groups."""
        documents = []

        if not username:
            print("DEBUG: IAM username is missing")
            return documents

        # 1. Policies attached directly to the user
        try:
            response = iam.list_attached_user_policies(UserName=username)

            for policy in response.get("AttachedPolicies", []):
                arn = policy.get("PolicyArn")
                if arn:
                    document = self._document(iam, arn)
                    if document:
                        documents.append(document)

        except Exception as exc:
            print(f"DEBUG: User managed policy error: {exc}")

        # 2. Policies inherited through IAM groups
        try:
            response = iam.list_groups_for_user(UserName=username)

            for group in response.get("Groups", []):
                group_name = group.get("GroupName")
                if not group_name:
                    continue

                # Group managed policies
                try:
                    result = iam.list_attached_group_policies(
                        GroupName=group_name
                    )

                    for policy in result.get("AttachedPolicies", []):
                        arn = policy.get("PolicyArn")
                        if arn:
                            document = self._document(iam, arn)
                            if document:
                                documents.append(document)
                            else:
                                print(
                                    f"DEBUG: Empty policy document: {arn}"
                                )

                except Exception as exc:
                    print(f"DEBUG: Group managed policy error: {exc}")

                # Group inline policies
                try:
                    result = iam.list_group_policies(
                        GroupName=group_name
                    )

                    for policy_name in result.get("PolicyNames", []):
                        policy_result = iam.get_group_policy(
                            GroupName=group_name,
                            PolicyName=policy_name,
                        )

                        document = policy_result.get("PolicyDocument", {})

                        if isinstance(document, str):
                            document = json.loads(unquote(document))

                        if isinstance(document, dict) and document:
                            documents.append(document)

                except Exception as exc:
                    print(f"DEBUG: Group inline policy error: {exc}")

        except Exception as exc:
            print(f"DEBUG: Group lookup error: {exc}")

        print(f"DEBUG: Total policy documents collected: {len(documents)}")

        return documents



    @staticmethod
    def _as_list(value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _condition_count(condition):
        if not isinstance(condition, dict):
            return 0

        count = 0
        for value in condition.values():
            if isinstance(value, dict):
                count += len(value)
            else:
                count += 1
        return count

    @staticmethod
    def _condition_has(condition, terms):
        if not isinstance(condition, dict):
            return False
        condition_text = json.dumps(condition, default=str).lower()
        return any(term in condition_text for term in terms)

    def _statements(self, documents):
        statements = []
        for document in documents:
            if not isinstance(document, dict):
                continue

            raw = document.get("Statement", [])
            if isinstance(raw, dict):
                raw = [raw]
            if isinstance(raw, list):
                statements.extend(
                    item for item in raw if isinstance(item, dict)
                )
        return statements

    def extract_features(self, user, password_policy=None, iam=None):
        """Convert an AWS IAM user summary into the model's feature fields."""
        statements = []

        if iam is not None:
            username = user.get("username") or user.get("UserName")

            try:
                documents = (
                    self._attached_documents(iam, username)
                    + self._inline_documents(iam, username)
                )
                statements = self._statements(documents)
            except Exception as exc:
                print(f"Policy extraction warning: {exc}")

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

        priv_esc_actions_lower = {
            item.lower() for item in PRIV_ESC_ACTIONS
        }

        for statement in statements:
            effect = str(statement.get("Effect", "")).lower()
            if effect == "allow":
                num_allow += 1
            elif effect == "deny":
                num_deny += 1

            actions = self._as_list(statement.get("Action"))
            resources = self._as_list(statement.get("Resource"))

            if statement.get("NotAction") is not None:
                notaction = 1

            total_actions += len(actions)

            if any(
                isinstance(action, str)
                and (action == "*" or action.endswith(":*"))
                for action in actions
            ):
                wildcard_action = 1

            if any(resource == "*" for resource in resources):
                wildcard_resource = 1

            if (
                effect == "allow"
                and any(action == "*" for action in actions)
                and any(resource == "*" for resource in resources)
            ):
                full_admin = 1

            principal = statement.get("Principal")
            if principal == "*":
                public_principal = 1
            elif isinstance(principal, dict):
                principal_text = json.dumps(principal).lower()
                if '"aws": "*"' in principal_text:
                    public_principal = 1

            for action in actions:
                if not isinstance(action, str):
                    continue

                normalized = action.lower()
                if (
                    normalized == "iam:passrole"
                    and any(resource == "*" for resource in resources)
                ):
                    passrole_wildcard = 1

                if normalized in priv_esc_actions_lower:
                    priv_esc_count += 1

            condition = statement.get("Condition", {})
            condition_count += self._condition_count(condition)

            if self._condition_has(condition, ["multifactorauth", "mfa"]):
                mfa_condition = 1
            if self._condition_has(
                condition, ["sourceip", "sourcevpc", "sourcevpce"]
            ):
                ip_condition = 1
            if self._condition_has(
                condition, ["encryption", "kms", "server-side-encryption"]
            ):
                encryption_condition = 1

            # A Principal in a policy often indicates a trust/resource policy;
            # it is not by itself proof of cross-account trust.
            if principal is not None:
                cross_account = 1

        access_keys = user.get("access_keys", [])
        active_ages = [
            key.get("age_days")
            for key in access_keys
            if isinstance(key, dict)
            and key.get("status") == "Active"
            and isinstance(key.get("age_days"), int)
        ]

        username = str(
            user.get("username") or user.get("UserName") or ""
        ).lower()

        attached = [
            str(policy).lower()
            for policy in user.get("attached_policies", [])
        ]
        if any("administratoraccess" in policy for policy in attached):
            full_admin = 1
            wildcard_action = 1
            wildcard_resource = 1

        mfa_enabled = bool(
            user.get("mfa_enabled", user.get("MFAEnabled", False))
        )

        # If a password policy object is passed, use its presence only as
        # contextual input where a compatible feature exists. This model's
        # current feature schema has no password-policy feature.
        _ = password_policy

        return {
            "num_statements": len(statements),
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
            "mfa_enabled": int(mfa_enabled),
            "access_key_age_days": max(active_ages, default=0),
            "is_prod": int("prod" in username or "production" in username),
        }

    def predict(self, user, password_policy=None, iam=None):
        """Predict whether an IAM profile is misconfigured."""
        if self.model is None:
            self.load()

        if not isinstance(user, dict):
            raise TypeError("Input must be a dictionary.")

        # Accept either a direct feature dictionary or an AWS user summary.
        if all(name in user for name in self.features):
            features = {name: user[name] for name in self.features}
        else:
            features = self.extract_features(
                user,
                password_policy=password_policy,
                iam=iam,
            )

        # Preserve the column names used when training the model.
        row = pd.DataFrame(
            [{name: features.get(name, 0) for name in self.features}],
            columns=self.features,
        )

        prediction = int(self.model.predict(row)[0])

        probability = None
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(row)[0]
            classes = list(self.model.classes_)
            if 1 in classes:
                probability = float(probabilities[classes.index(1)])

                print("DEBUG IAM FEATURES:", features)

        return {
            "prediction": prediction,
            "status": "MISCONFIGURED" if prediction == 1 else "NORMAL",
            "misconfiguration_probability": (
                round(probability * 100, 2)
                if probability is not None
                else None
            ),
            "features": features,
        }
