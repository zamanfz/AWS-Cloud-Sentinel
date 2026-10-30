import boto3
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime, timezone


class IAMInventoryCollector:
    def __init__(self, profile_name="default"):
        self.session = boto3.Session(
            profile_name=profile_name
        )

        self.iam = self.session.client("iam")

    def get_users(self):
        users = []

        try:
            paginator = self.iam.get_paginator(
                "list_users"
            )

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user.get("UserName")

                    user_data = {
                        "username": username,
                        "user_id": user.get("UserId"),
                        "arn": user.get("Arn"),
                        "created": str(
                            user.get("CreateDate")
                        ),
                        "mfa_enabled": False,
                        "access_keys": [],
                        "attached_policies": [],
                        "groups": [],
                    }

                    try:
                        mfa = self.iam.list_mfa_devices(
                            UserName=username
                        )

                        user_data["mfa_enabled"] = (
                            len(
                                mfa.get(
                                    "MFADevices",
                                    []
                                )
                            ) > 0
                        )

                    except ClientError:
                        pass

                    try:
                        keys = self.iam.list_access_keys(
                            UserName=username
                        )

                        for key in keys.get(
                            "AccessKeyMetadata",
                            []
                        ):
                            access_key_id = key.get(
                                "AccessKeyId"
                            )

                            create_date = key.get(
                                "CreateDate"
                            )

                            age_days = None

                            if create_date:
                                now = datetime.now(
                                    timezone.utc
                                )

                                if create_date.tzinfo is None:
                                    create_date = create_date.replace(
                                        tzinfo=timezone.utc
                                    )

                                age_days = (
                                    now - create_date
                                ).days

                            last_used = {}

                            try:
                                last_used_response = (
                                    self.iam.get_access_key_last_used(
                                        AccessKeyId=access_key_id
                                    )
                                )

                                last_used = (
                                    last_used_response.get(
                                        "AccessKeyLastUsed",
                                        {}
                                    )
                                )

                            except ClientError:
                                last_used = {}

                            user_data[
                                "access_keys"
                            ].append(
                                {
                                    "access_key_id": access_key_id,
                                    "status": key.get(
                                        "Status"
                                    ),
                                    "created": str(
                                        create_date
                                    ),
                                    "age_days": age_days,
                                    "last_used": str(
                                        last_used.get(
                                            "LastUsedDate"
                                        )
                                    )
                                    if last_used.get(
                                        "LastUsedDate"
                                    )
                                    else None,
                                }
                            )

                    except ClientError:
                        pass

                    try:
                        policies = (
                            self.iam.list_attached_user_policies(
                                UserName=username
                            )
                        )

                        user_data[
                            "attached_policies"
                        ] = [
                            policy.get(
                                "PolicyName"
                            )
                            for policy in policies.get(
                                "AttachedPolicies",
                                []
                            )
                        ]

                    except ClientError:
                        pass

                    try:
                        groups = (
                            self.iam.list_groups_for_user(
                                UserName=username
                            )
                        )

                        user_data["groups"] = [
                            group.get(
                                "GroupName"
                            )
                            for group in groups.get(
                                "Groups",
                                []
                            )
                        ]

                    except ClientError:
                        pass

                    users.append(user_data)

            return users

        except (
            BotoCoreError,
            ClientError
        ) as exc:
            return {
                "error": str(exc)
            }

    def get_password_policy(self):
        try:
            response = (
                self.iam.get_account_password_policy()
            )

            return response.get(
                "PasswordPolicy",
                {}
            )

        except ClientError as exc:
            return {
                "error": str(exc)
            }

    def get_account_summary(self):
        try:
            response = (
                self.iam.get_account_summary()
            )

            return response.get(
                "SummaryMap",
                {}
            )

        except ClientError as exc:
            return {
                "error": str(exc)
            }

    def collect(self):
        return {
            "users": self.get_users(),
            "password_policy": self.get_password_policy(),
            "account_summary": self.get_account_summary(),
        }


if __name__ == "__main__":
    collector = IAMInventoryCollector()
    inventory = collector.collect()

    from pprint import pprint

    pprint(inventory)