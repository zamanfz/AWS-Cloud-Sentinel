import unittest

from backend.rules.security_rules import (
    check_security_groups,
    check_ec2_instances,
    check_s3_buckets,
    check_iam,
)


class TestSecurityGroupRules(unittest.TestCase):

    def test_public_ssh(self):
        inventory = {
            "security_groups": [
                {
                    "group_id": "sg-test",
                    "group_name": "test-sg",
                    "ingress_rules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        findings = check_security_groups(
            inventory
        )

        self.assertEqual(
            len(findings),
            1
        )

        self.assertEqual(
            findings[0]["rule"],
            "PUBLIC_SSH"
        )

        self.assertEqual(
            findings[0]["severity"],
            "HIGH"
        )

    def test_public_rdp(self):
        inventory = {
            "security_groups": [
                {
                    "group_id": "sg-test",
                    "group_name": "test-sg",
                    "ingress_rules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpRanges": [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        findings = check_security_groups(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "PUBLIC_RDP"
        )

    def test_all_ports_public(self):
        inventory = {
            "security_groups": [
                {
                    "group_id": "sg-test",
                    "group_name": "test-sg",
                    "ingress_rules": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        findings = check_security_groups(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "ALL_PORTS_PUBLIC"
        )

        self.assertEqual(
            findings[0]["severity"],
            "CRITICAL"
        )


class TestEC2Rules(unittest.TestCase):

    def test_public_ec2_ip(self):
        inventory = {
            "ec2_instances": [
                {
                    "instance_id": "i-test",
                    "state": "running",
                    "public_ip": "203.0.113.10",
                    "metadata_http_tokens": "required",
                    "volumes": []
                }
            ]
        }

        findings = check_ec2_instances(
            inventory
        )

        self.assertEqual(
            len(findings),
            1
        )

        self.assertEqual(
            findings[0]["rule"],
            "EC2_PUBLIC_IP"
        )

    def test_imdsv1_enabled(self):
        inventory = {
            "ec2_instances": [
                {
                    "instance_id": "i-test",
                    "state": "running",
                    "public_ip": None,
                    "metadata_http_tokens": "optional",
                    "volumes": []
                }
            ]
        }

        findings = check_ec2_instances(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "EC2_IMDSV1_ENABLED"
        )

        self.assertEqual(
            findings[0]["severity"],
            "HIGH"
        )

    def test_unencrypted_ebs(self):
        inventory = {
            "ec2_instances": [
                {
                    "instance_id": "i-test",
                    "state": "running",
                    "public_ip": None,
                    "metadata_http_tokens": "required",
                    "volumes": [
                        {
                            "volume_id": "vol-test",
                            "encrypted": False
                        }
                    ]
                }
            ]
        }

        findings = check_ec2_instances(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "EC2_EBS_ENCRYPTION_DISABLED"
        )

        self.assertEqual(
            findings[0]["severity"],
            "HIGH"
        )


class TestS3Rules(unittest.TestCase):

    def test_public_s3_policy(self):
        inventory = {
            "s3_buckets": [
                {
                    "name": "test-bucket",
                    "policy_public": True,
                    "acl_public": False,
                    "public_access_block": {},
                    "versioning": "Enabled"
                }
            ]
        }

        findings = check_s3_buckets(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "PUBLIC_S3_BUCKET_POLICY"
        )

        self.assertEqual(
            findings[0]["severity"],
            "CRITICAL"
        )

    def test_public_s3_acl(self):
        inventory = {
            "s3_buckets": [
                {
                    "name": "test-bucket",
                    "policy_public": False,
                    "acl_public": True,
                    "public_access_block": {},
                    "versioning": "Enabled"
                }
            ]
        }

        findings = check_s3_buckets(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "PUBLIC_S3_BUCKET_ACL"
        )

    def test_s3_versioning_disabled(self):
        inventory = {
            "s3_buckets": [
                {
                    "name": "test-bucket",
                    "policy_public": False,
                    "acl_public": False,
                    "public_access_block": {},
                    "versioning": "Disabled"
                }
            ]
        }

        findings = check_s3_buckets(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "S3_VERSIONING_DISABLED"
        )


class TestIAMRules(unittest.TestCase):

    def test_mfa_disabled(self):
        inventory = {
            "iam": {
                "users": [
                    {
                        "username": "test-user",
                        "mfa_enabled": False,
                        "access_keys": []
                    }
                ],
                "account_summary": {
                    "AccountMFAEnabled": 1
                },
                "password_policy": {}
            }
        }

        findings = check_iam(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "IAM_USER_MFA_DISABLED"
        )

        self.assertEqual(
            findings[0]["severity"],
            "HIGH"
        )

    def test_old_access_key(self):
        inventory = {
            "iam": {
                "users": [
                    {
                        "username": "test-user",
                        "mfa_enabled": True,
                        "access_keys": [
                            {
                                "status": "Active",
                                "age_days": 120
                            }
                        ]
                    }
                ],
                "account_summary": {
                    "AccountMFAEnabled": 1
                },
                "password_policy": {}
            }
        }

        findings = check_iam(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "IAM_OLD_ACCESS_KEY"
        )

    def test_password_policy_missing(self):
        inventory = {
            "iam": {
                "users": [],
                "account_summary": {
                    "AccountMFAEnabled": 1
                },
                "password_policy": {
                    "error": "NoSuchEntity"
                }
            }
        }

        findings = check_iam(
            inventory
        )

        self.assertEqual(
            findings[0]["rule"],
            "IAM_PASSWORD_POLICY_MISSING"
        )

        self.assertEqual(
            findings[0]["severity"],
            "MEDIUM"
        )


if __name__ == "__main__":
    unittest.main()