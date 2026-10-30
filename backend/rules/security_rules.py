def check_security_groups(inventory):
    findings = []

    security_groups = inventory.get(
        "security_groups",
        []
    )

    if isinstance(security_groups, dict):
        return findings

    port_rules = {
        22: {
            "severity": "HIGH",
            "name": "SSH",
            "message": "SSH is exposed to the public internet.",
            "why_it_matters": "Public SSH access increases the risk of unauthorized remote access and brute-force attacks.",
        },
        3389: {
            "severity": "HIGH",
            "name": "RDP",
            "message": "RDP is exposed to the public internet.",
            "why_it_matters": "Public RDP access increases exposure to credential attacks and unauthorized remote access.",
        },
        3306: {
            "severity": "HIGH",
            "name": "MySQL",
            "message": "MySQL is exposed to the public internet.",
            "why_it_matters": "Public database access can expose database services to unauthorized connections and attacks.",
        },
        5432: {
            "severity": "HIGH",
            "name": "PostgreSQL",
            "message": "PostgreSQL is exposed to the public internet.",
            "why_it_matters": "Public database access can expose PostgreSQL services to unauthorized connections and attacks.",
        },
        80: {
            "severity": "MEDIUM",
            "name": "HTTP",
            "message": "HTTP is exposed to the public internet.",
            "why_it_matters": "Public HTTP access is expected for some web applications, but unrestricted exposure should be intentional and protected appropriately.",
        },
        443: {
            "severity": "LOW",
            "name": "HTTPS",
            "message": "HTTPS is exposed to the public internet.",
            "why_it_matters": "Public HTTPS access is common for web applications, but unrestricted exposure should be limited to systems that are intended to be internet-facing.",
        }
    }

    for group in security_groups:
        group_id = group.get("group_id")
        group_name = group.get("group_name")

        for rule in group.get(
            "ingress_rules",
            []
        ):
            protocol = rule.get("IpProtocol")
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            public_access = False

            for ip_range in rule.get(
                "IpRanges",
                []
            ):
                if ip_range.get(
                    "CidrIp"
                ) == "0.0.0.0/0":
                    public_access = True

            if not public_access:
                continue

            if protocol == "-1":
                findings.append(
                    {
                        "severity": "CRITICAL",
                        "rule": "ALL_PORTS_PUBLIC",
                        "resource": group_id,
                        "resource_type": "Security Group",
                        "resource_id": group_id,
                        "category": "Network Security",
                        "group_id": group_id,
                        "group_name": group_name,
                        "message": (
                            f"Security group '{group_name}' "
                            "allows all inbound traffic from "
                            "the public internet."
                        ),
                        "why_it_matters": (
                            "Allowing unrestricted inbound traffic exposes "
                            "all services associated with the security group "
                            "to the public internet."
                        ),
                        "current_configuration": (
                            "Inbound traffic from 0.0.0.0/0 is allowed "
                            "for all protocols and ports."
                        ),
                        "remediation": (
                            "Restrict inbound traffic to required ports "
                            "and trusted IP ranges."
                        )
                    }
                )

                continue

            if (
                isinstance(from_port, int)
                and isinstance(to_port, int)
            ):
                for port, config in port_rules.items():
                    if (
                        from_port <= port
                        and to_port >= port
                    ):
                        findings.append(
                            {
                                "severity": config["severity"],
                                "rule": f"PUBLIC_{config['name'].upper()}",
                                "resource": group_id,
                                "resource_type": "Security Group",
                                "resource_id": group_id,
                                "category": "Network Security",
                                "group_id": group_id,
                                "group_name": group_name,
                                "port": port,
                                "message": (
                                    f"Security group '{group_name}' "
                                    f"allows {config['name']} "
                                    f"port {port} from the public internet. "
                                    f"{config['message']}"
                                ),
                                "why_it_matters": config["why_it_matters"],
                                "current_configuration": (
                                    f"Port {port} is accessible from "
                                    "0.0.0.0/0."
                                ),
                                "remediation": (
                                    f"Restrict port {port} "
                                    "to trusted IP ranges."
                                )
                            }
                        )

    return findings


def check_ec2_instances(inventory):
    findings = []

    instances = inventory.get(
        "ec2_instances",
        []
    )

    if isinstance(instances, dict):
        return findings

    for instance in instances:
        instance_id = instance.get(
            "instance_id",
            "Unknown"
        )

        state = instance.get(
            "state"
        )

        if state == "terminated":
            continue

        public_ip = instance.get(
            "public_ip"
        )

        if public_ip:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule": "EC2_PUBLIC_IP",
                    "resource": instance_id,
                    "resource_type": "EC2 Instance",
                    "resource_id": instance_id,
                    "category": "Network Security",
                    "instance_id": instance_id,
                    "message": (
                        f"EC2 instance '{instance_id}' "
                        f"has a public IPv4 address "
                        f"{public_ip}."
                    ),
                    "why_it_matters": (
                        "A public IPv4 address makes the instance "
                        "directly reachable from the internet and "
                        "increases its network exposure."
                    ),
                    "current_configuration": (
                        f"Public IPv4 address: {public_ip}."
                    ),
                    "remediation": (
                        "Remove unnecessary public IP addresses "
                        "and use private networking where possible."
                    )
                }
            )

        metadata_tokens = instance.get(
            "metadata_http_tokens"
        )

        if metadata_tokens == "optional":
            findings.append(
                {
                    "severity": "HIGH",
                    "rule": "EC2_IMDSV1_ENABLED",
                    "resource": instance_id,
                    "resource_type": "EC2 Instance",
                    "resource_id": instance_id,
                    "category": "Instance Security",
                    "instance_id": instance_id,
                    "message": (
                        f"EC2 instance '{instance_id}' "
                        "allows IMDSv1."
                    ),
                    "why_it_matters": (
                        "IMDSv1 provides weaker protection against "
                        "credential exposure than IMDSv2."
                    ),
                    "current_configuration": (
                        "EC2 metadata HTTP tokens are set to optional, "
                        "allowing IMDSv1."
                    ),
                    "remediation": (
                        "Require IMDSv2 by setting metadata "
                        "HTTP tokens to required."
                    )
                }
            )

        volumes = instance.get(
            "volumes",
            []
        )

        for volume in volumes:
            volume_id = volume.get(
                "volume_id",
                "Unknown"
            )

            encrypted = volume.get(
                "encrypted",
                False
            )

            if not encrypted:
                findings.append(
                    {
                        "severity": "HIGH",
                        "rule": "EC2_EBS_ENCRYPTION_DISABLED",
                        "resource": volume_id,
                        "resource_type": "EBS Volume",
                        "resource_id": volume_id,
                        "category": "Data Protection",
                        "instance_id": instance_id,
                        "message": (
                            f"EBS volume '{volume_id}' "
                            f"attached to instance '{instance_id}' "
                            "is not encrypted."
                        ),
                        "why_it_matters": (
                            "Unencrypted EBS volumes can expose stored "
                            "data if snapshots, volumes, or underlying "
                            "storage are accessed improperly."
                        ),
                        "current_configuration": (
                            f"EBS volume {volume_id} is not encrypted."
                        ),
                        "remediation": (
                            "Use encrypted EBS volumes "
                            "for EC2 workloads."
                        )
                    }
                )

    return findings


def check_s3_buckets(inventory):
    findings = []

    s3_buckets = inventory.get(
        "s3_buckets",
        []
    )

    if isinstance(s3_buckets, dict):
        return findings

    for bucket in s3_buckets:
        bucket_name = bucket.get(
            "name",
            "Unknown"
        )

        if bucket.get(
            "policy_public"
        ) is True:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "rule": "PUBLIC_S3_BUCKET_POLICY",
                    "resource": bucket_name,
                    "resource_type": "S3 Bucket",
                    "resource_id": bucket_name,
                    "category": "Data Protection",
                    "message": (
                        f"S3 bucket '{bucket_name}' "
                        "has a public bucket policy."
                    ),
                    "why_it_matters": (
                        "A public bucket policy can allow unauthorized "
                        "users on the internet to access bucket data."
                    ),
                    "current_configuration": (
                        "The bucket policy is detected as public."
                    ),
                    "remediation": (
                        "Remove unintended public bucket policies "
                        "and enable S3 Block Public Access."
                    )
                }
            )

        if bucket.get(
            "acl_public"
        ) is True:
            findings.append(
                {
                    "severity": "HIGH",
                    "rule": "PUBLIC_S3_BUCKET_ACL",
                    "resource": bucket_name,
                    "resource_type": "S3 Bucket",
                    "resource_id": bucket_name,
                    "category": "Data Protection",
                    "message": (
                        f"S3 bucket '{bucket_name}' "
                        "has a public ACL grant."
                    ),
                    "why_it_matters": (
                        "A public ACL can grant unintended access "
                        "to objects or bucket resources."
                    ),
                    "current_configuration": (
                        "The bucket has an ACL grant to a public "
                        "or authenticated-users group."
                    ),
                    "remediation": (
                        "Remove public ACL grants and enable "
                        "S3 Block Public Access."
                    )
                }
            )

        public_access_block = bucket.get(
            "public_access_block",
            {}
        )

        required_flags = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets"
        ]

        if (
            public_access_block
            and not all(
                public_access_block.get(
                    flag,
                    False
                )
                for flag in required_flags
            )
        ):
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule": "S3_BLOCK_PUBLIC_ACCESS_INCOMPLETE",
                    "resource": bucket_name,
                    "resource_type": "S3 Bucket",
                    "resource_id": bucket_name,
                    "category": "Data Protection",
                    "message": (
                        f"S3 bucket '{bucket_name}' "
                        "does not have all Block Public Access "
                        "protections enabled."
                    ),
                    "why_it_matters": (
                        "Incomplete Block Public Access settings "
                        "can allow public access configurations "
                        "to be introduced unintentionally."
                    ),
                    "current_configuration": (
                        f"Block Public Access configuration: "
                        f"{public_access_block}."
                    ),
                    "remediation": (
                        "Enable all four S3 Block Public Access "
                        "settings unless a documented exception exists."
                    )
                }
            )

        if bucket.get(
            "versioning"
        ) == "Disabled":
            findings.append(
                {
                    "severity": "LOW",
                    "rule": "S3_VERSIONING_DISABLED",
                    "resource": bucket_name,
                    "resource_type": "S3 Bucket",
                    "resource_id": bucket_name,
                    "category": "Data Protection",
                    "message": (
                        f"S3 bucket '{bucket_name}' "
                        "does not have versioning enabled."
                    ),
                    "why_it_matters": (
                        "Without versioning, accidental deletion or "
                        "overwriting of objects is harder to recover from."
                    ),
                    "current_configuration": (
                        "S3 bucket versioning is disabled."
                    ),
                    "remediation": (
                        "Enable S3 versioning for recovery from "
                        "accidental deletion or overwrites."
                    )
                }
            )

    return findings


def check_iam(inventory):
    findings = []

    iam = inventory.get(
        "iam",
        {}
    )

    if not iam:
        return findings

    users = iam.get(
        "users",
        []
    )

    if isinstance(users, dict):
        return findings

    for user in users:
        username = user.get(
            "username",
            "Unknown"
        )

        if not user.get(
            "mfa_enabled",
            False
        ):
            findings.append(
                {
                    "severity": "HIGH",
                    "rule": "IAM_USER_MFA_DISABLED",
                    "resource": username,
                    "resource_type": "IAM User",
                    "resource_id": username,
                    "category": "Identity & Access",
                    "message": (
                        f"IAM user '{username}' "
                        "does not have MFA enabled."
                    ),
                    "why_it_matters": (
                        "MFA provides an additional authentication "
                        "factor and reduces the risk of unauthorized "
                        "access if credentials are compromised."
                    ),
                    "current_configuration": (
                        "MFA is not enabled for this IAM user."
                    ),
                    "remediation": (
                        "Enable MFA for the IAM user."
                    )
                }
            )

        for access_key in user.get(
            "access_keys",
            []
        ):
            status = access_key.get(
                "status"
            )

            age_days = access_key.get(
                "age_days"
            )

            access_key_id = access_key.get(
                "access_key_id",
                "Unknown"
            )

            if (
                status == "Active"
                and isinstance(
                    age_days,
                    int
                )
                and age_days >= 90
            ):
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "rule": "IAM_OLD_ACCESS_KEY",
                        "resource": username,
                        "resource_type": "IAM Access Key",
                        "resource_id": access_key_id,
                        "category": "Identity & Access",
                        "message": (
                            f"IAM user '{username}' "
                            f"has an active access key "
                            f"that is {age_days} days old."
                        ),
                        "why_it_matters": (
                            "Long-lived access keys increase the "
                            "window of exposure if credentials are "
                            "leaked or compromised."
                        ),
                        "current_configuration": (
                            f"Access key {access_key_id} is active "
                            f"and {age_days} days old."
                        ),
                        "remediation": (
                            "Rotate old access keys and use "
                            "temporary credentials where possible."
                        )
                    }
                )

            if status == "Inactive":
                findings.append(
                    {
                        "severity": "LOW",
                        "rule": "IAM_INACTIVE_ACCESS_KEY",
                        "resource": username,
                        "resource_type": "IAM Access Key",
                        "resource_id": access_key_id,
                        "category": "Identity & Access",
                        "message": (
                            f"IAM user '{username}' "
                            "has an inactive access key."
                        ),
                        "why_it_matters": (
                            "Unused credentials increase credential "
                            "management overhead and may remain "
                            "available if later reactivated."
                        ),
                        "current_configuration": (
                            f"Access key {access_key_id} is inactive."
                        ),
                        "remediation": (
                            "Delete unused access keys "
                            "after confirming they are no longer required."
                        )
                    }
                )

    account_summary = iam.get(
        "account_summary",
        {}
    )

    if not isinstance(
        account_summary,
        dict
    ):
        account_summary = {}

    if account_summary.get(
        "AccountMFAEnabled"
    ) == 0:
        findings.append(
            {
                "severity": "CRITICAL",
                "rule": "ROOT_MFA_DISABLED",
                "resource": "AWS Account",
                "resource_type": "AWS Account",
                "resource_id": "AWS Account",
                "category": "Identity & Access",
                "message": (
                    "The AWS account does not have "
                    "root-account MFA enabled."
                ),
                "why_it_matters": (
                    "The root account has highly privileged access, "
                    "so protecting it with MFA reduces the risk of "
                    "unauthorized administrative access."
                ),
                "current_configuration": (
                    "Root-account MFA is not enabled."
                ),
                "remediation": (
                    "Enable MFA for the AWS root account."
                )
            }
        )

    password_policy = iam.get(
        "password_policy",
        {}
    )

    if (
        isinstance(
            password_policy,
            dict
        )
        and password_policy.get(
            "error"
        )
    ):
        error = password_policy.get(
            "error",
            ""
        )

        if "NoSuchEntity" in error:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "rule": "IAM_PASSWORD_POLICY_MISSING",
                    "resource": "AWS Account",
                    "resource_type": "IAM Account",
                    "resource_id": "AWS Account",
                    "category": "Identity & Access",
                    "message": (
                        "No custom IAM account password "
                        "policy is configured."
                    ),
                    "why_it_matters": (
                        "Without an explicit password policy, "
                        "password requirements are not centrally "
                        "defined for IAM users."
                    ),
                    "current_configuration": (
                        "No custom IAM account password policy "
                        "is configured."
                    ),
                    "remediation": (
                        "Configure an IAM password policy "
                        "with appropriate complexity and rotation "
                        "requirements."
                    )
                }
            )

    return findings