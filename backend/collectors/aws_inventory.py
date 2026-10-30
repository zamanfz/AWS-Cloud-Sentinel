import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AWSInventoryCollector:
    def __init__(self, profile_name="default", region="ap-south-1"):
        self.profile_name = profile_name
        self.region = region

        self.session = boto3.Session(
            profile_name=profile_name,
            region_name=region,
        )

    def get_account_identity(self):
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()
        except (BotoCoreError, ClientError) as exc:
            return {"error": str(exc)}

    def get_s3_buckets(self):
        try:
            s3 = self.session.client("s3")
            response = s3.list_buckets()

            buckets = []

            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]

                bucket_info = {
                    "name": bucket_name,
                    "creation_date": str(bucket.get("CreationDate")),
                    "public_access_block": {},
                    "policy_public": False,
                    "acl_public": False,
                    "versioning": "Unknown",
                    "encryption": "Unknown",
                }

                try:
                    pab = s3.get_public_access_block(
                        Bucket=bucket_name
                    )
                    bucket_info["public_access_block"] = pab.get(
                        "PublicAccessBlockConfiguration",
                        {}
                    )
                except ClientError:
                    bucket_info["public_access_block"] = {}

                try:
                    policy_status = s3.get_bucket_policy_status(
                        Bucket=bucket_name
                    )
                    bucket_info["policy_public"] = (
                        policy_status
                        .get("PolicyStatus", {})
                        .get("IsPublic", False)
                    )
                except ClientError:
                    bucket_info["policy_public"] = False

                try:
                    acl = s3.get_bucket_acl(
                        Bucket=bucket_name
                    )

                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})

                        if grantee.get("URI") in [
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        ]:
                            bucket_info["acl_public"] = True

                except ClientError:
                    bucket_info["acl_public"] = False

                try:
                    versioning = s3.get_bucket_versioning(
                        Bucket=bucket_name
                    )
                    bucket_info["versioning"] = versioning.get(
                        "Status",
                        "Disabled"
                    )
                except ClientError:
                    bucket_info["versioning"] = "Unknown"

                try:
                    encryption = s3.get_bucket_encryption(
                        Bucket=bucket_name
                    )

                    rules = (
                        encryption
                        .get(
                            "ServerSideEncryptionConfiguration",
                            {}
                        )
                        .get("Rules", [])
                    )

                    bucket_info["encryption"] = (
                        "Enabled" if rules else "NotConfigured"
                    )

                except ClientError:
                    bucket_info["encryption"] = "NotConfigured"

                buckets.append(bucket_info)

            return buckets

        except (BotoCoreError, ClientError) as exc:
            return {"error": str(exc)}

    def get_ec2_instances(self):
        try:
            ec2 = self.session.client("ec2")
            response = ec2.describe_instances()

            instances = []

            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    volumes = []

                    for mapping in instance.get(
                        "BlockDeviceMappings",
                        []
                    ):
                        ebs = mapping.get("Ebs")

                        if not ebs:
                            continue

                        volume_id = ebs.get("VolumeId")

                        if not volume_id:
                            continue

                        encrypted = False

                        try:
                            volume_response = ec2.describe_volumes(
                                VolumeIds=[volume_id]
                            )

                            volume_data = volume_response.get(
                                "Volumes",
                                []
                            )

                            if volume_data:
                                encrypted = volume_data[0].get(
                                    "Encrypted",
                                    False
                                )

                        except ClientError:
                            encrypted = False

                        volumes.append(
                            {
                                "volume_id": volume_id,
                                "encrypted": encrypted,
                                "device": mapping.get(
                                    "Device"
                                ),
                            }
                        )

                    security_groups = [
                        {
                            "group_id": group.get("GroupId"),
                            "group_name": group.get("GroupName"),
                        }
                        for group in instance.get(
                            "SecurityGroups",
                            []
                        )
                    ]

                    metadata_options = instance.get(
                        "MetadataOptions",
                        {}
                    )

                    instances.append(
                        {
                            "instance_id": instance.get(
                                "InstanceId"
                            ),
                            "state": instance.get(
                                "State",
                                {}
                            ).get("Name"),
                            "instance_type": instance.get(
                                "InstanceType"
                            ),
                            "availability_zone": instance.get(
                                "Placement",
                                {}
                            ).get("AvailabilityZone"),
                            "public_ip": instance.get(
                                "PublicIpAddress"
                            ),
                            "private_ip": instance.get(
                                "PrivateIpAddress"
                            ),
                            "security_groups": security_groups,
                            "metadata_http_tokens": metadata_options.get(
                                "HttpTokens"
                            ),
                            "metadata_http_endpoint": metadata_options.get(
                                "HttpEndpoint"
                            ),
                            "volumes": volumes,
                        }
                    )

            return instances

        except (BotoCoreError, ClientError) as exc:
            return {"error": str(exc)}

    def get_security_groups(self):
        try:
            ec2 = self.session.client("ec2")
            response = ec2.describe_security_groups()

            groups = []

            for group in response.get("SecurityGroups", []):
                groups.append(
                    {
                        "group_id": group.get("GroupId"),
                        "group_name": group.get("GroupName"),
                        "description": group.get("Description"),
                        "vpc_id": group.get("VpcId"),
                        "ingress_rules": group.get(
                            "IpPermissions",
                            []
                        ),
                        "egress_rules": group.get(
                            "IpPermissionsEgress",
                            []
                        ),
                    }
                )

            return groups

        except (BotoCoreError, ClientError) as exc:
            return {"error": str(exc)}

    def collect(self):
        return {
            "account": self.get_account_identity(),
            "s3_buckets": self.get_s3_buckets(),
            "ec2_instances": self.get_ec2_instances(),
            "security_groups": self.get_security_groups(),
        }


if __name__ == "__main__":
    collector = AWSInventoryCollector()
    inventory = collector.collect()

    from pprint import pprint

    pprint(inventory)