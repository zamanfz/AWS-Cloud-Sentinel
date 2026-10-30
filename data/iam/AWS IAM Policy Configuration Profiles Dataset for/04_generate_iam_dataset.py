"""
Synthetic IAM policy misconfiguration dataset generator.

Produces AWS-style IAM configuration profiles for ML-based cloud
misconfiguration detection. Each profile contains:
  - a realistic IAM policy document (AWS JSON format)
  - surrounding IAM entity / account context
  - a binary label (0 = compliant, 1 = misconfigured)
  - the specific vulnerability tags present (multi-label, useful for analysis)

Outputs:
  - iam_dataset.json      full nested records (human-readable, keeps raw policy)
  - iam_dataset.csv       flattened ML-ready features + label
  - dataset_summary.json  class balance and vulnerability distribution

Standard library only. Deterministic via --seed.
"""

import json
import csv
import random
import uuid
import argparse
from datetime import datetime, timedelta

# --------------------------------------------------------------------------
# Building blocks: realistic AWS service actions grouped by risk
# --------------------------------------------------------------------------

READ_ACTIONS = {
    "s3":  ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
    "ec2": ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSecurityGroups"],
    "dynamodb": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
    "logs": ["logs:GetLogEvents", "logs:DescribeLogGroups"],
    "lambda": ["lambda:GetFunction", "lambda:ListFunctions"],
    "rds": ["rds:DescribeDBInstances", "rds:DescribeDBClusters"],
}

WRITE_ACTIONS = {
    "s3":  ["s3:PutObject", "s3:DeleteObject"],
    "ec2": ["ec2:StartInstances", "ec2:StopInstances", "ec2:CreateTags"],
    "dynamodb": ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
    "lambda": ["lambda:InvokeFunction", "lambda:UpdateFunctionCode"],
    "rds": ["rds:ModifyDBInstance"],
}

# Actions commonly abused for privilege escalation
PRIV_ESC_ACTIONS = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
]

SERVICES = list(READ_ACTIONS.keys())
DEPARTMENTS = ["data", "web", "billing", "ops", "ml", "security", "analytics"]
ENVIRONMENTS = ["prod", "staging", "dev", "sandbox"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
ENTITY_TYPES = ["role", "user"]

# Vulnerability tags we can inject
VULN_TAGS = [
    "wildcard_action",          # Action: "*"
    "wildcard_resource",        # Resource: "*" on sensitive actions
    "full_admin",               # Allow *:* — effectively administrator
    "public_principal",         # Principal: "*" with no condition (public access)
    "passrole_wildcard",        # iam:PassRole on Resource "*"
    "privilege_escalation",     # dangerous iam:* write actions granted
    "no_mfa_on_privileged",     # privileged actions without MFA condition
    "missing_encryption",       # allows PutObject without enforcing encryption
    "no_condition_constraints", # broad access, zero conditions
    "cross_account_no_externalid",  # trust policy without ExternalId
    "notaction_allow",          # Allow + NotAction (implicit over-permission)
]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def rand_arn(service, dept, env):
    acct = "".join(random.choice("0123456789") for _ in range(12))
    if service == "s3":
        return f"arn:aws:s3:::{dept}-{env}-bucket/*"
    if service == "dynamodb":
        return f"arn:aws:dynamodb:{random.choice(REGIONS)}:{acct}:table/{dept}_{env}"
    if service == "lambda":
        return f"arn:aws:lambda:{random.choice(REGIONS)}:{acct}:function:{dept}-{env}-fn"
    if service == "rds":
        return f"arn:aws:rds:{random.choice(REGIONS)}:{acct}:db:{dept}-{env}-db"
    if service == "logs":
        return f"arn:aws:logs:{random.choice(REGIONS)}:{acct}:log-group:/{dept}/{env}"
    return f"arn:aws:ec2:{random.choice(REGIONS)}:{acct}:instance/*"


def account_context(env):
    """Surrounding IAM entity/account config that a scanner would also see."""
    return {
        "AccountId": "".join(random.choice("0123456789") for _ in range(12)),
        "Environment": env,
        "MFAEnabled": random.random() > 0.15,
        "AccessKeyAgeDays": random.randint(1, 400),
        "LastUsedDays": random.randint(0, 180),
        "PolicyType": random.choice(["managed", "inline"]),
    }


# --------------------------------------------------------------------------
# Compliant policy generation
# --------------------------------------------------------------------------

def make_compliant(dept, env):
    """A least-privilege, well-scoped policy. label = 0."""
    statements = []
    services = random.sample(SERVICES, random.randint(1, 3))

    for svc in services:
        actions = list(READ_ACTIONS[svc])
        if random.random() > 0.4:
            actions += WRITE_ACTIONS.get(svc, [])
        resource = rand_arn(svc, dept, env)

        stmt = {
            "Sid": f"Allow{svc.capitalize()}{random.randint(100,999)}",
            "Effect": "Allow",
            "Action": sorted(set(actions)),
            "Resource": resource,
        }

        conditions = {}
        # Enforce encryption on S3 writes
        if svc == "s3" and any("Put" in a for a in actions):
            conditions["StringEquals"] = {"s3:x-amz-server-side-encryption": "AES256"}
        # Restrict to corporate IP range on some prod policies
        if env == "prod" and random.random() > 0.5:
            conditions.setdefault("IpAddress", {})["aws:SourceIp"] = "203.0.113.0/24"
        # Require MFA for write-capable prod access
        if env == "prod" and any(("Put" in a or "Delete" in a or "Modify" in a) for a in actions):
            conditions["Bool"] = {"aws:MultiFactorAuthPresent": "true"}
        if conditions:
            stmt["Condition"] = conditions

        statements.append(stmt)

    # Occasionally add an explicit deny as defense-in-depth (good practice)
    if random.random() > 0.6:
        statements.append({
            "Sid": "DenyUnlessSecureTransport",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        })

    policy = {"Version": "2012-10-17", "Statement": statements}
    return policy, []


# --------------------------------------------------------------------------
# Misconfigured policy generation
# --------------------------------------------------------------------------

def make_misconfigured(dept, env):
    """Start from a plausible policy, then inject 1-3 vulnerabilities. label = 1."""
    policy, _ = make_compliant(dept, env)
    stmts = policy["Statement"]
    applied = []

    n_vulns = random.choices([1, 2, 3], weights=[0.5, 0.35, 0.15])[0]
    chosen = random.sample(VULN_TAGS, n_vulns)

    for tag in chosen:
        if tag == "full_admin":
            stmts.append({
                "Sid": "AdminAccess",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            })
            applied += ["full_admin", "wildcard_action", "wildcard_resource"]

        elif tag == "wildcard_action":
            svc = random.choice(SERVICES)
            stmts.append({
                "Sid": f"Wide{svc.capitalize()}",
                "Effect": "Allow",
                "Action": f"{svc}:*",
                "Resource": rand_arn(svc, dept, env),
            })
            applied.append("wildcard_action")

        elif tag == "wildcard_resource":
            target = random.choice(stmts)
            target["Resource"] = "*"
            applied.append("wildcard_resource")

        elif tag == "public_principal":
            stmts.append({
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{dept}-{env}-bucket/*",
            })
            applied.append("public_principal")

        elif tag == "passrole_wildcard":
            stmts.append({
                "Sid": "PassAnyRole",
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": "*",
            })
            applied += ["passrole_wildcard", "wildcard_resource"]

        elif tag == "privilege_escalation":
            actions = random.sample(PRIV_ESC_ACTIONS, random.randint(2, 4))
            stmts.append({
                "Sid": "IamManage",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            })
            applied += ["privilege_escalation", "wildcard_resource"]

        elif tag == "no_mfa_on_privileged":
            stmts.append({
                "Sid": "DeleteNoMFA",
                "Effect": "Allow",
                "Action": ["s3:DeleteObject", "dynamodb:DeleteItem"],
                "Resource": rand_arn("s3", dept, env),
            })
            applied.append("no_mfa_on_privileged")

        elif tag == "missing_encryption":
            stmts.append({
                "Sid": "PutNoEncryption",
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{dept}-{env}-bucket/*",
                # note: deliberately NO server-side-encryption condition
            })
            applied.append("missing_encryption")

        elif tag == "no_condition_constraints":
            # strip all conditions from existing statements
            for s in stmts:
                s.pop("Condition", None)
            applied.append("no_condition_constraints")

        elif tag == "cross_account_no_externalid":
            ext_acct = "".join(random.choice("0123456789") for _ in range(12))
            stmts.append({
                "Sid": "TrustExternalAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ext_acct}:root"},
                "Action": "sts:AssumeRole",
                "Resource": "*",
                # note: no Condition with sts:ExternalId
            })
            applied += ["cross_account_no_externalid", "wildcard_resource"]

        elif tag == "notaction_allow":
            stmt = {
                "Sid": "AllowAllExceptIam",
                "Effect": "Allow",
                "NotAction": ["iam:*"],
                "Resource": "*",
            }
            stmts.append(stmt)
            applied += ["notaction_allow", "wildcard_resource"]

    policy["Statement"] = stmts
    return policy, sorted(set(applied))


# --------------------------------------------------------------------------
# Feature extraction (what an ML model would train on)
# --------------------------------------------------------------------------

def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def extract_features(policy, ctx):
    stmts = policy.get("Statement", [])
    f = {
        "num_statements": len(stmts),
        "num_allow": 0,
        "num_deny": 0,
        "has_wildcard_action": 0,
        "has_wildcard_resource": 0,
        "has_full_admin": 0,
        "has_public_principal": 0,
        "has_passrole_wildcard": 0,
        "priv_esc_action_count": 0,
        "has_mfa_condition": 0,
        "has_ip_condition": 0,
        "has_encryption_condition": 0,
        "num_conditions": 0,
        "uses_notaction": 0,
        "total_action_count": 0,
        "cross_account_trust": 0,
    }

    for s in stmts:
        effect = s.get("Effect", "Allow")
        if effect == "Allow":
            f["num_allow"] += 1
        else:
            f["num_deny"] += 1

        actions = _as_list(s.get("Action"))
        f["total_action_count"] += len(actions)

        if "NotAction" in s:
            f["uses_notaction"] = 1

        resources = _as_list(s.get("Resource"))
        if "*" in actions or any(a.endswith(":*") for a in actions):
            f["has_wildcard_action"] = 1
        if "*" in resources:
            f["has_wildcard_resource"] = 1
        if "*" in actions and "*" in resources and effect == "Allow":
            f["has_full_admin"] = 1

        principal = s.get("Principal")
        if principal == "*":
            f["has_public_principal"] = 1
        if isinstance(principal, dict) and "AWS" in principal:
            f["cross_account_trust"] = 1

        if "iam:PassRole" in actions and "*" in resources:
            f["has_passrole_wildcard"] = 1

        f["priv_esc_action_count"] += sum(1 for a in actions if a in PRIV_ESC_ACTIONS)

        cond = s.get("Condition", {})
        if cond:
            f["num_conditions"] += 1
            blob = json.dumps(cond).lower()
            if "multifactorauthpresent" in blob:
                f["has_mfa_condition"] = 1
            if "sourceip" in blob:
                f["has_ip_condition"] = 1
            if "server-side-encryption" in blob:
                f["has_encryption_condition"] = 1

    # a few context features
    f["mfa_enabled"] = int(ctx["MFAEnabled"])
    f["access_key_age_days"] = ctx["AccessKeyAgeDays"]
    f["is_prod"] = int(ctx["Environment"] == "prod")
    return f


# --------------------------------------------------------------------------
# Record assembly
# --------------------------------------------------------------------------

def build_record(label):
    dept = random.choice(DEPARTMENTS)
    env = random.choice(ENVIRONMENTS)
    entity_type = random.choice(ENTITY_TYPES)
    ctx = account_context(env)

    if label == 0:
        policy, vulns = make_compliant(dept, env)
    else:
        policy, vulns = make_misconfigured(dept, env)

    created = datetime(2024, 1, 1) + timedelta(days=random.randint(0, 540))

    record = {
        "profile_id": str(uuid.uuid4()),
        "entity_name": f"{dept}-{env}-{entity_type}-{random.randint(1000,9999)}",
        "entity_type": entity_type,
        "policy_name": f"{dept}-{env}-policy",
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "context": ctx,
        "policy_document": policy,
        "label": label,                      # 0 = compliant, 1 = misconfigured
        "label_text": "compliant" if label == 0 else "misconfigured",
        "vulnerabilities": vulns,            # multi-label detail
    }
    return record


def generate(n, seed, compliant_ratio=0.5):
    random.seed(seed)
    n_compliant = round(n * compliant_ratio)
    labels = [0] * n_compliant + [1] * (n - n_compliant)
    random.shuffle(labels)
    records = [build_record(l) for l in labels]
    random.shuffle(records)
    return records


# --------------------------------------------------------------------------
# Output writers
# --------------------------------------------------------------------------

def write_json(records, path):
    with open(path, "w") as fh:
        json.dump(records, fh, indent=2)


def write_csv(records, path):
    rows = []
    for r in records:
        feats = extract_features(r["policy_document"], r["context"])
        row = {
            "profile_id": r["profile_id"],
            "entity_name": r["entity_name"],
            "entity_type": r["entity_type"],
            "environment": r["context"]["Environment"],
            **feats,
            "vulnerabilities": "|".join(r["vulnerabilities"]),
            "label": r["label"],
        }
        rows.append(row)

    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return rows


def write_summary(records, rows, path):
    from collections import Counter
    label_counts = Counter(r["label"] for r in records)
    vuln_counts = Counter()
    for r in records:
        for v in r["vulnerabilities"]:
            vuln_counts[v] += 1
    summary = {
        "total_records": len(records),
        "compliant": label_counts[0],
        "misconfigured": label_counts[1],
        "vulnerability_distribution": dict(vuln_counts.most_common()),
        "feature_columns": [k for k in rows[0].keys()
                            if k not in ("profile_id", "entity_name", "vulnerabilities")],
    }
    with open(path, "w") as fh:
        json.dump(summary, fh, indent=2)
    return summary


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--compliant-ratio", type=float, default=0.5,
                    help="Fraction of records labeled compliant (e.g. 0.7)")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    records = generate(args.n, args.seed, args.compliant_ratio)
    write_json(records, f"{args.outdir}/iam_dataset.json")
    rows = write_csv(records, f"{args.outdir}/iam_dataset.csv")
    summary = write_summary(records, rows, f"{args.outdir}/dataset_summary.json")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
