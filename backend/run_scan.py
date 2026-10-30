from backend.ai.iam_model import IAMRandomForest
from backend.ai.anomaly_model import (
    CloudSentinelAnomalyModel,
    analyze_inventory,
    get_model_summary,
)
from datetime import datetime, timezone
import traceback

from backend.collectors.aws_inventory import AWSInventoryCollector
from backend.collectors.iam_inventory import IAMInventoryCollector
from backend.rules.security_rules import (
    check_security_groups,
    check_s3_buckets,
    check_ec2_instances,
    check_iam,
)
from backend.risk_engine import (
    calculate_risk,
    get_severity_summary,
)
from backend.report_generator import (
    generate_json_report,
    generate_html_report,
)
from backend.csv_report import (
    generate_csv_report,
)
from backend.ai.security_analyst import SecurityAnalyst


SCANNER_VERSION = "1.0.0"


def main():
    aws_collector = AWSInventoryCollector()
    iam_collector = IAMInventoryCollector()
    ai_analyst = SecurityAnalyst()

    inventory = aws_collector.collect()
    iam_inventory = iam_collector.collect()

    inventory["iam"] = iam_inventory

    iam_model = IAMRandomForest()

    try:
        iam_model.load()

        iam_client = iam_collector.iam

        iam_ml_results = []

        for user in iam_inventory.get("users", []):
            result = iam_model.predict(
    user,
    password_policy=iam_inventory.get("password_policy", {}),
    iam=iam_client,
)

            iam_ml_results.append(
                {
                    "resource": user.get(
                        "username",
                        "Unknown"
                    ),
                    "model": result,
                }
            )

        inventory["iam_ml"] = {
            "enabled": True,
            "algorithm": "Random Forest",
            "dataset": "AWS IAM Policy Configuration Profiles Dataset",
            "results": iam_ml_results,
        }

    except Exception as exc:
        iam_ml_results = []

        inventory["iam_ml"] = {
            "enabled": False,
            "algorithm": "Random Forest",
            "error": str(exc),
            "results": [],
        }

        print(f"DEBUG: IAM ML classification failed: {exc}")
        traceback.print_exc()

    ml_model = CloudSentinelAnomalyModel()

    ml_results = analyze_inventory(
        inventory,
        ml_model
    )

    ml_summary = get_model_summary(
        ml_results
    )

    inventory["ml_anomaly_detection"] = {
        "algorithm": ml_summary["algorithm"],
        "resources_analyzed": ml_summary["resources_analyzed"],
        "anomalies_detected": ml_summary["anomalies_detected"],
        "model_status": ml_summary["model_status"],
        "results": ml_results,
    }

    account = inventory.get(
        "account",
        {}
    )

    scan_metadata = {
        "scanner_name": "CloudSentinel",
        "scanner_version": SCANNER_VERSION,
        "scan_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "aws_account_id": account.get(
            "Account",
            "Unknown"
        ),
        "aws_region": aws_collector.region,
    }

    inventory["scan_metadata"] = scan_metadata

    security_group_findings = check_security_groups(
        inventory
    )

    s3_findings = check_s3_buckets(
        inventory
    )

    ec2_findings = check_ec2_instances(
        inventory
    )

    iam_findings = check_iam(
        inventory
    )

    findings = (
        security_group_findings
        + s3_findings
        + ec2_findings
        + iam_findings
    )

    for finding in findings:
        finding_resource = str(
            finding.get("resource", "")
        )

        for ml_result in ml_results:
            ml_resource = str(
                ml_result.get("resource", "")
            )

            if finding_resource == ml_resource:
                model_result = ml_result.get(
                    "model",
                    {}
                )

                finding["ml_prediction"] = (
                    "ANOMALY"
                    if model_result.get(
                        "is_anomaly",
                        False
                    )
                    else "NORMAL"
                )

                finding["ml_anomaly_score"] = (
                    model_result.get(
                        "anomaly_score"
                    )
                )

                finding["ml_risk"] = (
                    model_result.get(
                        "risk"
                    )
                )

                finding["ml_decision_score"] = (
                    model_result.get(
                        "decision_score"
                    )
                )

                break

    risk = calculate_risk(
        findings
    )

    severity_summary = get_severity_summary(
        findings
    )

    s3_buckets = inventory.get(
        "s3_buckets",
        []
    )

    security_groups = inventory.get(
        "security_groups",
        []
    )

    ec2_instances = inventory.get(
        "ec2_instances",
        []
    )

    iam_users = iam_inventory.get(
        "users",
        []
    )

    s3_count = (
        len(s3_buckets)
        if isinstance(s3_buckets, list)
        else 0
    )

    security_group_count = (
        len(security_groups)
        if isinstance(security_groups, list)
        else 0
    )

    ec2_count = (
        len(ec2_instances)
        if isinstance(ec2_instances, list)
        else 0
    )

    iam_count = (
        len(iam_users)
        if isinstance(iam_users, list)
        else 0
    )

    inventory_summary = {
        "s3_buckets": s3_count,
        "ec2_instances": ec2_count,
        "security_groups": security_group_count,
        "iam_users": iam_count,
    }

    ai_enabled = ai_analyst.is_available()

    ai_executive_summary = None
    ai_prioritization = None

    if ai_enabled and findings:
        enriched_findings = ai_analyst.enrich_findings(
            findings
        )

        findings = enriched_findings

        ai_prioritization = ai_analyst.prioritize_findings(
            findings
        )

        ai_executive_summary = (
            ai_analyst.generate_executive_summary(
                findings,
                risk,
                severity_summary,
                inventory_summary,
            )
        )

    inventory["ai"] = {
        "enabled": ai_enabled,
        "executive_summary": (
            ai_executive_summary
            if isinstance(ai_executive_summary, str)
            else None
        ),
        "prioritization": (
            ai_prioritization
            if isinstance(ai_prioritization, str)
            else None
        ),
    }

    report_file = generate_json_report(
        inventory,
        findings,
        risk,
        severity_summary
    )

    html_report_file = generate_html_report(
        inventory,
        findings,
        risk,
        severity_summary
    )

    csv_report_file = generate_csv_report(
        findings
    )

    print("\n=== ML Anomaly Detection ===")

    print(
        f"Algorithm: "
        f"{ml_summary['algorithm']}"
    )

    print(
        f"Resources analyzed: "
        f"{ml_summary['resources_analyzed']}"
    )

    print(
        f"Anomalies detected: "
        f"{ml_summary['anomalies_detected']}"
    )

    for result in ml_results:
        model_result = result["model"]

        print("\n--- ML Result ---")

        print(
            f"Resource Type: "
            f"{result['resource_type']}"
        )

        print(
            f"Resource: "
            f"{result['resource']}"
        )

        print(
            f"Prediction: "
            f"{'ANOMALY' if model_result['is_anomaly'] else 'NORMAL'}"
        )

        print(
            f"Anomaly Score: "
            f"{model_result['anomaly_score']}"
        )

        print(
            f"ML Risk: "
            f"{model_result['risk']}"
        )

        print(
            f"Decision Score: "
            f"{model_result['decision_score']}"
        )

        print("\n=== IAM ML Classification ===")

    if iam_ml_results:
        print("Algorithm: Random Forest")

        for result in iam_ml_results:
            model = result["model"]

            print(
                f"\nIAM User: "
                f"{result['resource']}"
            )

            print(
                f"Prediction: "
                f"{model['status']}"
            )

            print(
                f"Misconfiguration Probability: "
                f"{model['misconfiguration_probability']}%"
            )
    else:
        iam_ml_error = inventory.get("iam_ml", {}).get(
            "error",
            "Unknown error. Check the traceback printed above.",
        )
        print(f"IAM ML classification unavailable: {iam_ml_error}")
        
    print("\n=== CloudSentinel Scan ===")

    print(
        f"Scanner Version: {SCANNER_VERSION}"
    )

    print(
        f"AWS Account: "
        f"{scan_metadata['aws_account_id']}"
    )

    print(
        f"AWS Region: "
        f"{scan_metadata['aws_region']}"
    )

    print(
        f"Scan Time: "
        f"{scan_metadata['scan_timestamp']}"
    )

    print(
        f"S3 buckets checked: {s3_count}"
    )

    print(
        f"EC2 instances checked: {ec2_count}"
    )

    print(
        f"Security groups checked: "
        f"{security_group_count}"
    )

    print(
        f"IAM users checked: {iam_count}"
    )

    print(
        f"Findings: {len(findings)}"
    )

    print(
        f"Risk Score: {risk['score']}"
    )

    print(
        f"Risk Level: {risk['risk_level']}"
    )

    print(
        f"AI Security Analyst: "
        f"{'Enabled' if ai_enabled else 'Disabled'}"
    )

    print("\n=== Severity Summary ===")

    print(
        f"Critical: "
        f"{severity_summary['CRITICAL']}"
    )

    print(
        f"High: "
        f"{severity_summary['HIGH']}"
    )

    print(
        f"Medium: "
        f"{severity_summary['MEDIUM']}"
    )

    print(
        f"Low: "
        f"{severity_summary['LOW']}"
    )

    for finding in findings:
        print("\n--- Finding ---")

        print(
            f"Severity: "
            f"{finding['severity']}"
        )

        print(
            f"Rule: "
            f"{finding['rule']}"
        )

        print(
            f"Resource: "
            f"{finding['resource']}"
        )

        print(
            f"Message: "
            f"{finding['message']}"
        )

        print(
            f"Remediation: "
            f"{finding['remediation']}"
        )

        if finding.get("ai_analysis"):
            print(
                "\nAI Analysis:"
            )

            print(
                finding["ai_analysis"]
            )

    if ai_prioritization:
        print(
            "\n=== AI Remediation Prioritization ==="
        )

        print(
            ai_prioritization
        )

    if ai_executive_summary:
        print(
            "\n=== AI Executive Summary ==="
        )

        print(
            ai_executive_summary
        )

    print(
        f"\nJSON Report: {report_file}"
    )

    print(
        f"HTML Report: {html_report_file}"
    )

    print(
        f"CSV Report: {csv_report_file}"
    )


if __name__ == "__main__":
    main()