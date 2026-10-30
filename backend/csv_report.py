import csv
import os
from datetime import datetime, timezone


def generate_csv_report(findings, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)

    file_path = os.path.join(
        output_dir,
        "cloudsentinel_findings.csv"
    )

    fields = [
        "severity",
        "rule",
        "resource",
        "group_id",
        "group_name",
        "instance_id",
        "port",
        "message",
        "remediation",
    ]

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for finding in findings:
            writer.writerow(
                {
                    "severity": finding.get(
                        "severity",
                        ""
                    ),
                    "rule": finding.get(
                        "rule",
                        ""
                    ),
                    "resource": finding.get(
                        "resource",
                        ""
                    ),
                    "group_id": finding.get(
                        "group_id",
                        ""
                    ),
                    "group_name": finding.get(
                        "group_name",
                        ""
                    ),
                    "instance_id": finding.get(
                        "instance_id",
                        ""
                    ),
                    "port": finding.get(
                        "port",
                        ""
                    ),
                    "message": finding.get(
                        "message",
                        ""
                    ),
                    "remediation": finding.get(
                        "remediation",
                        ""
                    ),
                }
            )

    return file_path