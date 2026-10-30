# CloudSentinel

**CloudSentinel** is a Python-based AWS security posture scanner that
checks selected AWS resources for common misconfigurations, applies
security rules, and uses machine-learning models to help identify
potentially unusual configurations.

It includes a generated HTML dashboard, JSON and CSV reports, and a
local Flask web app for starting scans from the dashboard.

> **Important:** Machine-learning predictions are decision-support
> signals, not proof of a breach or a guarantee that a resource is safe.
> Validate findings against your AWS environment and security
> requirements.

## Features

-   AWS inventory collection for supported resource types, including IAM
    users and security groups.
-   Rule-based checks for selected misconfigurations, such as disabled
    IAM user MFA and a missing account password policy.
-   Isolation Forest anomaly detection to flag configurations that
    differ from learned patterns.
-   Random Forest IAM classification to estimate whether an IAM
    configuration resembles a misconfigured example.
-   HTML dashboard generated from scan results.
-   JSON and CSV reports.
-   Local Flask web interface with a **Run New Scan** button.

## Project Structure

``` text
CloudSentinel/
├── backend/
│   ├── run_scan.py
│   ├── web_app.py
│   ├── report_generator.py
│   ├── csv_report.py
│   ├── risk_engine.py
│   ├── collectors/
│   │   ├── aws_inventory.py
│   │   └── iam_inventory.py
│   ├── rules/
│   │   └── security_rules.py
│   └── ai/
│       ├── anomaly_model.py
│       ├── iam_model.py
│       ├── security_analyst.py
│       ├── train_anomaly_model.py
│       └── train_iam_model.py
├── config/
├── data/
├── models/
├── reports/
├── tests/
├── requirements.txt
└── README.md
```

The exact files and model artifacts may vary by version.

## Requirements

-   Python compatible with the project's dependencies.
-   AWS credentials configured for the account you intend to scan.
-   An AWS identity with only the permissions required by the collectors
    and security checks.
-   Flask installed in the project's virtual environment for the
    dashboard.

## Installation (Windows CMD)

Open Command Prompt and navigate to the project directory:

``` cmd
cd C:\Users\zaman\CloudSentinel
```

Activate the virtual environment if desired:

``` cmd
venv\Scripts\activate
```

Install project dependencies:

``` cmd
python -m pip install -r requirements.txt
```

Install Flask if it is not already listed in `requirements.txt`:

``` cmd
venv\Scripts\python.exe -m pip install flask
```

## Configure AWS Credentials

Use your organization's approved process or AWS CLI credential
configuration. For example, if the AWS CLI is installed:

``` cmd
aws configure
```

Use a dedicated, least-privilege, read-only identity. Never put access
keys in source code, README files, screenshots, or Git commits. Do not
use root-account credentials for routine scanning.

## Run a Scan

From the project root:

``` cmd
venv\Scripts\python.exe -m backend.run_scan
```

The scanner should print its progress and generate reports in
`reports\`, depending on the current implementation and scan results.
Common report files include:

-   `reports\cloudsentinel_report.html` --- HTML dashboard/report.
-   `reports\cloudsentinel_report.json` --- machine-readable scan
    output.
-   `reports\cloudsentinel_findings.csv` --- tabular findings.

## Run the Web Dashboard

Start the Flask app:

``` cmd
venv\Scripts\python.exe -m backend.web_app
```

Open this address in your browser:

``` text
http://127.0.0.1:5000
```

Keep the terminal open while using the dashboard. The app is configured
for local access. Do not expose it to the public internet without
appropriate authentication, authorization, request protection, and
deployment hardening.

Click **Run New Scan** to launch the scanner from the dashboard. After a
successful scan, the page should reload to show the newly generated
report.

## Understanding the ML Models

### Isolation Forest

Isolation Forest flags observations that appear unusual relative to the
data and features used by the model. An anomaly is not automatically a
security vulnerability; investigate it alongside rule-based findings and
AWS context.

### Random Forest IAM Classifier

The Random Forest classifier estimates whether an IAM configuration
resembles the classes in its training data. A predicted class or
probability is **not** a real-world probability of compromise. Model
quality depends on the training dataset and independent evaluation.

### Rule-Based Findings and Risk Score

Security rules identify specific conditions in scanned resources. The
risk engine combines findings according to the project's scoring logic.
Review individual findings rather than relying only on the overall risk
level.

## Troubleshooting

### Dashboard values do not change

The same values can be legitimate if the same resources and findings are
detected on each scan.

1.  Check report timestamps:

    ``` cmd
    dir reports\cloudsentinel_report.*
    ```

2.  Run another scan and check the timestamps again.

3.  Inspect terminal output and the JSON report for updated results.

4.  If the report timestamp changes but the dashboard does not, refresh
    the page and check that it loads the intended report.

### Flask module not found

Install Flask into the same virtual environment used to run the app:

``` cmd
venv\Scripts\python.exe -m pip install flask
```

### AWS access denied

Verify the credentials, account, region, and required read-only
permissions for the AWS APIs used by the collectors. Avoid granting
broad administrative permissions just to make a scan work.

### No S3 buckets or EC2 instances appear

A zero count may mean no resources were found in the configured
account/region, or that the scanner does not currently collect those
resource types successfully. Check the AWS account, region, API
permissions, and collector implementation.

### ML or report-generation errors

Review the full terminal traceback, confirm dependencies are installed
in the project's virtual environment, and verify that the expected model
files and datasets exist.

## Security and Limitations

-   CloudSentinel is a project scanner, not a substitute for AWS-native
    security services, professional security assessments, or continuous
    production monitoring.
-   Inventory coverage is limited to the resource types implemented in
    the collectors.
-   Findings can include false positives or false negatives; manually
    verify important results.
-   Unrepresentative or synthetic training data can produce misleading
    predictions.
-   Keep AWS credentials out of the repository and generated reports.
-   Keep the Flask dashboard local unless it is properly secured for
    wider deployment.
-   Review and test remediation actions before applying changes to any
    AWS account.

## Future Improvements

-   Expand and test AWS resource coverage, including EC2 and S3.
-   Add automated tests for collectors, security rules, scoring, and
    reports.
-   Compare consecutive scans and highlight new or resolved findings.
-   Evaluate models with representative, independently held-out data.
-   Add authentication and authorization before shared or remote
    deployment.
-   Improve structured logging and scan status/error reporting.

## License

Add the license and attribution terms applicable to this project before
publishing or distributing it.
