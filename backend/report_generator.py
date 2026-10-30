import json

import os
import re

from datetime import datetime, timezone

from html import escape





REPORT_DIR = "reports"

HISTORY_FILE = os.path.join(

    REPORT_DIR,

    "cloudsentinel_scan_history.json"

)

MAX_HISTORY = 20





def get_scan_metadata(inventory):

    metadata = inventory.get(

        "scan_metadata",

        {}

    )



    if not isinstance(metadata, dict):

        metadata = {}



    return metadata





def update_scan_history(

    inventory,

    findings,

    risk,

    severity_summary

):

    os.makedirs(

        REPORT_DIR,

        exist_ok=True

    )



    metadata = get_scan_metadata(

        inventory

    )



    timestamp = metadata.get(

        "scan_timestamp"

    )



    if not timestamp:

        timestamp = datetime.now(

            timezone.utc

        ).isoformat()



    entry = {

        "scan_timestamp": timestamp,

        "aws_account_id": metadata.get(

            "aws_account_id",

            "Unknown"

        ),

        "aws_region": metadata.get(

            "aws_region",

            "Unknown"

        ),

        "scanner_version": metadata.get(

            "scanner_version",

            "Unknown"

        ),

        "risk_score": risk.get(

            "score",

            0

        ),

        "risk_level": risk.get(

            "risk_level",

            "UNKNOWN"

        ),

        "finding_count": len(

            findings

        ),

        "severity_summary": severity_summary,

    }



    history = []



    if os.path.exists(

        HISTORY_FILE

    ):

        try:

            with open(

                HISTORY_FILE,

                "r",

                encoding="utf-8"

            ) as file:

                history = json.load(file)



            if not isinstance(

                history,

                list

            ):

                history = []



        except (

            json.JSONDecodeError,

            OSError

        ):

            history = []



    for existing in history:

        if existing.get(

            "scan_timestamp"

        ) == timestamp:

            return history



    history.insert(

        0,

        entry

    )



    history = history[

        :MAX_HISTORY

    ]



    with open(

        HISTORY_FILE,

        "w",

        encoding="utf-8"

    ) as file:

        json.dump(

            history,

            file,

            indent=4,

            default=str

        )



    return history





def load_scan_history():

    if not os.path.exists(

        HISTORY_FILE

    ):

        return []



    try:

        with open(

            HISTORY_FILE,

            "r",

            encoding="utf-8"

        ) as file:

            history = json.load(file)



        if isinstance(

            history,

            list

        ):

            return history



    except (

        json.JSONDecodeError,

        OSError

    ):

        pass



    return []





def generate_json_report(

    inventory,

    findings,

    risk,

    severity_summary

):

    os.makedirs(

        REPORT_DIR,

        exist_ok=True

    )



    metadata = get_scan_metadata(

        inventory

    )



    update_scan_history(

        inventory,

        findings,

        risk,

        severity_summary

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



    iam = inventory.get(

        "iam",

        {}

    )



    if not isinstance(

        iam,

        dict

    ):

        iam = {}



    iam_users = iam.get(

        "users",

        []

    )



    report = {

        "scanner": "CloudSentinel",

        "scanner_version": metadata.get(

            "scanner_version",

            "Unknown"

        ),

        "scan_metadata": metadata,

        "scan_time": metadata.get(

            "scan_timestamp",

            datetime.now(

                timezone.utc

            ).isoformat()

        ),

        "risk": risk,

        "severity_summary": severity_summary,

        "inventory_summary": {

            "s3_buckets": (

                len(s3_buckets)

                if isinstance(

                    s3_buckets,

                    list

                )

                else 0

            ),

            "security_groups": (

                len(security_groups)

                if isinstance(

                    security_groups,

                    list

                )

                else 0

            ),

            "iam_users": (

                len(iam_users)

                if isinstance(

                    iam_users,

                    list

                )

                else 0

            ),

            "ec2_instances": (

                len(ec2_instances)

                if isinstance(

                    ec2_instances,

                    list

                )

                else 0

            ),

        },

        "findings": findings,

        "ai": inventory.get(
            "ai",
            {}
        ),

        "iam_ml": inventory.get("iam_ml", {}),

    }



    filename = os.path.join(

        REPORT_DIR,

        "cloudsentinel_report.json"

    )



    with open(

        filename,

        "w",

        encoding="utf-8"

    ) as file:

        json.dump(

            report,

            file,

            indent=4,

            default=str

        )



    return filename





def format_scan_time(timestamp):

    if not timestamp:

        return "Unknown"



    try:

        parsed = datetime.fromisoformat(

            str(timestamp).replace(

                "Z",

                "+00:00"

            )

        )



        return parsed.strftime(

            "%Y-%m-%d %H:%M:%S"

        )



    except (

        ValueError,

        TypeError

    ):

        return str(timestamp)





def render_ai_markdown(text):
    if not text:
        return ""

    lines = str(text).replace("\r\n", "\n").split("\n")
    output = []
    in_list = False

    def inline(value):
        value = escape(str(value))
        value = re.sub(r"`([^`]+)`", r"<code>\1</code>", value)
        value = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", value)
        value = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", value)
        return value

    def close_list():
        nonlocal in_list
        if in_list:
            output.append("</ul>")
            in_list = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            close_list()
            continue
        if line.startswith("### "):
            close_list()
            output.append(f"<h4>{inline(line[4:])}</h4>")
        elif line.startswith("## "):
            close_list()
            output.append(f"<h3>{inline(line[3:])}</h3>")
        elif line.startswith("# "):
            close_list()
            output.append(f"<h3>{inline(line[2:])}</h3>")
        elif re.match(r"^\d+\.\s+", line):
            close_list()
            number, content = line.split(".", 1)
            output.append(f'<div class="ai-priority-card"><div class="ai-priority-number">{escape(number)}</div><div class="ai-priority-content">{inline(content.strip())}</div></div>')
        elif line.startswith("- ") or line.startswith("* "):
            if not in_list:
                output.append("<ul>")
                in_list = True
            output.append(f"<li>{inline(line[2:].strip())}</li>")
        else:
            close_list()
            output.append(f"<p>{inline(line)}</p>")

    close_list()
    return "\n".join(output)


def generate_findings_html(findings):

    html = ""



    for index, finding in enumerate(

        findings,

        start=1

    ):

        severity = finding.get(

            "severity",

            "LOW"

        )



        rule = finding.get(

            "rule",

            "Unknown"

        )



        resource = finding.get(

            "resource",

            "Unknown"

        )



        resource_type = finding.get(

            "resource_type",

            "Unknown"

        )



        resource_id = finding.get(

            "resource_id",

            resource

        )



        category = finding.get(

            "category",

            "Security"

        )



        message = finding.get(

            "message",

            ""

        )



        why_it_matters = finding.get(

            "why_it_matters",

            "No impact explanation available."

        )



        current_configuration = finding.get(

            "current_configuration",

            "No configuration details available."

        )



        remediation = finding.get(

            "remediation",

            "No remediation guidance available."

        )



        group_id = finding.get(

            "group_id"

        )



        group_name = finding.get(

            "group_name"

        )



        instance_id = finding.get(

            "instance_id"

        )



        port = finding.get(

            "port"

        )



        extra_details = ""



        if group_id:

            extra_details += f"""

            <div class="detail-item">

                <span>Security Group ID</span>

                <strong>{escape(str(group_id))}</strong>

            </div>

            """



        if group_name:

            extra_details += f"""

            <div class="detail-item">

                <span>Security Group Name</span>

                <strong>{escape(str(group_name))}</strong>

            </div>

            """



        if instance_id:

            extra_details += f"""

            <div class="detail-item">

                <span>Instance ID</span>

                <strong>{escape(str(instance_id))}</strong>

            </div>

            """



        if port is not None:

            extra_details += f"""

            <div class="detail-item">

                <span>Port</span>

                <strong>{escape(str(port))}</strong>

            </div>

            """



        if not extra_details:

            extra_details = """

            <div class="detail-item">

                <span>Additional Resource Metadata</span>

                <strong>None</strong>

            </div>

            """



        severity_class = escape(

            str(severity).lower()

        )



        html += f"""

        <tr data-severity="{escape(str(severity))}">

            <td>

                <span class="badge {severity_class}">

                    {escape(str(severity))}

                </span>

            </td>



            <td>

                <strong>{escape(str(rule))}</strong>

            </td>



            <td>

                {escape(str(resource))}

            </td>



            <td>

                {escape(str(message))}

            </td>



            <td>

                <button

                    class="details-button"

                    onclick="showFinding({index})">

                    View Details

                </button>

            </td>

        </tr>



        <tr

            id="finding-details-{index}"

            class="finding-detail-row"

            style="display:none;"

            data-severity="{escape(str(severity))}">



            <td colspan="5">



                <div class="finding-detail-panel">



                    <div class="finding-detail-header">



                        <div>

                            <span class="badge {severity_class}">

                                {escape(str(severity))}

                            </span>



                            <span class="finding-number">

                                Finding #{index}

                            </span>

                        </div>



                        <button

                            class="details-button"

                            onclick="hideFinding({index})">

                            Close

                        </button>



                    </div>



                    <h2>

                        {escape(str(rule))}

                    </h2>



                    <div class="detail-grid">



                        <div class="detail-card">

                            <div class="detail-label">

                                RESOURCE

                            </div>



                            <div class="detail-value">

                                {escape(str(resource))}

                            </div>

                        </div>



                        <div class="detail-card">

                            <div class="detail-label">

                                RESOURCE TYPE

                            </div>



                            <div class="detail-value">

                                {escape(str(resource_type))}

                            </div>

                        </div>



                        <div class="detail-card">

                            <div class="detail-label">

                                RESOURCE ID

                            </div>



                            <div class="detail-value">

                                {escape(str(resource_id))}

                            </div>

                        </div>



                        <div class="detail-card">

                            <div class="detail-label">

                                CATEGORY

                            </div>



                            <div class="detail-value">

                                {escape(str(category))}

                            </div>

                        </div>



                    </div>



                    <div class="detail-section">

                        <div class="detail-label">

                            DESCRIPTION

                        </div>



                        <div class="detail-text">

                            {escape(str(message))}

                        </div>

                    </div>



                    <div class="detail-section">

                        <div class="detail-label">

                            WHY IT MATTERS

                        </div>



                        <div class="detail-text">

                            {escape(str(why_it_matters))}

                        </div>

                    </div>



                    <div class="detail-section">

                        <div class="detail-label">

                            CURRENT CONFIGURATION

                        </div>



                        <div class="detail-text">

                            {escape(str(current_configuration))}

                        </div>

                    </div>



                    <div class="detail-section">

                        <div class="detail-label">

                            RESOURCE DETAILS

                        </div>



                        <div class="detail-grid">

                            {extra_details}

                        </div>

                    </div>



                    <div class="detail-section">

                        <div class="detail-label">

                            RECOMMENDED REMEDIATION

                        </div>



                        <div class="remediation-box">

                            {escape(str(remediation))}

                        </div>

                    </div>



                </div>



            </td>

        </tr>

        """



    if not html:

        html = """

        <tr>

            <td colspan="5" class="empty">

                No security findings detected.

            </td>

        </tr>

        """



    return html





def generate_history_html(history):

    if not history:

        return """

        <tr>

            <td colspan="4" class="empty">

                No scan history available.

            </td>

        </tr>

        """



    html = ""



    for entry in history:

        timestamp = format_scan_time(

            entry.get(

                "scan_timestamp"

            )

        )



        risk_level = entry.get(

            "risk_level",

            "UNKNOWN"

        )



        risk_score = entry.get(

            "risk_score",

            0

        )



        finding_count = entry.get(

            "finding_count",

            0

        )



        risk_class = escape(

            str(risk_level).lower()

        )



        html += f"""

        <tr>

            <td>

                {escape(timestamp)}

            </td>



            <td>

                <span class="badge {risk_class}">

                    {escape(str(risk_level))}

                </span>

            </td>



            <td>

                {escape(str(risk_score))}

            </td>



            <td>

                {escape(str(finding_count))}

            </td>

        </tr>

        """



    return html





def generate_trend_data(history):

    data = []



    for entry in reversed(

        history

    ):

        data.append(

            {

                "timestamp": format_scan_time(

                    entry.get(

                        "scan_timestamp"

                    )

                ),

                "score": entry.get(

                    "risk_score",

                    0

                ),

                "findings": entry.get(

                    "finding_count",

                    0

                ),

            }

        )



    return data





def generate_html_report(

    inventory,

    findings,

    risk,

    severity_summary

):

    os.makedirs(

        REPORT_DIR,

        exist_ok=True

    )



    metadata = get_scan_metadata(

        inventory

    )



    history = update_scan_history(

        inventory,

        findings,

        risk,

        severity_summary

    )



    scan_time = format_scan_time(

        metadata.get(

            "scan_timestamp"

        )

    )



    account_id = metadata.get(

        "aws_account_id",

        "Unknown"

    )



    region = metadata.get(

        "aws_region",

        "Unknown"

    )



    scanner_version = metadata.get(

        "scanner_version",

        "Unknown"

    )


    ai_data = inventory.get(
        "ai",
        {}
    )

    if not isinstance(ai_data, dict):
        ai_data = {}

    ai_enabled = bool(
        ai_data.get("enabled", False)
    )

    ai_executive_html = render_ai_markdown(
        ai_data.get("executive_summary")
    )

    ai_prioritization_html = render_ai_markdown(
        ai_data.get("prioritization")
    )

    
    iam_ml_data = inventory.get("iam_ml", {})

    if not isinstance(iam_ml_data, dict):
        iam_ml_data = {}

    iam_ml_results = iam_ml_data.get("results", [])

    if not isinstance(iam_ml_results, list):
        iam_ml_results = []

    iam_ml_rows = ""

    for item in iam_ml_results:
        model_result = item.get("model", {})
        status = str(model_result.get("status", "Unavailable"))
        probability = model_result.get("misconfiguration_probability")
        resource = escape(str(item.get("resource", "Unknown")))
        resource_type = escape(str(item.get("resource_type", "IAM_USER")))
        status_class = (
            "high"
            if status == "MISCONFIGURED"
            else "low"
            if status == "NORMAL"
            else "medium"
        )

        probability_text = (
            f"{probability:.2f}%"
            if isinstance(probability, (int, float))
            else "Unavailable"
        )

        iam_ml_rows += f"""
        <tr>
            <td>{resource}</td>
            <td>{resource_type}</td>
            <td><span class="badge {status_class}">{escape(status)}</span></td>
            <td>{escape(probability_text)}</td>
        </tr>
        """

    if not iam_ml_rows:
        iam_ml_rows = """
        <tr>
            <td colspan="4" class="empty">
                No IAM ML predictions available. Run a scan with the trained model.
            </td>
        </tr>
        """





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



    iam = inventory.get(

        "iam",

        {}

    )



    if not isinstance(

        iam,

        dict

    ):

        iam = {}



    iam_users = iam.get(

        "users",

        []

    )



    s3_count = (

        len(s3_buckets)

        if isinstance(

            s3_buckets,

            list

        )

        else 0

    )



    security_group_count = (

        len(security_groups)

        if isinstance(

            security_groups,

            list

        )

        else 0

    )



    ec2_count = (

        len(ec2_instances)

        if isinstance(

            ec2_instances,

            list

        )

        else 0

    )



    iam_count = (

        len(iam_users)

        if isinstance(

            iam_users,

            list

        )

        else 0

    )



    risk_level = risk.get(

        "risk_level",

        "UNKNOWN"

    )



    risk_score = risk.get(

        "score",

        0

    )



    critical_count = severity_summary.get(

        "CRITICAL",

        0

    )



    high_count = severity_summary.get(

        "HIGH",

        0

    )



    medium_count = severity_summary.get(

        "MEDIUM",

        0

    )



    low_count = severity_summary.get(

        "LOW",

        0

    )



    findings_html = generate_findings_html(

        findings

    )



    history_html = generate_history_html(

        history

    )



    trend_data = generate_trend_data(

        history

    )



    trend_json = json.dumps(

        trend_data

    )



    css = """

    * {

        box-sizing: border-box;

    }



    body {

        margin: 0;

        font-family: Inter, Segoe UI, Arial, sans-serif;

        background: #070b14;

        color: #e5e7eb;

    }



    .layout {

        display: flex;

        min-height: 100vh;

    }



    .sidebar {

        width: 240px;

        background: #0b1120;

        border-right: 1px solid #1e293b;

        padding: 25px 18px;

        position: fixed;

        top: 0;

        bottom: 0;

        left: 0;

        overflow-y: auto;

    }



    .logo {

        font-size: 23px;

        font-weight: 700;

        color: #f8fafc;

        margin-bottom: 40px;

    }



    .logo span {

        color: #38bdf8;

    }



    .nav-title {

        color: #64748b;

        font-size: 11px;

        text-transform: uppercase;

        letter-spacing: 1px;

        margin: 20px 12px 10px;

    }



    .nav-item {

        display: block;

        padding: 11px 12px;

        margin: 4px 0;

        border-radius: 7px;

        color: #94a3b8;

        text-decoration: none;

        font-size: 14px;

    }



    .nav-item.active {

        background: #172033;

        color: #f8fafc;

    }



    .nav-item:hover {

        background: #172033;

        color: #ffffff;

    }



    .main {

        margin-left: 240px;

        width: calc(100% - 240px);

    }



    .topbar {

        height: 76px;

        background: #0b1120;

        border-bottom: 1px solid #1e293b;

        display: flex;

        align-items: center;

        justify-content: space-between;

        padding: 0 35px;

        position: sticky;

        top: 0;

        z-index: 10;

    }



    .topbar-title {

        font-size: 18px;

        font-weight: 600;

        color: #f8fafc;

    }



    .status {

        display: flex;

        align-items: center;

        gap: 9px;

        color: #94a3b8;

        font-size: 13px;

    }



    .status-dot {

        width: 9px;

        height: 9px;

        background: #22c55e;

        border-radius: 50%;

        display: inline-block;

    }



    .content {

        padding: 32px 38px 50px;

    }



    .page-header {

        display: flex;

        justify-content: space-between;

        align-items: center;

        margin-bottom: 25px;

    }



    .page-header h1 {

        margin: 0 0 7px;

        font-size: 26px;

        color: #f8fafc;

    }



    .page-header p {

        margin: 0;

        color: #64748b;

        font-size: 13px;

    }



    .button {

        display: inline-block;

        text-decoration: none;

        padding: 10px 16px;

        border: 1px solid #334155;

        border-radius: 7px;

        color: #93c5fd;

        background: #0f172a;

        font-size: 13px;

    }



    .button:hover {

        background: #172033;

    }



    .cards {

        display: grid;

        grid-template-columns: repeat(4, 1fr);

        gap: 16px;

        margin-bottom: 18px;

    }



    .card {

        background: #0f172a;

        border: 1px solid #1e293b;

        border-radius: 10px;

        padding: 22px;

    }



    .card-label {

        color: #64748b;

        font-size: 11px;

        text-transform: uppercase;

        letter-spacing: 1px;

        margin-bottom: 12px;

    }



    .card-value {

        font-size: 28px;

        font-weight: 700;

        color: #f8fafc;

    }



    .risk-value {

        color: #fbbf24;

    }



    .card-sub {

        margin-top: 7px;

        color: #64748b;

        font-size: 12px;

    }



    .panel {

        background: #0f172a;

        border: 1px solid #1e293b;

        border-radius: 10px;

        padding: 23px;

        margin-bottom: 20px;

    }



    .panel h2 {

        margin: 0 0 20px;

        color: #f8fafc;

        font-size: 17px;

    }



    .inventory {

        display: grid;

        grid-template-columns: repeat(4, 1fr);

        gap: 14px;

    }



    .inventory-item {

        background: #111a2d;

        border: 1px solid #24324a;

        border-radius: 8px;

        padding: 18px;

    }



    .inventory-label {

        color: #64748b;

        font-size: 12px;

        margin-bottom: 10px;

    }



    .inventory-value {

        color: #f8fafc;

        font-size: 24px;

        font-weight: 700;

    }



    .overview-grid {

        display: grid;

        grid-template-columns: 1fr 2fr;

        gap: 20px;

    }



    .severity-list {

        display: flex;

        flex-direction: column;

        gap: 13px;

    }



    .severity-row {

        display: flex;

        justify-content: space-between;

        align-items: center;

        padding: 12px 14px;

        background: #111a2d;

        border-radius: 7px;

    }



    .severity-name {

        color: #cbd5e1;

        font-size: 13px;

    }



    .severity-count {

        color: #f8fafc;

        font-weight: 700;

    }



    .chart-container {

        position: relative;

        width: 100%;

        height: 280px;

    }



    #riskTrend {

        width: 100%;

        height: 100%;

        display: block;

    }



    .controls {

        display: flex;

        justify-content: flex-end;

        gap: 10px;

        margin-bottom: 18px;

    }



    .search {

        width: 250px;

        padding: 10px 12px;

        border: 1px solid #334155;

        background: #0b1120;

        color: #e2e8f0;

        border-radius: 7px;

        outline: none;

    }



    .search:focus {

        border-color: #3b82f6;

    }



    .select {

        padding: 10px 12px;

        border: 1px solid #334155;

        background: #0b1120;

        color: #e2e8f0;

        border-radius: 7px;

        outline: none;

    }



    .table-wrapper {

        overflow-x: auto;

    }



    table {

        width: 100%;

        border-collapse: collapse;

    }



    th {

        text-align: left;

        padding: 12px 14px;

        color: #64748b;

        font-size: 11px;

        text-transform: uppercase;

        letter-spacing: 1px;

        border-bottom: 1px solid #1e293b;

    }



    td {

        padding: 16px 14px;

        color: #cbd5e1;

        font-size: 13px;

        border-bottom: 1px solid #172033;

        vertical-align: top;

    }



    tr:hover {

        background: #0b1425;

    }



    td strong {

        color: #dbeafe;

    }



    .badge {

        display: inline-block;

        padding: 5px 9px;

        border-radius: 5px;

        font-size: 11px;

        font-weight: 700;

    }



    .badge.critical {

        background: #451a1a;

        color: #fca5a5;

    }



    .badge.high {

        background: #431407;

        color: #fdba74;

    }



    .badge.medium {

        background: #422006;

        color: #fde68a;

    }



    .badge.low {

        background: #052e16;

        color: #86efac;

    }



    .details-button {

        border: 1px solid #334155;

        background: transparent;

        color: #93c5fd;

        padding: 8px 13px;

        border-radius: 7px;

        cursor: pointer;

        font-size: 13px;

        white-space: nowrap;

    }



    .details-button:hover {

        background: #172033;

    }



    .finding-detail-row td {

        padding: 0;

    }



    .finding-detail-panel {

        margin: 12px 0 20px;

        padding: 26px;

        background: #0b1120;

        border: 1px solid #24324a;

        border-radius: 12px;

    }



    .finding-detail-header {

        display: flex;

        align-items: center;

        justify-content: space-between;

        margin-bottom: 18px;

    }



    .finding-number {

        margin-left: 10px;

        color: #64748b;

        font-size: 14px;

    }



    .finding-detail-panel h2 {

        margin: 0 0 22px;

        color: #f8fafc;

        font-size: 24px;

    }



    .detail-grid {

        display: grid;

        grid-template-columns: repeat(2, minmax(0, 1fr));

        gap: 14px;

    }



    .detail-card {

        padding: 18px;

        background: #111a2d;

        border: 1px solid #24324a;

        border-radius: 9px;

    }



    .detail-label {

        color: #64748b;

        font-size: 11px;

        letter-spacing: 1px;

        margin-bottom: 9px;

    }



    .detail-value {

        color: #f8fafc;

        font-size: 15px;

        font-weight: 600;

        word-break: break-word;

    }



    .detail-section {

        margin-top: 22px;

    }



    .detail-text {

        color: #cbd5e1;

        line-height: 1.7;

        font-size: 14px;

    }



    .detail-item {

        padding: 14px;

        background: #111a2d;

        border: 1px solid #24324a;

        border-radius: 8px;

    }



    .detail-item span {

        display: block;

        color: #64748b;

        font-size: 11px;

        margin-bottom: 7px;

    }



    .detail-item strong {

        color: #e2e8f0;

        font-size: 14px;

        word-break: break-word;

    }



    .remediation-box {

        padding: 16px;

        background: #111f38;

        border-left: 3px solid #3b82f6;

        border-radius: 7px;

        color: #dbeafe;

        line-height: 1.6;

    }



    .empty {

        text-align: center;

        padding: 40px;

        color: #64748b;

    }



    .footer {

        text-align: center;

        padding: 25px;

        color: #475569;

        font-size: 12px;

    }



    .metadata-grid {

        display: grid;

        grid-template-columns: repeat(4, 1fr);

        gap: 14px;

    }



    .metadata-item {

        padding: 16px;

        background: #111a2d;

        border: 1px solid #24324a;

        border-radius: 8px;

    }



    .metadata-label {

        color: #64748b;

        font-size: 10px;

        text-transform: uppercase;

        letter-spacing: 1px;

        margin-bottom: 8px;

    }



    .metadata-value {

        color: #e2e8f0;

        font-size: 13px;

        word-break: break-word;

    }



    
.ai-panel {
    padding: 26px;
    overflow: hidden;
    border: 1px solid #263650;
    background: #0d1526;
}
.ai-header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding-bottom:22px;margin-bottom:24px;border-bottom:1px solid #24324a}
.ai-header h2{margin:3px 0 5px;font-size:19px;letter-spacing:-.2px}
.ai-eyebrow{color:#818cf8;font-size:10px;font-weight:700;letter-spacing:1.4px}
.ai-subtitle{margin:0;color:#64748b;font-size:12px}
.ai-status-card{display:inline-flex;align-items:center;gap:8px;flex-shrink:0;padding:8px 12px;border:1px solid #263650;border-radius:999px;background:#111a2d;color:#cbd5e1;font-size:12px;font-weight:600}
.ai-status-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.12)}
.ai-status-dot.off{background:#64748b;box-shadow:none}
.ai-section{margin-top:24px}.ai-section:first-of-type{margin-top:0}
.ai-section-heading{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.ai-section-icon{width:30px;height:30px;display:flex;align-items:center;justify-content:center;border:1px solid #334155;border-radius:8px;background:#111a2d;color:#818cf8;font-size:10px;font-weight:800}
.ai-section-heading h3{margin:0;color:#f8fafc;font-size:14px;font-weight:700}.ai-section-heading span{display:block;margin-top:3px;color:#64748b;font-size:11px}
.ai-summary-card{padding:22px 24px;border:1px solid #263650;border-radius:10px;background:#0b1220}
.ai-prose{color:#cbd5e1;font-size:13px;line-height:1.6;overflow-wrap:anywhere}.ai-prose h3{margin:0 0 8px;padding-top:2px;color:#f8fafc;font-size:14px;line-height:1.4}.ai-prose h3:not(:first-child){margin-top:22px;padding-top:16px;border-top:1px solid #1e293b}.ai-prose h4{margin:16px 0 7px;color:#e2e8f0;font-size:13px}.ai-prose p{margin:0 0 10px}.ai-prose ul{margin:6px 0 10px;padding-left:19px}.ai-prose li{margin:5px 0;padding-left:3px}.ai-prose strong{color:#f8fafc;font-weight:650}.ai-prose code{padding:2px 5px;border:1px solid #263650;border-radius:4px;background:#111a2d;color:#93c5fd;font-family:Consolas,"Courier New",monospace;font-size:11px}
.ai-priority-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.ai-priority-card{display:grid;grid-template-columns:32px 1fr;gap:12px;min-width:0;padding:16px;border:1px solid #263650;border-radius:10px;background:#0b1220}.ai-priority-number{width:28px;height:28px;display:flex;align-items:center;justify-content:center;border-radius:7px;background:#172033;color:#93c5fd;font-size:11px;font-weight:800}.ai-priority-content{min-width:0;color:#cbd5e1;font-size:12px;line-height:1.55;overflow-wrap:anywhere}.ai-priority-content strong{color:#f8fafc}.ai-priority-content code{padding:2px 5px;border-radius:4px;background:#111a2d;color:#93c5fd;font-family:Consolas,"Courier New",monospace;font-size:10px}
@media(max-width:1000px){.ai-priority-list{grid-template-columns:1fr}}@media(max-width:750px){.ai-header{align-items:flex-start;flex-direction:column}.ai-panel{padding:20px}.ai-summary-card{padding:17px}}

@media (max-width: 1100px) {

        .cards {

            grid-template-columns: repeat(2, 1fr);

        }



        .inventory {

            grid-template-columns: repeat(2, 1fr);

        }



        .overview-grid {

            grid-template-columns: 1fr;

        }



        .metadata-grid {

            grid-template-columns: repeat(2, 1fr);

        }

    }



    @media (max-width: 750px) {

        .sidebar {

            display: none;

        }



        .main {

            margin-left: 0;

            width: 100%;

        }



        .cards {

            grid-template-columns: 1fr;

        }



        .inventory {

            grid-template-columns: 1fr;

        }



        .content {

            padding: 20px;

        }



        .topbar {

            padding: 0 20px;

        }



        .page-header {

            align-items: flex-start;

            gap: 15px;

            flex-direction: column;

        }



        .controls {

            flex-direction: column;

        }



        .search {

            width: 100%;

        }



        .detail-grid {

            grid-template-columns: 1fr;

        }



        .metadata-grid {

            grid-template-columns: 1fr;

        }

    }

    """



    javascript = """

    function filterFindings() {

        const searchElement =

            document.getElementById("search");



        const severityElement =

            document.getElementById("severityFilter");



        const search =

            searchElement.value.toLowerCase();



        const severity =

            severityElement.value;



        const rows =

            document.querySelectorAll(

                "#findingsTable tr"

            );



        rows.forEach(function(row) {

            const text =

                row.innerText.toLowerCase();



            const rowSeverity =

                row.getAttribute(

                    "data-severity"

                );



            const matchesSearch =

                text.includes(search);



            const matchesSeverity =

                severity === "ALL" ||

                rowSeverity === severity;



            if (

                matchesSearch &&

                matchesSeverity

            ) {

                row.style.display = "";

            } else {

                row.style.display = "none";

            }

        });

    }



    function showFinding(index) {

        const row =

            document.getElementById(

                "finding-details-" + index

            );



        if (row) {

            row.style.display = "table-row";



            setTimeout(function() {

                row.scrollIntoView({

                    behavior: "smooth",

                    block: "center"

                });

            }, 50);

        }

    }



    function hideFinding(index) {

        const row =

            document.getElementById(

                "finding-details-" + index

            );



        if (row) {

            row.style.display = "none";

        }

    }



    function drawRiskTrend() {

        const canvas =

            document.getElementById(

                "riskTrend"

            );



        if (!canvas) {

            return;

        }



        const container =

            canvas.parentElement;



        const width =

            container.clientWidth;



        const height =

            container.clientHeight;



        const ratio =

            window.devicePixelRatio || 1;



        canvas.width =

            width * ratio;



        canvas.height =

            height * ratio;



        canvas.style.width =

            width + "px";



        canvas.style.height =

            height + "px";



        const ctx =

            canvas.getContext("2d");



        ctx.scale(

            ratio,

            ratio

        );



        const data =

            TREND_DATA;



        ctx.clearRect(

            0,

            0,

            width,

            height

        );



        if (!data.length) {

            ctx.fillStyle =

                "#64748b";



            ctx.font =

                "14px Segoe UI";



            ctx.fillText(

                "No scan history available",

                20,

                30

            );



            return;

        }



        const paddingLeft = 48;

        const paddingRight = 20;

        const paddingTop = 20;

        const paddingBottom = 45;



        const chartWidth =

            width -

            paddingLeft -

            paddingRight;



        const chartHeight =

            height -

            paddingTop -

            paddingBottom;



        const scores =

            data.map(function(item) {

                return Number(

                    item.score || 0

                );

            });



        const maxScore =

            Math.max(

                20,

                Math.max.apply(

                    null,

                    scores

                )

            );



        ctx.strokeStyle =

            "#1e293b";



        ctx.lineWidth = 1;



        for (

            let i = 0;

            i <= 4;

            i++

        ) {

            const y =

                paddingTop +

                (

                    chartHeight *

                    i /

                    4

                );



            ctx.beginPath();



            ctx.moveTo(

                paddingLeft,

                y

            );



            ctx.lineTo(

                width - paddingRight,

                y

            );



            ctx.stroke();



            const value =

                Math.round(

                    maxScore -

                    (

                        maxScore *

                        i /

                        4

                    )

                );



            ctx.fillStyle =

                "#64748b";



            ctx.font =

                "11px Segoe UI";



            ctx.fillText(

                String(value),

                8,

                y + 4

            );

        }



        const points =

            data.map(

                function(item, index) {

                    const x =

                        data.length === 1

                        ? paddingLeft +

                          chartWidth / 2

                        : paddingLeft +

                          (

                            chartWidth *

                            index /

                            (

                                data.length -

                                1

                            )

                          );



                    const score =

                        Number(

                            item.score || 0

                        );



                    const y =

                        paddingTop +

                        chartHeight -

                        (

                            score /

                            maxScore *

                            chartHeight

                        );



                    return {

                        x: x,

                        y: y,

                        score: score

                    };

                }

            );



        ctx.strokeStyle =

            "#38bdf8";



        ctx.lineWidth = 2;



        ctx.beginPath();



        points.forEach(

            function(point, index) {

                if (index === 0) {

                    ctx.moveTo(

                        point.x,

                        point.y

                    );

                } else {

                    ctx.lineTo(

                        point.x,

                        point.y

                    );

                }

            }

        );



        ctx.stroke();



        points.forEach(

            function(point, index) {

                ctx.fillStyle =

                    "#38bdf8";



                ctx.beginPath();



                ctx.arc(

                    point.x,

                    point.y,

                    4,

                    0,

                    Math.PI * 2

                );



                ctx.fill();



                ctx.fillStyle =

                    "#cbd5e1";



                ctx.font =

                    "11px Segoe UI";



                ctx.textAlign =

                    "center";



                ctx.fillText(

                    String(point.score),

                    point.x,

                    point.y - 10

                );



                if (

                    data.length <= 8 ||

                    index === 0 ||

                    index === data.length - 1

                ) {

                    ctx.fillStyle =

                        "#64748b";



                    ctx.fillText(

                        data[index].timestamp,

                        point.x,

                        height - 12

                    );

                }

            }

        );



        ctx.textAlign = "left";

    }



    window.addEventListener(

        "resize",

        drawRiskTrend

    );



    document.addEventListener(

        "DOMContentLoaded",

        drawRiskTrend

    );

    """



    html = f"""

<!DOCTYPE html>

<html lang="en">



<head>



<meta charset="UTF-8">



<meta

    name="viewport"

    content="width=device-width, initial-scale=1.0">



<title>

    CloudSentinel Security Dashboard

</title>



<style>

{css}

</style>



</head>



<body>



<div class="layout">



<aside class="sidebar">



    <div class="logo">

        Cloud<span>Sentinel</span>

    </div>



    <div class="nav-title">

        Security

    </div>



    <a

        class="nav-item active"

        href="#">

        Dashboard

    </a>



    <a

        class="nav-item"

        href="#findings">

        Findings

    </a>


    <a
        class="nav-item"
        href="#ai">

        AI Security Analyst

    </a>



    <a

        class="nav-item"

        href="#inventory">

        AWS Inventory

    </a>



    <a

        class="nav-item"

        href="#scan-info">

        Scan Information

    </a>



    <a

        class="nav-item"

        href="#history">

        Scan History

    </a>



    <div class="nav-title">

        Reports

    </div>



    <a

        class="nav-item"

        href="cloudsentinel_report.json"

        target="_blank">

        JSON Report

    </a>



    <a

        class="nav-item"

        href="cloudsentinel_findings.csv"

        target="_blank">

        CSV Report

    </a>



</aside>



<main class="main">



<header class="topbar">



    <div class="topbar-title">

        Security Dashboard

    </div>



    <div class="status">

        <span class="status-dot"></span>

        Scanner Active

    </div>



</header>



<div class="content">



<div class="page-header">



    <div>



        <h1>

            Security Overview

        </h1>



        <p>

            AWS misconfiguration assessment

            · Last scan {escape(scan_time)}

        </p>



    </div>



    <a

        class="button"

        href="cloudsentinel_report.json"

        target="_blank">

        View JSON

    </a>



</div>



<div class="cards">



    <div class="card">



        <div class="card-label">

            Risk Level

        </div>



        <div class="card-value risk-value">

            {escape(str(risk_level))}

        </div>



        <div class="card-sub">

            Current security posture

        </div>



    </div>



    <div class="card">



        <div class="card-label">

            Risk Score

        </div>



        <div class="card-value">

            {escape(str(risk_score))}

        </div>



        <div class="card-sub">

            Calculated from findings

        </div>



    </div>



    <div class="card">



        <div class="card-label">

            Findings

        </div>



        <div class="card-value">

            {len(findings)}

        </div>



        <div class="card-sub">

            Detected issues

        </div>



    </div>



    <div class="card">



        <div class="card-label">

            IAM Users

        </div>



        <div class="card-value">

            {iam_count}

        </div>



        <div class="card-sub">

            Users assessed

        </div>



    </div>



</div>



<div
    class="panel ai-panel"
    id="ai">

    <div class="ai-header">
        <div>
            <div class="ai-eyebrow">INTELLIGENT SECURITY REVIEW</div>
            <h2>AI Security Analyst</h2>
            <p class="ai-subtitle">AI-assisted interpretation of the latest CloudSentinel scan</p>
        </div>
        <div class="ai-status-card">
            <span class="ai-status-dot{"" if ai_enabled else " off"}"></span>
            <span>{"Enabled" if ai_enabled else "Disabled"}</span>
        </div>
    </div>

    <div class="ai-section">
        <div class="ai-section-heading">
            <div class="ai-section-icon">01</div>
            <div><h3>Executive Security Summary</h3><span>What the scan means at a glance</span></div>
        </div>
        <div class="ai-summary-card">
            {ai_executive_html if ai_executive_html else "<p>No AI executive summary is available.</p>"}
        </div>
    </div>

    {"<div class=\"ai-section\"><div class=\"ai-section-heading\"><div class=\"ai-section-icon\">02</div><div><h3>Remediation Prioritization</h3><span>Recommended order for addressing the findings</span></div></div><div class=\"ai-priority-list\">" + ai_prioritization_html + "</div></div>" if ai_prioritization_html else ""}

</div>


<div

    class="panel"

    id="scan-info">



    <h2>

        Scan Information

    </h2>



    <div class="metadata-grid">



        <div class="metadata-item">



            <div class="metadata-label">

                Scanner

            </div>



            <div class="metadata-value">

                CloudSentinel

            </div>



        </div>



        <div class="metadata-item">



            <div class="metadata-label">

                Version

            </div>



            <div class="metadata-value">

                {escape(str(scanner_version))}

            </div>



        </div>



        <div class="metadata-item">



            <div class="metadata-label">

                AWS Region

            </div>



            <div class="metadata-value">

                {escape(str(region))}

            </div>



        </div>



        <div class="metadata-item">



            <div class="metadata-label">

                AWS Account

            </div>



            <div class="metadata-value">

                {escape(str(account_id))}

            </div>



        </div>



    </div>



</div>


<div class="panel" id="iam-ml">
    <div class="ai-header">
        <div>
            <div class="ai-eyebrow">MACHINE LEARNING</div>
            <h2>IAM Misconfiguration Detection</h2>
            <p class="ai-subtitle">
                Supervised classification using the trained Random Forest model
            </p>
        </div>
        <div class="ai-status-card">
            <span class="ai-status-dot{" " if iam_ml_data.get("enabled") else " off"}"></span>
            <span>{"Model Loaded" if iam_ml_data.get("enabled") else "Model Unavailable"}</span>
        </div>
    </div>

    <div class="inventory">
        <div class="inventory-item">
            <div class="inventory-label">Algorithm</div>
            <div class="inventory-value" style="font-size:18px">
                Random Forest
            </div>
        </div>
        <div class="inventory-item">
            <div class="inventory-label">Test Accuracy</div>
            <div class="inventory-value">92%</div>
        </div>
        <div class="inventory-item">
            <div class="inventory-label">Test Precision</div>
            <div class="inventory-value">87.93%</div>
        </div>
        <div class="inventory-item">
            <div class="inventory-label">Test Recall</div>
            <div class="inventory-value">85%</div>
        </div>
    </div>

    <div class="table-wrapper" style="margin-top:22px">
        <table>
            <thead>
                <tr>
                    <th>IAM Resource</th>
                    <th>Resource Type</th>
                    <th>Prediction</th>
                    <th>Model Probability</th>
                </tr>
            </thead>
            <tbody>
                {iam_ml_rows}
            </tbody>
        </table>
    </div>

    <p class="ai-subtitle" style="margin-top:16px">
        Evaluation metrics are from the dataset test split. Live predictions
        are model estimates and do not replace deterministic security rules.
    </p>
</div>

<a class="nav-item" href="#iam-ml">IAM ML Model</a>



<div

    class="panel"

    id="inventory">



    <h2>

        AWS Inventory

    </h2>



    <div class="inventory">



        <div class="inventory-item">



            <div class="inventory-label">

                S3 Buckets

            </div>



            <div class="inventory-value">

                {s3_count}

            </div>



        </div>



        <div class="inventory-item">



            <div class="inventory-label">

                EC2 Instances

            </div>



            <div class="inventory-value">

                {ec2_count}

            </div>



        </div>



        <div class="inventory-item">



            <div class="inventory-label">

                Security Groups

            </div>



            <div class="inventory-value">

                {security_group_count}

            </div>



        </div>



        <div class="inventory-item">



            <div class="inventory-label">

                IAM Users

            </div>



            <div class="inventory-value">

                {iam_count}

            </div>



        </div>



    </div>



</div>



<div class="overview-grid">



<div class="panel">



    <h2>

        Severity Distribution

    </h2>



    <div class="severity-list">



        <div class="severity-row">



            <span class="severity-name">

                Critical

            </span>



            <span class="badge critical">

                {critical_count}

            </span>



        </div>



        <div class="severity-row">



            <span class="severity-name">

                High

            </span>



            <span class="badge high">

                {high_count}

            </span>



        </div>



        <div class="severity-row">



            <span class="severity-name">

                Medium

            </span>



            <span class="badge medium">

                {medium_count}

            </span>



        </div>



        <div class="severity-row">



            <span class="severity-name">

                Low

            </span>



            <span class="badge low">

                {low_count}

            </span>



        </div>



    </div>



</div>



<div class="panel">



    <h2>

        Risk Trend

    </h2>



    <div class="chart-container">



        <canvas id="riskTrend"></canvas>



    </div>



</div>



</div>



<div

    class="panel"

    id="findings">



    <div

        style="

        display:flex;

        justify-content:space-between;

        align-items:center;

        gap:15px;

        flex-wrap:wrap;

        ">



        <h2>

            Security Findings

        </h2>



        <div class="controls">



            <input

                id="search"

                class="search"

                type="text"

                placeholder="Search findings..."

                oninput="filterFindings()">



            <select

                id="severityFilter"

                class="select"

                onchange="filterFindings()">



                <option value="ALL">

                    All Severities

                </option>



                <option value="CRITICAL">

                    Critical

                </option>



                <option value="HIGH">

                    High

                </option>



                <option value="MEDIUM">

                    Medium

                </option>



                <option value="LOW">

                    Low

                </option>



            </select>



        </div>



    </div>



    <div class="table-wrapper">



        <table>



            <thead>



                <tr>



                    <th>

                        Severity

                    </th>



                    <th>

                        Rule

                    </th>



                    <th>

                        Resource

                    </th>



                    <th>

                        Description

                    </th>



                    <th>

                        Details

                    </th>



                </tr>



            </thead>



            <tbody id="findingsTable">



                {findings_html}



            </tbody>



        </table>



    </div>



</div>



<div

    class="panel"

    id="history">



    <div

        style="

        display:flex;

        justify-content:space-between;

        align-items:center;

        margin-bottom:20px;

        ">



        <h2>

            Scan History

        </h2>



        <span

            style="

            color:#64748b;

            font-size:12px;

            ">

            Last {len(history)} scans

        </span>



    </div>



    <div class="table-wrapper">



        <table>



            <thead>



                <tr>



                    <th>

                        Scan Time

                    </th>



                    <th>

                        Risk Level

                    </th>



                    <th>

                        Risk Score

                    </th>



                    <th>

                        Findings

                    </th>



                </tr>



            </thead>



            <tbody>



                {history_html}



            </tbody>



        </table>



    </div>



</div>



<div class="footer">



    CloudSentinel AWS Security Scanner



</div>



</div>



</main>



</div>



<script>



const TREND_DATA = {trend_json};



{javascript}



</script>



</body>



</html>

"""



    filename = os.path.join(

        REPORT_DIR,

        "cloudsentinel_report.html"

    )



    with open(

        filename,

        "w",

        encoding="utf-8"

    ) as file:

        file.write(html)



    return filename