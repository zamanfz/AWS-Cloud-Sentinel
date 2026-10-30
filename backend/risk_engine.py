SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}


def calculate_risk(findings):
    score = 0

    for finding in findings:
        severity = finding.get(
            "severity",
            "LOW"
        )

        score += SEVERITY_WEIGHTS.get(
            severity,
            0
        )

    if score >= 20:
        risk_level = "CRITICAL"
    elif score >= 12:
        risk_level = "HIGH"
    elif score >= 6:
        risk_level = "MEDIUM"
    elif score > 0:
        risk_level = "LOW"
    else:
        risk_level = "SECURE"

    return {
        "score": score,
        "risk_level": risk_level,
    }


def get_severity_summary(findings):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity in summary:
            summary[severity] += 1

    return summary