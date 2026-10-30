import json
import os

from openai import OpenAI


class SecurityAnalyst:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("CLOUDSENTINEL_AI_MODEL", "gpt-6-luna")

        self.client = None

        if self.api_key:
            self.client = OpenAI(api_key=self.api_key)

    def is_available(self):
        return self.client is not None

    def _sanitize_finding(self, finding):
        allowed_fields = [
            "severity",
            "rule",
            "resource",
            "resource_type",
            "resource_id",
            "category",
            "message",
            "description",
            "why_it_matters",
            "current_configuration",
            "remediation",
            "port",
            "ml_prediction",
"ml_anomaly_score",
"ml_risk",
"ml_decision_score",
        ]

        return {
            key: finding.get(key)
            for key in allowed_fields
            if finding.get(key) is not None
        }

    
    def _request(self, prompt):
        if not self.client:
            return None

        try:
            response = self.client.responses.create(
                model=self.model,
                instructions=(
                    "You are CloudSentinel AI Security Analyst. "
                    "Analyze AWS security findings. "
                    "Do not invent facts or recommend destructive actions. "
                    "Give concise, practical guidance."
                ),
                input=prompt,
            )

            return response.output_text.strip()

        except Exception as exc:
            message = str(exc).lower()

            if "rate_limit_exceeded" in message or "requests per day" in message:
                return None

            print(
                "AI analysis temporarily unavailable."
            )

            return None


    def analyze_finding(self, finding):
        sanitized = self._sanitize_finding(finding)

        prompt = (
            "Analyze this CloudSentinel security finding.\n\n"
            f"{json.dumps(sanitized, indent=2)}\n\n"
            "Return the analysis using exactly these sections:\n"
            "Risk Explanation\n"
            "Business Impact\n"
            "Recommended Action\n"
            "Priority\n"
            "Keep the response concise."
        )

        return self._request(prompt)

    def prioritize_findings(self, findings):
        sanitized = [
            self._sanitize_finding(finding)
            for finding in findings
        ]

        prompt = (
            "Prioritize the following AWS security findings for remediation.\n\n"
            f"{json.dumps(sanitized, indent=2)}\n\n"
            "Rank them from most urgent to least urgent.\n"
            "Consider severity, potential exposure, identity risk, "
            "data exposure, and attack surface.\n\n"
            "Return a numbered list.\n"
            "For each item include:\n"
            "Priority\n"
            "Rule\n"
            "Reason\n"
            "Recommended Action"
        )

        return self._request(prompt)

    def generate_executive_summary(
        self,
        findings,
        risk,
        severity_summary,
        inventory_summary
    ):
        sanitized_findings = [
            self._sanitize_finding(finding)
            for finding in findings
        ]

        data = {
            "risk": risk,
            "severity_summary": severity_summary,
            "inventory_summary": inventory_summary,
            "findings": sanitized_findings,
        }

        prompt = (
            "Generate an executive security summary for this "
            "CloudSentinel AWS scan.\n\n"
            f"{json.dumps(data, indent=2)}\n\n"
            "Return exactly these sections:\n"
            "Overall Security Posture\n"
            "Top Risks\n"
            "Immediate Actions\n"
            "Recommended Next Steps\n\n"
            "Keep it suitable for a project dashboard and mentor demonstration."
        )

        return self._request(prompt)

    def answer_question(
        self,
        question,
        findings,
        risk,
        inventory_summary
    ):
        sanitized_findings = [
            self._sanitize_finding(finding)
            for finding in findings
        ]

        context = {
            "risk": risk,
            "inventory_summary": inventory_summary,
            "findings": sanitized_findings,
        }

        prompt = (
            "Answer the user's CloudSentinel security question "
            "using only the supplied scanner context.\n\n"
            f"Scanner Context:\n{json.dumps(context, indent=2)}\n\n"
            f"Question:\n{question}\n\n"
            "If the scanner context does not contain enough information, "
            "say so instead of inventing facts. "
            "Give a practical security explanation."
        )

        return self._request(prompt)

    def enrich_findings(self, findings):
        enriched = []

        for finding in findings:
            result = dict(finding)

            analysis = self.analyze_finding(
                finding
            )

            if isinstance(analysis, str):
                result["ai_analysis"] = analysis
                result["ai_enabled"] = True
            else:
                result["ai_analysis"] = None
                result["ai_enabled"] = False

            enriched.append(result)

        return enriched