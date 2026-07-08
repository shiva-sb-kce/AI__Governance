class RiskEngine:

    def calculate_risk(self, threat_class, confidence):

        score = int(confidence * 100)

        if threat_class == "SAFE":
            return {
                "risk_score": 0,
                "severity": "LOW",
                "action": "ALLOW"
            }

        if score >= 90:
            severity = "CRITICAL"
            action = "BLOCK"

        elif score >= 70:
            severity = "HIGH"
            action = "REVIEW"

        elif score >= 40:
            severity = "MEDIUM"
            action = "WARN"

        else:
            severity = "LOW"
            action = "ALLOW"

        return {
            "risk_score": score,
            "severity": severity,
            "action": action
        }