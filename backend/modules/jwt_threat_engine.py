def get_severity(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score >= 20:
        return "LOW"

    return "SAFE"


def get_action(severity):

    mapping = {
        "CRITICAL": "BLOCK",
        "HIGH": "BLOCK",
        "MEDIUM": "FLAG",
        "LOW": "MONITOR",
        "SAFE": "ALLOW"
    }

    return mapping[severity]

def detect_jwt_threat(request):
    score = 0
    reason = None

    token = request.get("auth_token", "")

    if not token:
        return 80, "JWT — Missing Token"

    if request.get("token_expired", False):
        return 80, "JWT — Expired Token"

    return 0, None