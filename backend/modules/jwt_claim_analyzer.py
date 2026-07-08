EXPECTED_ISSUER = "AI-GOVERNANCE"
EXPECTED_AUDIENCE = "api-users"

def analyze_claims(payload):

    score = 0
    reasons = []

    if not payload:

        return {
            "score": score,
            "reasons": reasons
        }

    issuer = payload.get("iss")
    audience = payload.get("aud")

    if issuer != EXPECTED_ISSUER:

        score += 60

        reasons.append(
            "Invalid Issuer"
        )

    if audience != EXPECTED_AUDIENCE:

        score += 60

        reasons.append(
            "Invalid Audience"
        )

    return {
        "score": score,
        "reasons": reasons
    }