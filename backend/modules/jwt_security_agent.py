from modules.jwt_validation import validate_token
from modules.jwt_claim_analyzer import analyze_claims
from modules.jwt_replay_detection import check_replay
from modules.jwt_threat_engine import (
    get_severity,
    get_action
)

class JWTSecurityAgent:

    def analyze(self, token: str):

        total_score = 0
        reasons = []

        validation = validate_token(token)

        total_score += validation["score"]
        reasons.extend(validation["reasons"])

        payload = validation["payload"]

        claim_result = analyze_claims(payload)

        total_score += claim_result["score"]
        reasons.extend(claim_result["reasons"])

        replay_result = check_replay(payload)

        total_score += replay_result["score"]
        reasons.extend(replay_result["reasons"])

        total_score = min(total_score, 200)

        severity = get_severity(total_score)

        action = get_action(severity)

        return {
            "valid": total_score == 0,
            "risk_score": total_score,
            "severity": severity,
            "action": action,
            "reasons": reasons
        }