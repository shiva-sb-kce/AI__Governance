USED_JTI = set()

def check_replay(payload):

    score = 0
    reasons = []

    if not payload:
        return {
            "score": score,
            "reasons": reasons
        }

    jti = payload.get("jti")

    if not jti:
        return {
            "score": score,
            "reasons": reasons
        }

    if jti in USED_JTI:

        score += 90

        reasons.append(
            "JWT Replay Attack"
        )

    else:

        USED_JTI.add(jti)

    return {
        "score": score,
        "reasons": reasons
    }