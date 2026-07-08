import jwt

SECRET_KEY = "governance_secret"

def validate_token(token: str):

    score = 0
    reasons = []

    if not token:
        return {
            "score": 80,
            "reasons": ["Missing JWT Token"],
            "payload": None
        }

    try:

        header = jwt.get_unverified_header(token)

        if header.get("alg", "").lower() == "none":
            score += 100
            reasons.append("JWT Algorithm None Attack")

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return {
            "score": score,
            "reasons": reasons,
            "payload": payload
        }

    except jwt.ExpiredSignatureError:

        return {
            "score": 70,
            "reasons": ["Expired Token"],
            "payload": None
        }

    except jwt.InvalidSignatureError:

        return {
            "score": 90,
            "reasons": ["Invalid Signature"],
            "payload": None
        }

    except jwt.InvalidTokenError:

        return {
            "score": 80,
            "reasons": ["Malformed JWT"],
            "payload": None
        }