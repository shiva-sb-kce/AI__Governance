from modules.jwt_security_agent import (
    JWTSecurityAgent
)

agent = JWTSecurityAgent()

result = agent.analyze("")

token = "PASTE_TOKEN_HERE"

print(agent.analyze(token))