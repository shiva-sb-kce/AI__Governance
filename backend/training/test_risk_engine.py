import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )
)

from modules.risk_engine import RiskEngine

engine = RiskEngine()

result = engine.calculate_risk(
    threat_class="PROMPT_INJECTION",
    confidence=0.96
)

print(result)