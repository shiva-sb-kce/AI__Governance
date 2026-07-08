from transformers import AutoTokenizer
from transformers import AutoModelForSequenceClassification

import torch 

import os

MODEL_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "models",
        "deberta_classifier"
    )
)

print("MODEL PATH =", MODEL_PATH)

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

model.eval()

labels = {
    0: "SAFE",
    1: "PROMPT_INJECTION",
    2: "JAILBREAK",
    3: "MALICIOUS",
    4: "SUSPICIOUS"
}

def classify_prompt(prompt):

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=256
    )

    with torch.no_grad():

        outputs = model(**inputs)

        probs = torch.softmax(
            outputs.logits,
            dim=1
        )

        confidence, prediction = torch.max(
            probs,
            dim=1
        )

    return {
        "class": labels[prediction.item()],
        "confidence": round(
            confidence.item(),
            4
        )
    }

if __name__ == "__main__":
    prompt = input("Enter Prompt: ")

    result = classify_prompt(prompt)

    print(result)