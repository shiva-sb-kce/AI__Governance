import torch
import torch.nn.functional as F
import os

MODEL_PATH = "models/deberta_classifier"
print("PWD =", os.getcwd())
print("MODEL_PATH =", os.path.abspath(MODEL_PATH))
print("EXISTS =", os.path.exists(MODEL_PATH))

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification
)


LABELS = {
    0: "SAFE",
    1: "JAIL_BREAK",
    2: "PROMPT_INJECTION",
    3: "Suspicious Activity",
    4: "Malicious Intent"
}
 
device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_PATH,
    use_fast=False,
    local_files_only=True
)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_PATH,
    local_files_only=True
)

model.to(device)
model.eval()

while True:

    prompt = input("\nEnter Prompt: ")

    if prompt.lower() == "exit":
        break

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=256
    )

    inputs = {
        k: v.to(device)
        for k, v in inputs.items()
    }

    with torch.no_grad():

        outputs = model(**inputs)

        probs = F.softmax(
            outputs.logits,
            dim=1
        )

        confidence, prediction = torch.max(
            probs,
            dim=1
        )

    predicted_label = prediction.item()

    print("\nPrediction:")
    print(
        LABELS[predicted_label]
    )

    print(
        "Confidence:",
        round(
            confidence.item() * 100,
            2
        ),
        "%"
    )