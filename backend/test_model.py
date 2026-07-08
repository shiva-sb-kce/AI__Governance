from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

MODEL_PATH = r"models/deberta_classifier"

print("Exists:", os.path.exists(MODEL_PATH))

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_PATH,
    use_fast=False,
    local_files_only=True
)

print("Tokenizer Loaded")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_PATH,
    local_files_only=True
)

print("Model Loaded")