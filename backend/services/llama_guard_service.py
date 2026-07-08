import torch

from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM
)

MODEL_PATH = "../models/llama_guard"

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_PATH
)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    torch_dtype=torch.float16,
    device_map="auto"
)

def scan_prompt(prompt):

    messages = [
        {
            "role": "user",
            "content": prompt
        }
    ]

    input_ids = tokenizer.apply_chat_template(
        messages,
        return_tensors="pt"
    ).to(model.device)

    output = model.generate(
        input_ids,
        max_new_tokens=100
    )

    response = tokenizer.decode(
        output[0],
        skip_special_tokens=True
    )

    return response