from fastapi import FastAPI
from diffusers import DiffusionPipeline
from diffusers.utils import export_to_video
import torch
import os

app = FastAPI()

print("Loading WAN model...")

# Detect device
device = "cuda" if torch.cuda.is_available() else "cpu"

# Clear old VRAM cache
if device == "cuda":
    torch.cuda.empty_cache()

# Load model
pipe = DiffusionPipeline.from_pretrained(
    "Wan-AI/Wan2.1-T2V-1.3B-Diffusers",
    torch_dtype=torch.float32   # safer for GTX 1080
)

# Move model to GPU
pipe = pipe.to(device)

# Memory optimization
pipe.enable_attention_slicing()

# Optional:
# pipe.enable_xformers_memory_efficient_attention()

print("Model loaded successfully")

# Prompt collection
PROMPTS = {

    "cyberpunk_cat":
    "A cute cat walking in a futuristic cyberpunk city, neon lights, cinematic lighting, ultra detailed",

    "robot_city":
    "A giant humanoid robot walking through a destroyed futuristic city, smoke, cinematic, realistic",

    "anime_girl":
    "Anime girl standing in rain, Tokyo street at night, glowing neon signs, cinematic anime style",

    "space_scene":
    "Astronaut floating in deep space near a glowing galaxy, cinematic lighting, realistic",

    "sports_car":
    "A red sports car drifting on a mountain road during sunset, cinematic camera movement",

    "dragon_fire":
    "A massive dragon breathing fire over a medieval castle at night, fantasy cinematic scene",

    "nature":
    "Beautiful waterfall in a tropical jungle, birds flying, cinematic drone shot",

    "superhero":
    "A superhero flying above a futuristic city at sunset, epic cinematic scene"
}


@app.get("/")
def home():

    return {
        "message": "WAN Video API Running",
        "available_prompts": list(PROMPTS.keys())
    }


@app.get("/generate")
def generate(prompt_name: str = "cyberpunk_cat"):

    # Check prompt
    if prompt_name not in PROMPTS:
        return {
            "error": "Invalid prompt name",
            "available_prompts": list(PROMPTS.keys())
        }

    prompt = PROMPTS[prompt_name]

    print(f"Generating video for: {prompt_name}")

    try:

        # Generate video
        output = pipe(
            prompt=prompt,
            num_frames=4,
            num_inference_steps=4,
            guidance_scale=5,
            height=256,
            width=256
        )

        video_frames = output.frames[0]

        # Create output folder
        os.makedirs("outputs", exist_ok=True)

        output_path = f"outputs/{prompt_name}.mp4"

        # Save video
        export_to_video(
            video_frames,
            output_path,
            fps=4
        )

        print("Video saved:", output_path)

        return {
            "message": "Video generated successfully",
            "prompt": prompt,
            "video_path": output_path
        }

    except Exception as e:

        return {
            "error": str(e)
        }