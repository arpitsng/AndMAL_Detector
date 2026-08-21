import os
from dotenv import load_dotenv
load_dotenv()
from google import genai

keys = {
    'GEMINI_API_KEY1': os.environ.get('GEMINI_API_KEY1', ''),
    'GEMINI_API_KEY2': os.environ.get('GEMINI_API_KEY2', ''),
    'GEMINI_API_KEY3': os.environ.get('GEMINI_API_KEY3', ''),
}

model = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')
print(f"Configured GEMINI_MODEL in .env: {model}")

for name, key in keys.items():
    if not key:
        print(f"{name}: NOT SET")
        continue
    try:
        client = genai.Client(api_key=key)
        resp = client.models.generate_content(
            model=model,
            contents="Say 'OK'"
        )
        print(f"{name}: SUCCESS -> {resp.text.strip()}")
    except Exception as e:
        print(f"{name}: FAILED -> {e}")
