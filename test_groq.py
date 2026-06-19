import os
from openai import OpenAI

key = os.environ.get("GROQ_API_KEY", "").strip()
client = OpenAI(api_key=key, base_url="https://api.groq.com/openai/v1", max_retries=1)

try:
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": "Hello"}],
        timeout=10
    )
    print("SUCCESS")
    print(response.choices[0].message.content)
except Exception as e:
    print(f"ERROR: {e}")
