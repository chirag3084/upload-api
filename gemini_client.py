from google import genai
from dotenv import load_dotenv
import os
load_dotenv()

client = genai.Client(
    api_key=os.environ.get("GEMINI_API_KEY")
)
print(client.api_key)
