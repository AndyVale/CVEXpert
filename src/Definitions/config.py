REF_MAX = 10
NOT_NONE_REF_MAX = 5

CHAT_MODEL = "Qwen/Qwen3-4B"
CHAT_MODEL_TEMP = 0.2

SUMMARIZER_MODEL = "Qwen/Qwen3-4B"#"mistralai/Ministral-3-3B-Instruct-2512"

from dotenv import load_dotenv
import os

load_dotenv(".env")
VAST_HOST = os.getenv('VAST_HOST')
OPEN_BUTTON_TOKEN = os.getenv('OPEN_BUTTON_TOKEN')
