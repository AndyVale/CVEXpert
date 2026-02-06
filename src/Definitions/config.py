REF_MAX = 10
NOT_NONE_REF_MAX = 5

CHAT_MODEL = "Qwen/Qwen3-4B"
CHAT_MODEL_TEMP = 0.2

SUMMARIZER_MODEL = "Qwen/Qwen3-4B"#"mistralai/Ministral-3-3B-Instruct-2512"

EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-4B"

from dotenv import load_dotenv
import os

load_dotenv(".env")
VAST_IP_PORT = os.getenv('VAST_IP_PORT')
VAST_IP_PORT2 = os.getenv('VAST_IP_PORT2')

OPEN_BUTTON_TOKEN = os.getenv('OPEN_BUTTON_TOKEN')
OPEN_BUTTON_TOKEN2 = os.getenv('OPEN_BUTTON_TOKEN2')

