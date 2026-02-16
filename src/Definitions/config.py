REF_MAX = 10
NOT_NONE_REF_MAX = 5

CHAT_MODEL = "Qwen/Qwen3-4B"
CHAT_MODEL_TEMP = 0.2

SUMMARIZER_MODEL = "Qwen/Qwen3-4B"#"mistralai/Ministral-3-3B-Instruct-2512"

EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-4B"

from dotenv import load_dotenv
import os

load_dotenv(".env")
VAST_IP_PORT_MODEL = os.getenv('VAST_IP_PORT_MODEL')
VAST_IP_PORT_EMBEDDING = os.getenv('VAST_IP_PORT_EMBEDDING')

OPEN_BUTTON_TOKEN_MODEL = os.getenv('OPEN_BUTTON_TOKEN_MODEL')
OPEN_BUTTON_TOKEN_EMBEDDING = os.getenv('OPEN_BUTTON_TOKEN_EMBEDDING')

