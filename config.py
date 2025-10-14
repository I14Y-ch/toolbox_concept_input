import os
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

# DeepL API key for translations (REQUIRED)
DEEPL_API_KEY = os.environ.get('DEEPL_API_KEY')
if not DEEPL_API_KEY:
    raise ValueError("DEEPL_API_KEY environment variable is required")

# Flask configuration (REQUIRED)
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not FLASK_SECRET_KEY:
    raise ValueError("FLASK_SECRET_KEY environment variable is required")

# Upload configuration (optional, defaults to 16MB)
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # Default 16MB