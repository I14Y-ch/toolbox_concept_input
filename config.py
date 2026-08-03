import os
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

# DeepL API key for translations (REQUIRED)
DEEPL_API_KEY = os.environ.get('DEEPL_API_KEY')
if not DEEPL_API_KEY:
    raise ValueError("DEEPL_API_KEY environment variable is required")

# Flask configuration (REQUIRED)
# Prefer standardized SECRET_KEY; keep FLASK_SECRET_KEY as backward-compat fallback.
SECRET_KEY = os.environ.get('SECRET_KEY') or os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")
if len(SECRET_KEY) < 32:
    raise ValueError("SECRET_KEY must be at least 32 characters long")

# Upload configuration (optional, defaults to 16MB)
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # Default 16MB