# This is a standard WSGI entry point for Flask applications
import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Flask app
from autoimport import app

# Make the 'application' variable available for WSGI servers
# Some WSGI servers look for 'application' by default instead of 'app'
application = app

# This is only used when running this file directly, not by Gunicorn
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)