import os
import tempfile
from autoimport import app

if __name__ == '__main__':
    # Use PORT environment variable if available (for Digital Ocean)
    port = int(os.environ.get('PORT', 5000))
    
    # Set Flask environment
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Ensure session directory exists
    session_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'session_data')
    os.makedirs(session_dir, exist_ok=True)
    
    # Run the app
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
