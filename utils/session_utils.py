"""
Utilities for managing session data more efficiently.
"""
import json
import os
import tempfile
import uuid

def store_large_data(data):
    """Store large data in a temporary file rather than in the session"""
    session_id = str(uuid.uuid4())
    
    # Create a temporary directory if it doesn't exist
    temp_dir = os.path.join(tempfile.gettempdir(), 'autoimport')
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    # Store data in a temporary file
    file_path = os.path.join(temp_dir, f"{session_id}.json") 
    with open(file_path, 'w') as f:
        json.dump(data, f)
    
    return session_id

def get_large_data(session_id):
    """Retrieve large data from a temporary file"""
    temp_dir = os.path.join(tempfile.gettempdir(), 'autoimport')
    file_path = os.path.join(temp_dir, f"{session_id}.json")
    
    if not os.path.exists(file_path):
        return None
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    return data

def cleanup_large_data(session_id):
    """Remove temporary file for large data"""
    temp_dir = os.path.join(tempfile.gettempdir(), 'autoimport')
    file_path = os.path.join(temp_dir, f"{session_id}.json")
    
    if os.path.exists(file_path):
        os.remove(file_path)
