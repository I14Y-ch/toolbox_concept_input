import sys
import os

def print_debug_info():
    """Print debugging information about the Python environment"""
    print("--- Python Environment Debug Info ---")
    print(f"Python Version: {sys.version}")
    print(f"Current Working Directory: {os.getcwd()}")
    print(f"Python Path:")
    for path in sys.path:
        print(f"  - {path}")
    
    print("\n--- Available Files in Current Directory ---")
    try:
        files = os.listdir(".")
        for file in sorted(files):
            if os.path.isfile(file) and file.endswith(".py"):
                print(f"  - {file}")
    except Exception as e:
        print(f"Error listing files: {e}")
    
    print("\n--- Checking for critical modules ---")
    try:
        print("Checking for 'wsgi' module...", end=" ")
        try:
            import wsgi
            print("✓ Found")
            print(f"  Located at: {wsgi.__file__}")
            if hasattr(wsgi, 'application'):
                print("  'application' object exists in module")
            else:
                print("  WARNING: 'application' object NOT found in module")
        except ImportError as e:
            print(f"✗ Not found: {e}")
        
        print("Checking for 'autoimport' module...", end=" ")
        try:
            import autoimport
            print("✓ Found")
            print(f"  Located at: {autoimport.__file__}")
            if hasattr(autoimport, 'app'):
                print("  'app' object exists in module")
            else:
                print("  WARNING: 'app' object NOT found in module")
        except ImportError as e:
            print(f"✗ Not found: {e}")
    except Exception as e:
        print(f"Error during module checks: {e}")
    
    print("\n--- End of Debug Info ---")

if __name__ == "__main__":
    print_debug_info()
