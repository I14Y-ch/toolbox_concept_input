from flask import Flask, request, render_template, jsonify, session, redirect, url_for, abort
import pandas as pd
from datetime import datetime, date
import os
import re
import json
import base64
import jwt
from collections import Counter
from pandas.api.types import is_numeric_dtype, is_object_dtype
import requests
import config
import uuid
import pickle
import unicodedata
import string
from collections import defaultdict
from langdetect import detect
import tempfile
import openai

# Create the Flask app first, before any circular imports might occur
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.secret_key = config.FLASK_SECRET_KEY  # Use config value from environment

# Add error handlers to return JSON instead of HTML for API requests
@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum file size is 16MB.'}), 413

@app.errorhandler(500)
def internal_server_error(error):
    """Handle internal server errors"""
    import traceback
    traceback.print_exc()
    # Check if this is an API request (JSON expected)
    if request.path.startswith('/api/') or request.is_json or request.accept_mimetypes.accept_json:
        return jsonify({'error': 'Internal server error. Please try again or contact support.'}), 500
    # Otherwise return HTML error page
    return "Internal Server Error", 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle any unhandled exceptions"""
    import traceback
    traceback.print_exc()
    # Check if this is an API request or file upload
    if request.path.startswith('/api/') or request.is_json or request.accept_mimetypes.accept_json or request.path == '/':
        return jsonify({'error': f'An error occurred: {str(error)}'}), 500
    # Otherwise re-raise to let Flask handle it
    raise error

# Create a directory to store session data files
SESSION_DATA_DIR = os.path.join(tempfile.gettempdir(), 'i14y-concept-import-sessions')
if not os.path.exists(SESSION_DATA_DIR):
    os.makedirs(SESSION_DATA_DIR)

# Helper functions to save and load session data
def save_session_data(data):
    """Save session data to a file and return a unique ID"""
    session_id = str(uuid.uuid4())
    file_path = os.path.join(SESSION_DATA_DIR, f"{session_id}.pkl")
    with open(file_path, 'wb') as f:
        pickle.dump(data, f)
    return session_id

def load_session_data(session_id):
    """Load session data from a file based on ID"""
    file_path = os.path.join(SESSION_DATA_DIR, f"{session_id}.pkl")
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'rb') as f:
        return pickle.load(f)

# Add theme definitions
VALID_THEMES = {
    "101": "Work",  # "Arbeit"
    "102": "Construction",  # "Bauen"
    "103": "Education",  # "Bildung"
    "104": "Foreign Relations",  # "Aussenbeziehungen"
    "105": "Jurisdiction",  # "Gerichtsbarkeit"
    "106": "Society",  # "Gesellschaft"
    "107": "Political Activities",  # "Politische Aktivitäten"
    "108": "Culture",  # "Kultur"
    "109": "Agriculture",  # "Landwirtschaft"
    "110": "Infrastructure",  # "Infrastruktur"
    "111": "Security",  # "Sicherheit"
    "112": "Taxes",  # "Steuern"
    "113": "Environment",  # "Umwelt"
    "114": "Health",  # "Gesundheit"
    "115": "Economy",  # "Wirtschaft"
    "116": "Mobility",  # "Mobilität"
    "117": "Residents",  # "Einwohner"
    "118": "Companies",  # "Unternehmen"
    "119": "Authorities",  # "Behörden"
    "120": "Buildings and Real Estate",  # "Gebäude und Grundstücke"
    "121": "Animals",  # "Tiere"
    "122": "Geoinformation",  # "Geoinformationen"
    "123": "Legal Framework",  # "Rechtssammlung"
    "124": "Energy",  # "Energie"
    "125": "Public Statistics",  # "Öffentliche Statistik"
    "126": "Social Security"  # "Soziale Sicherheit"
}

def simple_multilingual(text):
    """Create a simple multilingual object without performing translations"""
    return {
        "de": text,
        "en": text,
        "fr": text,
        "it": text,
        "rm": text,
    }

def generate_regex_pattern(values):
    """Generate a regex pattern that matches all strings in the given list using pure Python."""
    if not values:
        return ""
    
    # For numeric values, just return a generic pattern
    if all(isinstance(v, (int, float)) for v in values):
        max_digits = max(len(str(int(v))) for v in values)
        return f"\\d{{{max_digits}}}"
    
    # For strings, prepare valid samples
    samples = [str(v) for v in values[:50] if v is not None and str(v).strip()]  # Use up to 50 samples, skip empty values
    
    if not samples:
        return ".*"  # Default if no valid samples
    
    # Check for common patterns first
    date_formats = [
        # Standard ISO format: YYYY-MM-DD
        (r'^\d{4}-\d{2}-\d{2}$', "\\d{4}-\\d{2}-\\d{2}"),
        # European format: DD.MM.YYYY
        (r'^\d{2}\.\d{2}\.\d{4}$', "\\d{2}\\.\\d{2}\\.\\d{4}"),
        # European format with flexible day/month: D.M.YYYY or DD.MM.YYYY
        (r'^\d{1,2}\.\d{1,2}\.\d{4}$', "\\d{1,2}\\.\\d{1,2}\\.\\d{4}"),
        # US format: MM/DD/YYYY
        (r'^\d{2}/\d{2}/\d{4}$', "\\d{2}/\\d{2}/\\d{4}"),
        # Flexible slash format: M/D/YYYY or MM/DD/YYYY
        (r'^\d{1,2}/\d{1,2}/\d{4}$', "\\d{1,2}/\\d{1,2}/\\d{4}"),
        # Compact format: YYYYMMDD
        (r'^\d{8}$', "\\d{8}"),
        # ISO format with time: YYYY-MM-DD HH:MM:SS
        (r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}")
    ]
    
    # More permissive date pattern detection - match if 80% of samples match the pattern
    for pattern, regex in date_formats:
        matching_count = sum(1 for s in samples if re.match(pattern, s))
        match_percentage = matching_count / len(samples)
        if match_percentage > 0.8:  # If 80% or more samples match
            return regex
    
    # Email pattern special case
    if all('@' in s for s in samples):
        return "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    
    # UUID pattern special case
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if all(re.match(uuid_pattern, s.lower()) for s in samples):
        return "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    
    # Fallback to simple patterns for specific cases
    if len(set(len(s) for s in samples)) == 1:
        sample_length = len(samples[0])
        
        # Check if all characters are numeric
        if all(s.isdigit() for s in samples):
            return f"\\d{{{sample_length}}}"
        
        # Check if all characters are alphabetic
        if all(s.isalpha() for s in samples):
            return f"[A-Za-z]{{{sample_length}}}"
            
        # Check if all characters are alphanumeric
        if all(s.isalnum() for s in samples):
            return f"[A-Za-z0-9]{{{sample_length}}}"
    
    # Check for common character patterns
    has_letters = any(c.isalpha() for s in samples for c in s)
    has_digits = any(c.isdigit() for s in samples for c in s)
    has_spaces = any(' ' in s for s in samples)
    has_special = any(not c.isalnum() and c != ' ' for s in samples for c in s)
    
    if has_letters and has_digits and not has_spaces and not has_special:
        # Alphanumeric without spaces or special chars
        min_length = min(len(s) for s in samples)
        max_length = max(len(s) for s in samples)
        if min_length == max_length:
            return f"[A-Za-z0-9]{{{min_length}}}"
        else:
            return f"[A-Za-z0-9]{{{min_length},{max_length}}}"
    
    # Last resort - return a generic pattern
    return ".*"

def analyze_column_type(series):
    # First check for all null values
    if series.isna().all():
        return {'type': 'String', 'is_codelist': False}
    
    column_name = series.name.lower() if hasattr(series, 'name') else ""
    
    # Special handling for year columns
    is_year_column = (
        'jahr' in column_name or 
        'year' in column_name or 
        'annee' in column_name or 
        'anno' in column_name
    )
    
    # Check for year values (4-digit numbers between 1900 and current year + 100)
    current_year = datetime.now().year
    def is_year_value(val):
        try:
            val = int(val)
            return 1900 <= val <= current_year + 100
        except:
            return False
    
    # Check if all values are years
    all_years = False
    if is_numeric_dtype(series) or is_object_dtype(series):
        all_years = all(is_year_value(val) for val in series.dropna())
    
    # If it's a year column by name or all values are years, treat as Number
    if (is_year_column or all_years) and len(series.dropna().unique()) <= 200:
        return {
            'type': 'Number',
            'is_codelist': False,
            'format': 'YYYY',
            'pattern': '\\d{4}'
        }
    
    # Check if datetime - use explicit formats to avoid warnings
    is_date = False
    date_format = None
    
    # Common date formats to try
    date_formats = [
        '%Y-%m-%d',    # YYYY-MM-DD
        '%d.%m.%Y',    # DD.MM.YYYY
        '%d/%m/%Y',    # DD/MM/YYYY
        '%m/%d/%Y',    # MM/DD/YYYY
        '%Y%m%d',      # YYYYMMDD
        '%d-%m-%Y'     # DD-MM-YYYY
    ]
    
    sample_values = series.dropna().head(10).astype(str)
    if pd.api.types.is_datetime64_any_dtype(series):
        is_date = True
        date_format = infer_date_format(series)
    else:
        # Try each format explicitly
        for fmt in date_formats:
            try:
                # Try to parse with this format - specify errors='raise' to avoid silent conversion
                pd.to_datetime(sample_values, format=fmt, errors='raise')
                is_date = True
                date_format = fmt_to_readable(fmt)
                break
            except:
                continue
        
        # If none worked, check common patterns with regex instead of using dateutil
        if not is_date:
            date_patterns = [
                (r'^\d{4}-\d{2}-\d{2}$', 'YYYY-MM-DD'),
                (r'^\d{2}\.\d{2}\.\d{4}$', 'DD.MM.YYYY'),
                (r'^\d{2}/\d{2}/\d{4}$', 'DD/MM/YYYY')
            ]
            
            for pattern, fmt in date_patterns:
                if all(re.match(pattern, s) for s in sample_values):
                    is_date = True
                    date_format = fmt
                    break
    
    if is_date:
        pattern = generate_regex_pattern(series.dropna().tolist())
        # Ensure we have a proper date pattern even if generate_regex_pattern fails
        if pattern == ".*" and date_format:
            # Use format to determine pattern
            if date_format == 'YYYY-MM-DD':       
                pattern = "\\d{4}-\\d{2}-\\d{2}"
            elif date_format == 'DD.MM.YYYY':
                pattern = "\\d{2}\\.\\d{2}\\.\\d{4}"
            elif date_format == 'DD/MM/YYYY':
                pattern = "\\d{2}/\\d{2}/\\d{4}"
                
        return {
            'type': 'Date',
            'is_codelist': False,
            'format': date_format,
            'pattern': pattern
        }
    
    # Get basic statistics
    unique_values = series.dropna().unique()
    total_values = len(series.dropna())
    
    # Check if numeric
    is_numeric = False
    if pd.api.types.is_numeric_dtype(series):
        is_numeric = True
    else:
        try:
            pd.to_numeric(series, errors='raise')
            is_numeric = True
        except:
            pass
    
    # Criteria for codelist remains the same, but we'll exclude years and true numeric values
    is_codelist = (
        len(unique_values) < 50 and 
        total_values >= 5 and 
        len(unique_values) < total_values/2
    )
    
    # Additional checks for numeric values
    if is_numeric:
        # If values look like measurements (many different values, decimals), not a codelist
        values = pd.to_numeric(series.dropna())
        has_decimals = any(v % 1 != 0 for v in values)
        high_cardinality = len(unique_values) > 20
        
        if has_decimals or high_cardinality:
            is_codelist = False
        
        # For small integers, additional check if it looks like a code
        if not is_codelist and not has_decimals:
            if (len(unique_values) <= 10 and
                max(values) <= 100 and
                values.dtype in ['int64', 'int32']):
                is_codelist = True
    
    if is_codelist:
        value_counts = series.value_counts()
        
        # Calculate length statistics for codes
        if is_numeric:
            code_lengths = [len(str(val)) for val in unique_values]
            code_type = 'numeric'
        else:
            code_lengths = [len(str(val)) for val in unique_values]
            code_type = 'string'
        
        return {
            'type': 'Codelist',
            'is_codelist': True,
            'unique_values': sorted(unique_values.tolist())[:20],  # Limit unique values
            'value_counts': {str(k): v for k, v in list(value_counts.items())[:20]},  # Limit value counts
            'total_values': total_values,
            'unique_count': len(unique_values),
            'code_type': code_type,
            'min_length': min(code_lengths),
            'max_length': max(code_lengths)
        }
    
    # Make sure to include pattern in the Number type too
    if is_numeric and not is_codelist:
        # Generate pattern for numeric values
        values = pd.to_numeric(series.dropna())
        has_decimals = any(v % 1 != 0 for v in values)
        
        if has_decimals:
            # For floating point values
            max_decimals = max(len(str(v).split('.')[1]) if '.' in str(v) else 0 
                               for v in values)
            pattern = f"\\d+\\.\\d{{{max_decimals}}}"
        else:
            # For integer values
            max_digits = max(len(str(int(v))) for v in values)
            pattern = f"\\d{{{max_digits}}}"
            
        return {
            'type': 'Number',
            'is_codelist': False,
            'pattern': pattern
        }
    
    # For string values, generate a pattern
    if not is_numeric:
        pattern = generate_regex_pattern(series.dropna().tolist())
        return {
            'type': 'String',
            'is_codelist': False,
            'pattern': pattern
        }
    
    # Default to Number for numeric columns
    return {'type': 'Number', 'is_codelist': False}

def infer_date_format(series):
    """Infer the date format from a series."""
    # Convert to strings first
    samples = [str(val)[:10] for val in series.dropna().tolist()[:5]]
    
    # Check common patterns
    if all(re.match(r'^\d{4}-\d{2}-\d{2}$', s) for s in samples):
        return 'YYYY-MM-DD'
    if all(re.match(r'^\d{2}\.\d{2}\.\d{4}$', s) for s in samples):
        return 'DD.MM.YYYY'
    if all(re.match(r'^\d{2}/\d{2}/\d{4}$', s) for s in samples):
        return 'DD/MM/YYYY'
    
    # Default format
    return 'YYYY-MM-DD'

def fmt_to_readable(fmt):
    """Convert Python date format to human-readable format"""
    mapping = {
        '%Y-%m-%d': 'YYYY-MM-DD',
        '%d.%m.%Y': 'DD.MM.YYYY',
        '%d/%m/%Y': 'DD/MM/YYYY',
        '%m/%d/%Y': 'MM/DD/YYYY',
        '%Y%m%d': 'YYYYMMDD',
        '%d-%m-%Y': 'DD-MM-YYYY'
    }
    return mapping.get(fmt, fmt)

def fetch_agencies():
    """Fetch available agencies from I14Y API"""
    try:
        response = requests.get("https://input.i14y.admin.ch/api/Agent", timeout=10)
        if response.status_code == 200:
            agencies = response.json()
            # Sort agencies by German name for better UI
            agencies.sort(key=lambda x: x.get('name', {}).get('de', '').lower())
            return agencies
        else:
            return []
    except Exception:
        return []

def fetch_dataset_metadata(dataset_id, token):
    """Fetch metadata for a dataset from the I14Y API"""
    url = f'https://api.i14y.admin.ch/api/partner/v1/datasets/{dataset_id}'
    headers = {
        'accept': 'text/plain',
        'Authorization': token
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return None
    except Exception:
        return None

def detect_language(text):
    """
    Detect the language of the given text.
    Supports multiple languages including German, French, Italian, and English.
    """
    if not text or not detect:
        return 'DE'  # Default to German if text is empty or langdetect not available
    
    try:
        # Map language codes to what DeepL expects
        lang_map = {
            'de': 'DE',  # German
            'en': 'EN',  # English
            'fr': 'FR',  # French
            'it': 'IT',  # Italian
        }
        
        # Detect language using langdetect
        detected = detect(text)
        
        # Return appropriate code or default to German
        return lang_map.get(detected, 'DE')
    except Exception:
        return 'DE'  # Default to German if detection fails

def fetch_user_agencies(token):
    """Fetch agencies assigned to the user based on their token"""
    if not token:
        return []
    
    # Properly format the token - ensure it has 'Bearer ' prefix but avoid double prefixing
    auth_token = token.strip()
    if not auth_token.startswith('Bearer '):
        auth_token = f'Bearer {auth_token}'
    
    url = "https://input.i14y.admin.ch/api/Agent/user"
    headers = {
        'accept': 'application/json',
        'Authorization': auth_token
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            agencies = response.json()
            # Sort agencies by German name for better UI
            agencies.sort(key=lambda x: x.get('name', {}).get('de', '').lower())
            return agencies
        else:
            # Try alternative approach - fetch all agencies and let user choose
            return fetch_agencies()
    except Exception:
        # Try alternative approach - fetch all agencies and let user choose
        return fetch_agencies()

def read_csv_with_encoding_fallback(file, **kwargs):
    """
    Try to read CSV with different encodings and delimiters
    """
    from io import StringIO, BytesIO
    
    # Read the file content as bytes
    if hasattr(file, 'read'):
        # Save the current position
        initial_position = file.tell() if hasattr(file, 'tell') else 0
        content = file.read()
        
        # Reset file pointer for potential re-use
        if hasattr(file, 'seek'):
            try:
                file.seek(initial_position)
            except:
                pass
        
        if isinstance(content, str):
            # Already decoded, use directly
            return pd.read_csv(StringIO(content), **kwargs)
    else:
        content = file
    
    # Ensure content is bytes
    if isinstance(content, str):
        content = content.encode('utf-8')
    
    # Try to detect encoding with chardet if available
    detected_encoding = None
    try:
        import chardet
        detected = chardet.detect(content)
        if detected and detected.get('encoding'):
            detected_encoding = detected['encoding']
    except ImportError:
        pass
    
    # Build list of encodings to try, prioritizing detected encoding
    encodings = ['utf-8', 'cp1252', 'latin1', 'iso-8859-1', 'utf-16', 'utf-32']
    if detected_encoding and detected_encoding not in encodings:
        encodings.insert(0, detected_encoding)
    elif detected_encoding:
        # Move detected encoding to front
        encodings.remove(detected_encoding)
        encodings.insert(0, detected_encoding)
    
    # Try each encoding
    last_error = None
    for encoding in encodings:
        try:
            text_content = content.decode(encoding)
            # Try to read with pandas
            return pd.read_csv(StringIO(text_content), **kwargs)
        except (UnicodeDecodeError, LookupError) as e:
            last_error = e
            continue
        except Exception as e:
            # Pandas error (e.g., parsing error)
            last_error = e
            continue
    
    # If all encodings fail, raise an error with details
    if last_error:
        raise ValueError(f"Could not decode or parse the CSV file. Last error: {str(last_error)}")
    else:
        raise ValueError("Could not decode the CSV file with any supported encoding")

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        # We don't need to fetch agencies upfront anymore, as we'll fetch them based on the token
        return render_template('index.html', themes=VALID_THEMES)
    
    if request.method == 'POST':
        try:
            # Get the token from the form
            token = request.form.get('token')
            if not token:
                return jsonify({'error': 'API token is required'}), 400
            
            # Check if an agency was selected or needs to be selected
            selected_agency = request.form.get('selected_agency')
            if not selected_agency:
                # Fetch agencies for this user
                agencies = fetch_user_agencies(token)
                
                if not agencies:
                    return jsonify({'error': 'Could not fetch any agencies with the provided token. Please verify your token is correct.'})
                
                if len(agencies) > 1:
                    # Return JSON with agency selection data instead of HTML template
                    return jsonify({
                        'needs_agency_selection': True,
                        'agencies': agencies,
                        'token': token,
                        'themes': VALID_THEMES
                    })
                else:
                    # If only one agency, use it automatically
                    selected_agency = agencies[0]['identifier']
            
            # Now we have the token and selected agency
            if 'file' not in request.files:
                return jsonify({'error': 'No file part'})
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No selected file'})
            
            try:
                if file and file.filename.lower().endswith(('.xlsx', '.xls')):
                    df = pd.read_excel(file)
                elif file and file.filename.lower().endswith('.csv'):
                    df = read_csv_with_encoding_fallback(file, sep=None, engine='python')
                else:
                    return jsonify({'error': 'Unsupported file type. Please upload a .xlsx, .xls, or .csv file'}), 400
            except ValueError as e:
                # Specific error for encoding/parsing issues
                import traceback
                traceback.print_exc()
                return jsonify({'error': f'Failed to read the file: {str(e)}. Please check the file format and encoding.'}), 400
            except Exception as e:
                import traceback
                traceback.print_exc()
                return jsonify({'error': f'Failed to read the file: {str(e)}. Please check the file format and encoding.'}), 400
            
            columns_info = []
            form_data = {
                'responsible_person': request.form.get('responsible_person'),
                'responsible_deputy': request.form.get('responsible_deputy'),
                'publisher_id': selected_agency,  # We use the selected agency as publisher ID
                'theme': request.form.get('theme')
            }
            
            # Validate new required fields
            if not all(form_data.values()):
                return jsonify({'error': 'All concept information fields are required'})
            
            # Validate theme
            if form_data['theme'] not in VALID_THEMES:
                return jsonify({'error': 'Invalid theme code'})
            
            # Process columns but avoid storing large datasets in session
            for column in df.columns:
                analysis = analyze_column_type(df[column])
                
                # Create a simplified column info that takes less space
                column_info = {
                    'name': column,
                    'type': analysis['type'],
                    'is_codelist': analysis['is_codelist']
                }
                
                # Only store essential data for codelists
                if analysis['is_codelist']:
                    # Limit the amount of data we store in the session
                    column_info.update({
                        'unique_values': analysis['unique_values'][:20],  # Limit to 20 values
                        'value_counts': {str(k): v for k, v in list(analysis['value_counts'].items())[:20]},
                        'code_type': analysis['code_type'],
                        'min_length': analysis['min_length'],
                        'max_length': analysis['max_length'],
                        'unique_count': analysis['unique_count']
                    })
                
                # Add pattern and format if they exist
                if 'pattern' in analysis:
                    column_info['pattern'] = analysis['pattern']
                
                if 'format' in analysis:
                    column_info['format'] = analysis['format']
                
                columns_info.append(column_info)
            
            # Store only minimal data in the session
            session_data = {
                'columns': columns_info,
                'form_data': form_data,
                'token': token,
                # We no longer need dataset_id or dataset_metadata
            }
            
            # Save the full data to a file
            session_id = save_session_data(session_data)
            
            # Store only the session ID in the actual session cookie
            session['session_data_id'] = session_id
            
            # Return JSON success response instead of redirect
            return jsonify({
                'success': True,
                'redirect_url': url_for('results')
            })
            
        except Exception as e:
            # Catch any unhandled errors and return JSON
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'An error occurred while processing the file: {str(e)}'}), 500
    
    return render_template('index.html', themes=VALID_THEMES)

@app.route('/results', methods=['GET'])
def results():
    if 'session_data_id' not in session:
        return redirect(url_for('upload_file'))
    
    # Get session data from file
    session_data = load_session_data(session['session_data_id'])
    if not session_data:
        # Session data expired or not found
        session.pop('session_data_id', None)
        return redirect(url_for('upload_file'))
    
    return render_template('results.html', 
                          columns=session_data['columns'],
                          form_data=session_data['form_data'],
                          themes=VALID_THEMES)  # Pass themes to the template

@app.route('/concept/<int:index>', methods=['GET'])
def view_concept(index):
    if 'session_data_id' not in session:
        return redirect(url_for('upload_file'))
    
    # Get session data from file
    session_data = load_session_data(session['session_data_id'])
    if not session_data:
        # Session data expired or not found
        session.pop('session_data_id', None)
        return redirect(url_for('upload_file'))
    
    # Validate index
    if index < 0 or index >= len(session_data['columns']):
        return redirect(url_for('results'))
    
    return render_template('concept.html', 
                          column=session_data['columns'][index],
                          index=index,
                          total=len(session_data['columns']),
                          form_data=session_data['form_data'],
                          token=session_data.get('token', ''))  # Pass token to template

def generate_concept_json(column, form_data, description, params=None, translations=None, dataset_metadata=None, keywords=None):
    """Generate a concept JSON based on column information and user inputs"""
    # Default params if none provided
    if not params:
        params = {}
    
    # Handle keywords - use provided keywords or generate defaults
    if keywords and keywords.strip():
        # Parse keywords string into multilingual objects
        keyword_list = []
        for kw in keywords.split(','):
            kw = kw.strip()
            if kw:
                keyword_list.append(simple_multilingual(kw))
        concept_keywords = keyword_list
    elif translations and translations.get('keywords'):
        # Use keywords from translations if available
        concept_keywords = []
        keywords_trans = translations['keywords']
        # Get all non-empty keywords from different languages
        all_keywords = set()
        for lang in ['de', 'en', 'fr', 'it', 'rm']:
            if keywords_trans.get(lang) and keywords_trans[lang].strip():
                # Split by comma and add each keyword
                for kw in keywords_trans[lang].split(','):
                    kw = kw.strip()
                    if kw:
                        all_keywords.add(kw)
        
        # Create multilingual objects for each unique keyword
        for kw in all_keywords:
            concept_keywords.append(simple_multilingual(kw))
    else:
        # Generate keywords from column name parts (fallback)
        concept_keywords = []
        for word in column['name'].split('_'):
            if word:
                # Only use simple keywords without translations by default
                concept_keywords.append(simple_multilingual(word))
    
    # Ensure we have at least one keyword
    if not concept_keywords:
        concept_keywords = [simple_multilingual(column['name'])]
    
    # Determine concept type - using correct I14Y API enum values
    concept_type = "String"  # Default - changed from "Text" to "String"
    if column['is_codelist']:
        concept_type = "CodeList"
    elif column['type'] == "Number":
        concept_type = "Numeric"
    elif column['type'] == "Date":
        concept_type = "Date"  # Changed from "DateTime" to "Date"
    
    # Create identifier with proper format
    identifier = column['name'].replace(' ', '_').upper()
    
    # Build data object with exact field ordering
    data = {"conceptType": concept_type}
    
    # Add type-specific fields
    if column['is_codelist']:
        # Use "String" instead of "Text" - matching the exact enum values from the API
        value_type = "Numeric" if column['code_type'] == 'numeric' else "String"
        data["codeListEntryValueType"] = value_type
        data["codeListEntryValueMaxLength"] = column.get('max_length', 0)
    
    elif column['type'] == "Number":
        data["maxValue"] = int(params.get('max_value', 999))
        data["measurementUnit"] = params.get('unit', '')
        data["minValue"] = int(params.get('min_value', 0))
        data["numberDecimals"] = int(params.get('decimals', 0))
        # Note: pattern is not supported for Numeric type in I14Y API
    
    elif column['type'] == "Date":
        # Date type only has pattern field (not dateTimeFormat)
        pattern = params.get('pattern') or params.get('format') or column.get('pattern') or column.get('format', 'yyyy-mm-dd')
        data["pattern"] = pattern
    
    else:  # String type
        # String type requires maxLength and minLength
        data["maxLength"] = int(params.get('max_length', 255))
        data["minLength"] = int(params.get('min_length', 0))
        # Include pattern if provided and not empty (allow .* as valid pattern)
        pattern = params.get('pattern')
        if pattern and pattern.strip():
            data["pattern"] = pattern.strip()
    
    # Empty conformsTo field instead of adding a standard entry
    data["conformsTo"] = []
    
    # Use translations if available, otherwise use simple multilingual text
    if translations and translations.get('description'):
        data["description"] = translations['description']
    else:
        data["description"] = simple_multilingual(description)
    
    data["identifier"] = identifier
    data["keywords"] = concept_keywords
    
    # Use translations for name if available
    if translations and translations.get('title'):
        data["name"] = translations['title']
    else:
        data["name"] = simple_multilingual(column['name'])
    
    data["publisher"] = {
        "identifier": form_data['publisher_id']
    }
    
    # Ensure email format for responsible persons - API expects email, not identifier
    data["responsibleDeputy"] = {
        "email": form_data['responsible_deputy']
    }
    data["responsiblePerson"] = {
        "email": form_data['responsible_person']
    }
    
    # Ensure themes is correctly formatted
    data["themes"] = [{
        "code": form_data['theme']
    }]
    
    # Format dates properly
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    
    data["validFrom"] = now
    data["validTo"] = "9999-12-31T23:59:59.9999999+00:00"
    data["version"] = "1.0.0"
    
    return {"data": data}

def generate_concept_description(column, lang="de", title="", description="", codelist_values=None, use_openai=False):
    """Generate a description using OpenAI API or fallback to default description"""
    if use_openai:
        try:
            # Get OpenAI API key from environment
            openai_api_key = os.getenv('OPENAI_API_KEY')
            if not openai_api_key:
                # Fallback to default generation if no API key
                return generate_default_description(column, lang)
            
            # Set up OpenAI client
            client = openai.OpenAI(api_key=openai_api_key)
            
            # Build context for OpenAI
            context = f"Column name: {column['name']}\n"
            context += f"Data type: {column['type']}\n"
            context += f"Is codelist: {column['is_codelist']}\n"
            
            if title:
                context += f"Title: {title}\n"
            if description:
                context += f"Existing description: {description}\n"
            
            if column['is_codelist'] and codelist_values:
                context += f"Codelist values: {', '.join(str(v) for v in codelist_values[:10])}\n"
                if len(codelist_values) > 10:
                    context += f"... and {len(codelist_values) - 10} more values\n"
            
            if column.get('pattern'):
                context += f"Pattern: {column['pattern']}\n"
            
            # Create prompt based on language
            lang_prompts = {
                "de": "Generiere eine präzise, professionelle Beschreibung für dieses Datenkonzept auf Deutsch. Die Beschreibung sollte klar und informativ sein.",
                "en": "Generate a precise, professional description for this data concept in English. The description should be clear and informative.",
                "fr": "Générez une description précise et professionnelle pour ce concept de données en français. La description doit être claire et informative.",
                "it": "Genera una descrizione precisa e professionale per questo concetto di dati in italiano. La descrizione dovrebbe essere chiara e informativa."
            }
            
            prompt = lang_prompts.get(lang.lower(), lang_prompts["de"])
            prompt += "\n\nKontext:\n" + context
            prompt += "\n\nBeschreibung:"
            
            # Call OpenAI API
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that generates precise descriptions for data concepts in statistical and administrative contexts."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.3
            )
            
            generated_description = response.choices[0].message.content.strip()
            
            # Clean up the response
            if generated_description.startswith('"') and generated_description.endswith('"'):
                generated_description = generated_description[1:-1]
            
            return generated_description
            
        except Exception as e:
            print(f"OpenAI API error: {e}")
            # Fallback to default generation
            return generate_default_description(column, lang)
    else:
        # Use default description generation
        return generate_default_description(column, lang)

def generate_default_description(column, lang="de"):
    """Generate a default description based on column analysis"""
    if column['is_codelist']:
        if lang == "fr":
            description = f"Le concept {column['name']} contient une liste de codes"
            if column.get('unique_values') and len(column['unique_values']) > 0:
                examples = ', '.join(str(v) for v in column['unique_values'][:3])
                description += f". Les valeurs incluent: {examples}"
                if len(column['unique_values']) > 3:
                    description += "..."
        elif lang == "it":
            description = f"Il concetto {column['name']} contiene un elenco di codici"
            if column.get('unique_values') and len(column['unique_values']) > 0:
                examples = ', '.join(str(v) for v in column['unique_values'][:3])
                description += f". I valori includono: {examples}"
                if len(column['unique_values']) > 3:
                    description += "..."
        elif lang == "en":
            description = f"The concept {column['name']} contains a codelist"
            if column.get('unique_values') and len(column['unique_values']) > 0:
                examples = ', '.join(str(v) for v in column['unique_values'][:3])
                description += f". Values include: {examples}"
                if len(column['unique_values']) > 3:
                    description += "..."
        else:  # Default to German
            description = f"Das Konzept {column['name']} beinhaltet eine Codeliste"
            if column.get('unique_values') and len(column['unique_values']) > 0:
                examples = ', '.join(str(v) for v in column['unique_values'][:3])
                description += f". Darin sind folgende Werte verzeichnet: {examples}"
                if len(column['unique_values']) > 3:
                    description += "..."
    elif column['type'] == 'Date':
        if lang == "fr":
            description = f"Le concept {column['name']} contient des informations de date"
            if column.get('format'):
                description += f" au format {column['format']}"
        elif lang == "it":
            description = f"Il concetto {column['name']} contiene informazioni sulla data"
            if column.get('format'):
                description += f" nel formato {column['format']}"
        elif lang == "en":
            description = f"The concept {column['name']} contains date information"
            if column.get('format'):
                description += f" in format {column['format']}"
        else:  # Default to German
            description = f"Das Konzept {column['name']} enthält Datumsinformationen"
            if column.get('format'):
                description += f" im Format {column['format']}"
    elif column['type'] == 'Number':
        if lang == "fr":
            description = f"Le concept {column['name']} contient des valeurs numériques"
        elif lang == "it":
            description = f"Il concetto {column['name']} contiene valori numerici"
        elif lang == "en":
            description = f"The concept {column['name']} contains numeric values"
        else:  # Default to German
            description = f"Das Konzept {column['name']} enthält numerische Werte"
    else:
        if lang == "fr":
            description = f"Le concept {column['name']} contient des données textuelles"
        elif lang == "it":
            description = f"Il concetto {column['name']} contiene dati testuali"
        elif lang == "en":
            description = f"The concept {column['name']} contains text data"
        else:  # Default to German
            description = f"Das Konzept {column['name']} enthält Textdaten"
    
    if column.get('pattern'):
        if lang == "fr":
            description += f". Modèle: {column['pattern']}"
        elif lang == "it":
            description += f". Pattern: {column['pattern']}"
        elif lang == "en":
            description += f". Pattern: {column['pattern']}"
        else:  # Default to German
            description += f". Muster: {column['pattern']}"
    
    return description

def estimate_field_values(column):
    """Estimate field values based on column data for form pre-filling"""
    params = {}
    
    if column['type'] == 'Number' and not column['is_codelist']:
        # If we tracked min/max in analyze_column_type, we'd use those values
        # For now we'll use defaults
        params['min_value'] = 0
        params['max_value'] = 999
        params['decimals'] = 0
        params['unit'] = ""
    
    if column['type'] == 'String' and not column['is_codelist']:
        # If we had string length info in analyze_column_type
        params['max_length'] = 255
    
    if column['type'] == 'Date' and not column['is_codelist']:
        # Add date-specific parameters
        params['format'] = column.get('format', 'YYYY-MM-DD')
    
    if column.get('pattern'):
        params['pattern'] = column['pattern']
    
    return params

@app.route('/api/extract-keywords/<int:index>', methods=['POST'])
def extract_keywords(index):
    """Extract keywords from title and description using OpenAI API"""
    if 'session_data_id' not in session:
        return jsonify({'error': 'No results found. Please upload a file first.'}), 404
    
    session_data = load_session_data(session['session_data_id'])
    if not session_data:
        return jsonify({'error': 'Session expired. Please upload the file again.'}), 404
    
    if index < 0 or index >= len(session_data['columns']):
        return jsonify({'error': 'Invalid column index'}), 400
    
    column = session_data['columns'][index]
    
    # Get data from request
    data = request.get_json() or {}
    
    # Extract parameters
    title = data.get('title', '')
    description = data.get('description', '')
    lang = data.get('lang', 'de').lower()
    
    # Validate language is supported
    if lang not in ['de', 'en', 'fr', 'it']:
        lang = 'de'  # Default to German if unsupported language
    
    # Generate keywords using OpenAI
    try:
        # Get OpenAI API key from environment
        openai_api_key = os.getenv('OPENAI_API_KEY')
        if not openai_api_key:
            return jsonify({'error': 'OpenAI API key not configured'}), 500
        
        # Set up OpenAI client
        client = openai.OpenAI(api_key=openai_api_key)
        
        # Build context for OpenAI
        context = f"Column name: {column['name']}\n"
        context += f"Data type: {column['type']}\n"
        context += f"Is codelist: {column['is_codelist']}\n"
        
        if title:
            context += f"Title: {title}\n"
        if description:
            context += f"Description: {description}\n"
        
        # Create prompt based on language
        lang_prompts = {
            "de": "Extrahiere 3-7 relevante Keywords aus dem folgenden Kontext. Die Keywords sollten durch Kommas getrennt sein und für die statistische Datenbeschreibung relevant sein.",
            "en": "Extract 3-7 relevant keywords from the following context. The keywords should be separated by commas and relevant for statistical data description.",
            "fr": "Extrayez 3-7 mots-clés pertinents du contexte suivant. Les mots-clés doivent être séparés par des virgules et pertinents pour la description des données statistiques.",
            "it": "Estrai 3-7 parole chiave rilevanti dal seguente contesto. Le parole chiave dovrebbero essere separate da virgole e rilevanti per la descrizione dei dati statistici."
        }
        
        prompt = lang_prompts.get(lang, lang_prompts["de"])
        prompt += "\n\nKontext:\n" + context
        prompt += "\n\nKeywords:"
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that extracts relevant keywords for statistical data concepts. Return only the keywords separated by commas, no additional text."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=100,
            temperature=0.3
        )
        
        keywords_text = response.choices[0].message.content.strip()
        
        # Clean up the response - remove quotes if present
        if keywords_text.startswith('"') and keywords_text.endswith('"'):
            keywords_text = keywords_text[1:-1]
        elif keywords_text.startswith("'") and keywords_text.endswith("'"):
            keywords_text = keywords_text[1:-1]
        
        return jsonify({
            'keywords': keywords_text
        })
        
    except Exception as e:
        print(f"OpenAI keyword extraction error: {e}")
        # Fallback to simple keyword extraction
        return jsonify({
            'keywords': generate_fallback_keywords(title, description, lang)
        })

def generate_fallback_keywords(title, description, lang):
    """Generate fallback keywords when OpenAI is not available"""
    # Simple keyword extraction based on title and description
    text = f"{title} {description}".strip()
    
    if not text:
        return ""
    
    # Split into words and filter
    words = text.split()
    
    # Remove common stop words based on language
    stop_words = {
        'de': ['der', 'die', 'das', 'und', 'oder', 'mit', 'für', 'von', 'zu', 'im', 'am', 'auf', 'in', 'an', 'bei', 'nach', 'aus', 'über', 'unter', 'vor', 'hinter', 'neben', 'zwischen', 'durch', 'gegen', 'um', 'ohne', 'seit', 'bis', 'während', 'wegen', 'statt', 'trotz', 'obwohl', 'obgleich', 'wenn', 'falls', 'sofern', 'soweit', 'sobald', 'bevor', 'nachdem', 'seitdem', 'solange', 'während', 'als', 'wie', 'da', 'weil', 'denn', 'deshalb', 'darum', 'deswegen', 'also', 'folglich', 'somit', 'demnach', 'mithin', 'sondern', 'doch', 'jedoch', 'allerdings', 'hingegen', 'andererseits', 'im gegenteil', 'vielmehr', 'zwar', 'zwar...aber', 'entweder...oder', 'weder...noch', 'nicht nur...sondern auch', 'sowohl...als auch', 'teils...teils', 'halb...halb', 'bald...bald', 'mal...mal', 'einmal...einmal', 'bald...bald', 'teils...teils', 'halb...halb', 'bald...bald', 'mal...mal', 'einmal...einmal'],
        'en': ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'shall', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'her', 'its', 'our', 'their', 'what', 'which', 'who', 'when', 'where', 'why', 'how'],
        'fr': ['le', 'la', 'les', 'l\'', 'un', 'une', 'des', 'du', 'de', 'à', 'au', 'aux', 'en', 'dans', 'sur', 'sous', 'avec', 'sans', 'pour', 'par', 'chez', 'contre', 'entre', 'vers', 'depuis', 'pendant', 'avant', 'après', 'jusque', 'lorsque', 'quand', 'comme', 'si', 'que', 'qui', 'quoi', 'dont', 'où', 'd\'où', 'parce que', 'puisque', 'car', 'donc', 'or', 'ni', 'mais', 'et', 'ou', 'ne', 'pas', 'plus', 'très', 'trop', 'peu', 'beaucoup', 'assez', 'autant', 'tant', 'tellement', 'si', 'tel', 'telle', 'tels', 'telles', 'tout', 'toute', 'tous', 'toutes', 'chaque', 'chacun', 'chacune', 'aucun', 'aucune', 'nul', 'nulle', 'rien', 'personne', 'rien', 'autre', 'autres', 'même', 'mêmes', 'quel', 'quelle', 'quels', 'quelles', 'ce', 'cet', 'cette', 'ces', 'mon', 'ma', 'mes', 'ton', 'ta', 'tes', 'son', 'sa', 'ses', 'notre', 'nos', 'votre', 'vos', 'leur', 'leurs'],
        'it': ['il', 'lo', 'la', 'i', 'gli', 'le', 'un', 'uno', 'una', 'del', 'dello', 'della', 'dei', 'degli', 'delle', 'al', 'allo', 'alla', 'ai', 'agli', 'alle', 'dal', 'dallo', 'dalla', 'dai', 'dagli', 'dalle', 'nel', 'nello', 'nella', 'nei', 'negli', 'nelle', 'sul', 'sullo', 'sulla', 'sui', 'sugli', 'sulle', 'di', 'a', 'da', 'in', 'con', 'su', 'per', 'tra', 'fra', 'e', 'o', 'ma', 'se', 'che', 'chi', 'cosa', 'come', 'quando', 'dove', 'perché', 'perchè', 'quindi', 'allora', 'poi', 'dopo', 'prima', 'mentre', 'finché', 'finchè', 'appena', 'non', 'anche', 'solo', 'soltanto', 'pure', 'neppure', 'nemmeno', 'neanche', 'mai', 'sempre', 'spesso', 'raramente', 'talvolta', 'qualche', 'alcuni', 'alcune', 'tutti', 'tutte', 'ogni', 'ciascun', 'ciascuna', 'nessun', 'nessuna', 'nulla', 'nessuno', 'altro', 'altra', 'altri', 'altre', 'stesso', 'stessa', 'stessi', 'stesse', 'tale', 'tali', 'qual', 'quale', 'quali', 'questo', 'questa', 'questi', 'queste', 'quello', 'quella', 'quelli', 'quelle', 'mio', 'mia', 'miei', 'mie', 'tuo', 'tua', 'tuoi', 'tue', 'suo', 'sua', 'suoi', 'sue', 'nostro', 'nostra', 'nostri', 'nostre', 'vostro', 'vostra', 'vostri', 'vostre', 'loro']
    }
    
    stop_words_list = stop_words.get(lang, stop_words['de'])
    
    # Filter words: remove stop words, keep only alphanumeric words, limit length
    keywords = []
    for word in words:
        word_lower = word.lower().strip('.,!?;:')
        if (len(word_lower) > 2 and 
            word_lower not in stop_words_list and 
            word_lower.isalnum()):
            keywords.append(word_lower)
    
    # Remove duplicates and limit to 5 keywords
    unique_keywords = list(dict.fromkeys(keywords))[:5]
    
    return ', '.join(unique_keywords)

@app.route('/api/generate-description/<int:index>', methods=['POST'])
def generate_description(index):
    """Generate a description using OpenAI API"""
    if 'session_data_id' not in session:
        return jsonify({'error': 'No results found. Please upload a file first.'}), 404
    
    session_data = load_session_data(session['session_data_id'])
    if not session_data:
        return jsonify({'error': 'Session expired. Please upload the file again.'}), 404
    
    if index < 0 or index >= len(session_data['columns']):
        return jsonify({'error': 'Invalid column index'}), 400
    
    column = session_data['columns'][index]
    
    # Get data from request
    data = request.get_json() or {}
    
    # Extract parameters
    title = data.get('title', '')
    description = data.get('description', '')
    codelist_values = data.get('codelist_values')
    
    # Get the requested language, default to "de"
    lang = data.get('lang', 'de').lower()
    
    # Validate language is supported
    if lang not in ['de', 'en', 'fr', 'it']:
        lang = 'de'  # Default to German if unsupported language
    
    # Generate description using OpenAI (use_openai=True)
    generated_description = generate_concept_description(
        column, 
        lang=lang,
        title=title,
        description=description,
        codelist_values=codelist_values,
        use_openai=True
    )
    
    # Get suggested field values
    params = estimate_field_values(column)
    
    return jsonify({
        'description': generated_description,
        'params': params
    })

@app.route('/api/get-default-description/<int:index>', methods=['GET'])
def get_default_description(index):
    """Get a default description for a column (no OpenAI API call)"""
    if 'session_data_id' not in session:
        return jsonify({'error': 'No results found. Please upload a file first.'}), 404
    
    session_data = load_session_data(session['session_data_id'])
    if not session_data:
        return jsonify({'error': 'Session expired. Please upload the file again.'}), 404
    
    if index < 0 or index >= len(session_data['columns']):
        return jsonify({'error': 'Invalid column index'}), 400
    
    column = session_data['columns'][index]
    
    # Get the requested language, default to "de"
    lang = request.args.get('lang', 'de').lower()
    
    # Validate language is supported
    if lang not in ['de', 'en', 'fr', 'it']:
        lang = 'de'  # Default to German if unsupported language
    
    # Generate default description (use_openai=False)
    default_description = generate_concept_description(
        column, 
        lang=lang,
        use_openai=False
    )
    
    return jsonify({
        'description': default_description
    })

@app.route('/api/create-concept/<int:index>', methods=['POST'])
def create_concept(index):
    """Translate title and description texts - DO NOT CREATE CONCEPTS"""
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    title = data.get('title', '')
    description = data.get('description', '')
    
    # Import translator only when needed to avoid automatic translations during loading
    from utils.translator import create_multilingual_text
    
    title_translations = create_multilingual_text(title)
    desc_translations = create_multilingual_text(description)
    
    return jsonify({
        'title': title_translations,
        'description': desc_translations
    })

@app.route('/api/submit-concept', methods=['POST'])
def submit_concept():
    """Submit a concept to the I14Y API - now handles both concept creation and submission"""
    # Get data from the request
    data = request.json
    
    # Get token from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 400
    
    # If this is form data rather than a concept JSON
    if data and 'index' in data:
        if 'session_data_id' not in session:
            return jsonify({'error': 'No session found. Please upload a file first.'}), 404
        
        session_data = load_session_data(session['session_data_id'])
        if not session_data:
            return jsonify({'error': 'Session expired. Please upload the file again.'}), 404
        
        index = data.get('index')
        if index < 0 or index >= len(session_data['columns']):
            return jsonify({'error': 'Invalid column index'}), 400
        
        column = session_data['columns'][index]
        
        # If column already has a concept GUID, return it immediately
        if 'concept_guid' in column:
            return jsonify({
                'success': True,
                'status': 200,
                'message': f"Concept for {column['name']} already exists",
                'conflict': True,
                'location': f"/api/partner/v1/concepts/{column['concept_guid']}"
            })
        
        # Before generating a new concept, check if we've recently tried to create this exact same concept
        # Use a simple cache to avoid duplicate submissions in quick succession
        concept_cache_key = f"{session['session_data_id']}_{data.get('index')}"
        last_attempt_time = getattr(app, '_concept_submission_cache', {}).get(concept_cache_key)
        
        # If we've tried to create this concept in the last 30 seconds, return the cached response
        if last_attempt_time and (datetime.now() - last_attempt_time).total_seconds() < 30:
            return jsonify({
                'success': True,
                'status': 200,
                'message': 'Duplicate request prevented. The previous request is still being processed.'
            })
            
        # Record this attempt in the cache
        if not hasattr(app, '_concept_submission_cache'):
            app._concept_submission_cache = {}
        app._concept_submission_cache[concept_cache_key] = datetime.now()
        
        # Get form data
        form_data = session_data['form_data']
        description = data.get('description', '')
        
        # Extract additional params for the concept
        params = {
            'min_value': data.get('min_value'),
            'max_value': data.get('max_value'),
            'decimals': data.get('decimals'),
            'unit': data.get('unit'),
            'pattern': data.get('pattern'),
            'max_length': data.get('max_length'),
            'format': data.get('format')
        }
        
        # Check if translations were provided
        translations = data.get('translations')
        
        # Get keywords from the request
        keywords = data.get('keywords', '')
        
        # Generate the concept JSON
        concept = generate_concept_json(
            column, 
            form_data, 
            description, 
            params, 
            translations, 
            session_data.get('dataset_metadata'),
            keywords
        )
        
        # Validate the generated concept
        issues = []
        required_fields = ['conceptType', 'description', 'identifier', 'name']
        for field in required_fields:
            if field not in concept['data']:
                issues.append(f'Missing required field: {field}')
        
        if issues:
            return jsonify({
                'success': False,
                'status': 400,
                'message': f"Validation error: {', '.join(issues)}",
                'issues': issues
            }), 400
        
    else:
        # If direct concept JSON was provided (backward compatibility)
        concept = data
        index = None
    
    # Make the request to the I14Y API
    url = 'https://api.i14y.admin.ch/api/partner/v1/concepts'
    headers = {
        'accept': 'text/plain',
        'Authorization': auth_header,
        'Content-Type': 'application/json'
    }
    
    try:
        # Make the actual API call
        response = requests.post(url, headers=headers, json=concept)
        
        # Handle 409 Conflict (already exists) as a SUCCESS case
        if response.status_code == 409:
            # Try to get the existing concept's details
            concept_id = concept.get('data', {}).get('identifier', '')
            if concept_id:
                try:
                    # Try to fetch the existing concept to provide more details
                    get_url = f'https://api.i14y.admin.ch/api/partner/v1/concepts/{concept_id}'
                    get_response = requests.get(get_url, headers={
                        'accept': 'text/plain',
                        'Authorization': auth_header
                    })
                    if get_response.ok:
                        existing_concept = get_response.json()
                        
                        # Extract GUID from existing concept if available
                        concept_guid = None
                        if 'id' in existing_concept:
                            concept_guid = existing_concept['id']
                        
                        # Generate I14Y web interface URL
                        i14y_url = None
                        if concept_guid:
                            i14y_url = f"https://input.i14y.admin.ch/catalog/concepts/{concept_guid}"
                        
                        return jsonify({
                            'success': True,
                            'status': 200,  # Return 200 OK instead of 409 since this is expected
                            'message': f'Concept "{concept_id}" already exists in I14Y and will be used',
                            'conflict': True,
                            'existing_concept': existing_concept,
                            'i14y_url': i14y_url
                        })
                except Exception:
                    pass
            # Default conflict response if we couldn't get details
            return jsonify({
                'success': True,
                'status': 200,  # Return 200 OK instead of 409
                'message': 'Concept already exists in I14Y and will be used',
                'conflict': True
            })
        
        # For successful creation (201 Created)
        elif response.status_code == 201:
            location = response.headers.get('Location')
            concept_guid = None
            i14y_url = None
            
            # If we have an index, store the concept GUID in the column
            if location:
                location_parts = location.split('/')
                concept_guid = location_parts[-1]
                
                # Generate I14Y web interface URL
                i14y_url = f"https://input.i14y.admin.ch/catalog/concepts/{concept_guid}"
                
                # Update the column in session data if we have an index
                if index is not None and 'session_data_id' in session:
                    session_data = load_session_data(session['session_data_id'])
                    if session_data:
                        session_data['columns'][index]['concept_guid'] = concept_guid
                        save_session_data(session_data)
            
            return jsonify({
                'success': True,
                'status': response.status_code,
                'message': 'Concept successfully created. ',
                'location': location,
                'concept_guid': concept_guid,
                'i14y_url': i14y_url
            })
        
        # For other successful responses
        elif response.status_code < 400:
            return jsonify({
                'success': True,
                'status': response.status_code,
                'message': response.text
            })
        
        # Handle error responses
        else:
            error_message = "Unknown error"
            try:
                # Try to parse the error response as JSON
                error_data = response.json()
                if isinstance(error_data, dict):
                    error_message = error_data.get('message', error_data.get('error', response.text))
                    if 'title' in error_data and 'detail' in error_data:
                        error_message = f"{error_data.get('title')}: {error_data.get('detail')}"
                    elif isinstance(error_data, dict):
                        error_message = error_data.get('message', error_data.get('error', response.text))
                    else:
                        error_message = str(error_data)
            except Exception:
                error_message = response.text
            return jsonify({
                'success': False,
                'status': response.status_code,
                'message': error_message
            }), response.status_code
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'status': 500,
            'message': f"Exception during submission: {str(e)}"
        }), 500

@app.route('/api/add-codelist-entries/<concept_guid>', methods=['POST'])
def add_codelist_entries(concept_guid):
    """Add codelist entries to an existing concept"""
    # Get the payload from the request
    payload = request.json
    
    # Get token from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid Authorization header'}), 400
    
    if not concept_guid:
        return jsonify({'error': 'Missing concept GUID'}), 400
    
    if not payload or 'data' not in payload or not isinstance(payload['data'], list):
        return jsonify({'error': 'Invalid payload format'}), 400
    
    # Translate monolingual labels if needed
    try:
        from utils.translator import create_multilingual_text
        
        # Check if we need to perform translations
        needs_translation = False
        for entry in payload['data']:
            # If 'name' exists and is a string (monolingual) instead of an object (multilingual)
            if 'name' in entry and isinstance(entry['name'], str):
                needs_translation = True
                break
                
        if needs_translation:
            translated_entries = []
            
            for entry in payload['data']:
                translated_entry = entry.copy()  # Create a copy to modify
                
                # Translate the name if it's a string
                if 'name' in entry and isinstance(entry['name'], str):
                    label = entry['name']
                    
                    try:
                        # Detect the source language instead of assuming DE
                        source_lang = detect_language(label)
                        
                        # Create translations for all required languages
                        translated_labels = create_multilingual_text(label, source_lang)
                        translated_entry['name'] = translated_labels
                    except Exception:
                        # Fall back to simple multilingual with the same text for all languages
                        translated_entry['name'] = simple_multilingual(label)
                
                translated_entries.append(translated_entry)
            
            # Replace the original entries with translated ones
            payload['data'] = translated_entries
    except ImportError:
        pass
    except Exception:
        import traceback
        traceback.print_exc()
    
    # Make the request to the I14Y API
    url = f'https://api.i14y.admin.ch/api/partner/v1/concepts/{concept_guid}/codelist-entries/imports/json'
    headers = {
        'accept': '*/*',
        'Authorization': auth_header
    }
    
    try:
        import tempfile
        import json
        # Create a temporary file with the JSON payload
        with tempfile.NamedTemporaryFile(suffix='.json', mode='w+', delete=False) as temp_file:
            json.dump(payload, temp_file, ensure_ascii=False)
            temp_path = temp_file.name
        
        # Open the file in binary mode for the request
        with open(temp_path, 'rb') as f:
            files = {'file': ('payload.json', f, 'application/json')}
            # Make the actual API call
            response = requests.post(url, headers=headers, files=files)
        
        # Delete the temporary file
        import os
        os.unlink(temp_path)
        
        # Check for errors
        if response.status_code >= 400:
            error_message = "Unknown error"
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    error_message = error_data.get('message', error_data.get('error', response.text))
                else:
                    error_message = str(error_data)
            except:
                error_message = response.text
            
            return jsonify({
                'success': False,
                'message': f"API error: {error_message}",
                'status': response.status_code
            }), response.status_code
        
        # Return success
        translated = "with automatic translation" if needs_translation else ""
        return jsonify({
            'success': True,
            'message': f"Successfully added {len(payload['data'])} codelist entries {translated}",
            'status': response.status_code
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.before_request
def cleanup_old_sessions():
    """Clean up session files older than 1 hour"""
    # Only run cleanup occasionally (e.g., 1% of requests)
    import random
    if random.random() > 0.01:
        return
    
    import time
    current_time = time.time()
    one_hour_ago = current_time - 3600  # 1 hour in seconds
    
    for filename in os.listdir(SESSION_DATA_DIR):
        if filename.endswith('.pkl'):
            file_path = os.path.join(SESSION_DATA_DIR, filename)
            # Check if file is older than 1 hour
            if os.path.getmtime(file_path) < one_hour_ago:
                try:
                    os.remove(file_path)
                except:
                    pass  # Ignore errors during cleanup

# Add this function to generate codes
def generate_code_for_value(value, code_length=2, existing_codes=None, known_mappings=None):
    """Generate a meaningful code for a given value."""
    if not existing_codes:
        existing_codes = set()
    
    if not known_mappings:
        known_mappings = {}
    
    # If we already have a known mapping for this value, use it
    if value in known_mappings:
        code = known_mappings[value]
        if len(code) > code_length:
            code = code[:code_length]
        
        if code not in existing_codes:
            return code
    
    # Normalize the value: convert to uppercase, remove accents, remove special chars
    # This helps with non-ASCII characters like ü, é, etc.
    normalized = unicodedata.normalize('NFKD', str(value))
    normalized = ''.join([c for c in normalized if not unicodedata.combining(c)])
    normalized = normalized.upper()
    normalized = ''.join([c for c in normalized if c.isalnum() or c.isspace()])
    
    # Method 1: For short values, use the whole value if it fits
    if len(normalized) <= code_length and not normalized.isdigit():
        code = normalized
        if code not in existing_codes:
            return code
    
    # Method 2: For multi-word values, use initials
    words = normalized.split()
    if len(words) >= 2:
        initials = ''.join([word[0] for word in words])
        if len(initials) <= code_length:
            if initials not in existing_codes:
                return initials
            
            # Try to use first 2 letters from first word and first letter from others
            if len(words[0]) >= 2:
                extended_initials = words[0][:2] + ''.join([word[0] for word in words[1:]])
                if len(extended_initials) <= code_length:
                    if extended_initials not in existing_codes:
                        return extended_initials
    
    # Method 3: Take first n letters
    if len(normalized) > code_length:
        prefix = normalized.replace(' ', '')[:code_length]
        if prefix not in existing_codes:
            return prefix
    
    # Method 4: For numeric values, pad with zeros
    if normalized.isdigit():
        numeric_code = normalized.zfill(code_length)[:code_length]
        if numeric_code not in existing_codes:
            return numeric_code
    
    # Method 5: Add numbers to disambiguate
    base_code = normalized.replace(' ', '')[:code_length-1] if len(normalized) >= code_length else normalized.replace(' ', '')
    for i in range(1, 10):  # Try adding 1-9 to the end
        suffix_code = (base_code + str(i))[:code_length]
        if suffix_code not in existing_codes:
            return suffix_code
    
    # Last resort: generate a random code
    import random
    letters = string.ascii_uppercase
    while True:
        random_code = ''.join(random.choice(letters) for _ in range(code_length))
        if random_code not in existing_codes:
            return random_code

def get_known_code_mappings():
    """Return known code mappings for common entities."""
    # Country codes (ISO 3166-1 alpha-2)
    countries = {
        "Schweiz": "CH", "Switzerland": "CH", "Suisse": "CH", "Svizzera": "CH",
        "Deutschland": "DE", "Germany": "DE", "Allemagne": "DE", "Germania": "DE",
        "Österreich": "AT", "Austria": "AT", "Autriche": "AT", "Austria": "AT",
        "Frankreich": "FR", "France": "FR", "Francia": "FR",
        "Italien": "IT", "Italy": "IT", "Italie": "IT", "Italia": "IT",
        "Vereinigte Staaten": "US", "United States": "US", "États-Unis": "US", "Stati Uniti": "US",
        "Vereinigtes Königreich": "GB", "United Kingdom": "GB", "Royaume-Uni": "GB", "Regno Unito": "GB",
        "Spanien": "ES", "Spain": "ES", "Espagne": "ES", "Spagna": "ES",
        "Niederlande": "NL", "Netherlands": "NL", "Pays-Bas": "NL", "Paesi Bassi": "NL",
        "Belgien": "BE", "Belgium": "BE", "Belgique": "BE", "Belgio": "BE",
        "Schweden": "SE", "Sweden": "SE", "Suède": "SE", "Svezia": "SE",
        "Norwegen": "NO", "Norway": "NO", "Norvège": "NO", "Norvegia": "NO",
        "Dänemark": "DK", "Denmark": "DK", "Danemark": "DK", "Danimarca": "DK",
        "Finnland": "FI", "Finland": "FI", "Finlande": "FI", "Finlandia": "FI",
        "Portugal": "PT", "Portogallo": "PT",
        "Griechenland": "GR", "Greece": "GR", "Grèce": "GR", "Grecia": "GR",
        "Polen": "PL", "Poland": "PL", "Pologne": "PL",
        "Tschechien": "CZ", "Czech Republic": "CZ", "République tchèque": "CZ", "Repubblica Ceca": "CZ",
        "Ungarn": "HU", "Hungary": "HU", "Hongrie": "HU", "Ungheria": "HU",
        "Russland": "RU", "Russia": "RU", "Russie": "RU", "Russia": "RU",
        "China": "CN", "Chine": "CN", "Cina": "CN",
        "Japan": "JP", "Japon": "JP", "Giapponese": "JP",
        "Indien": "IN", "India": "IN", "Inde": "IN", "India": "IN",
        "Brasilien": "BR", "Brazil": "BR", "Brésil": "BR", "Brasile": "BR",
        "Australien": "AU", "Australia": "AU", "Australie": "AU", "Australia": "AU",
        "Kanada": "CA", "Canada": "CA", "Canada": "CA", "Canada": "CA",
    }
    
    # Language codes (ISO 639-1)
    languages = {
        "Deutsch": "DE", "German": "DE", "Allemand": "DE", "Tedesco": "DE",
        "Englisch": "EN", "English": "EN", "Anglais": "EN", "Inglese": "EN",
        "Französisch": "FR", "French": "FR", "Français": "FR", "Francese": "FR",
        "Italienisch": "IT", "Italian": "IT", "Italien": "IT", "Italiano": "IT",
        "Spanisch": "ES", "Spanish": "ES", "Espagnol": "ES", "Spagnolo": "ES",
        "Portugiesisch": "PT", "Portuguese": "PT", "Portugais": "PT", "Portoghese": "PT",
        "Russisch": "RU", "Russian": "RU", "Russe": "RU", "Russo": "RU",
        "Chinesisch": "ZH", "Chinese": "ZH", "Chinois": "ZH", "Cinese": "ZH",
        "Japanisch": "JA", "Japanese": "JA", "Japonais": "JA", "Giapponese": "JA",
        "Arabisch": "AR", "Arabic": "AR", "Arabe": "AR", "Arabo": "AR"
    }
    
    # Days of the week
    days = {
        "Montag": "MO", "Monday": "MO", "Lundi": "MO", "Lunedì": "MO",
        "Dienstag": "TU", "Tuesday": "TU", "Mardi": "TU", "Martedì": "TU",
        "Mittwoch": "WE", "Wednesday": "WE", "Mercredi": "WE", "Mercoledì": "WE",
        "Donnerstag": "TH", "Thursday": "TH", "Jeudi": "TH", "Giovedì": "TH",
        "Freitag": "FR", "Friday": "FR", "Vendredi": "FR", "Venerdì": "FR",
        "Samstag": "SA", "Saturday": "SA", "Samedi": "SA", "Sabato": "SA",
        "Sonntag": "SU", "Sunday": "SU", "Dimanche": "SU", "Domenica": "SU"
    }
    
    # Months
    months = {
        "Januar": "01", "January": "01", "Janvier": "01", "Gennaio": "01",
        "Februar": "02", "February": "02", "Février": "02", "Febbraio": "02",
        "März": "03", "March": "03", "Mars": "03", "Marzo": "03",
        "April": "04", "Avril": "04", "Aprile": "04",
        "Mai": "05", "May": "05", "Mag": "05", "Maggio": "05",
        "Juni": "06", "June": "06", "Juin": "06", "Giugno": "06",
        "Juli": "07", "July": "07", "Juillet": "07", "Luglio": "07",
        "August": "08", "Août": "08", "Agosto": "08",
        "September": "09", "Septembre": "09", "Settembre": "09",
        "Oktober": "10", "October": "10", "Octobre": "10", "Ottobre": "10",
        "November": "11", "Novembre": "11",
        "Dezember": "12", "December": "12", "Décembre": "12", "Dicembre": "12"
    }
    
    # Boolean values
    boolean = {
        "Ja": "Y", "Yes": "Y", "Oui": "Y", "Si": "Y",
        "Nein": "N", "No": "N", "Non": "N",
        "Wahr": "T", "True": "T", "Vrai": "T", "Vero": "T", 
        "Falsch": "F", "False": "F", "Faux": "F", "Falso": "F"
    }
    
    # Common units
    units = {
        "Meter": "M", "Metre": "M", "Mètre": "M", "Metro": "M",
        "Kilometer": "KM", "Kilometre": "KM", "Kilomètre": "KM", "Chilometro": "KM",
        "Zentimeter": "CM", "Centimeter": "CM", "Centimètre": "CM", "Centimetro": "CM",
        "Millimeter": "MM", "Millimetre": "MM", "Millimètre": "MM", "Millilitro": "MM",
        "Kilogramm": "KG", "Kilogram": "KG", "Kilogramme": "KG", "Chilogrammo": "KG",
        "Gramm": "G", "Gram": "G", "Gramme": "G", "Grammo": "G",
        "Liter": "L", "Litre": "L", "Litre": "L", "Litro": "L",
        "Milliliter": "ML", "Millilitre": "ML", "Millilitre": "ML", "Millilitro": "ML",
        "Stunde": "H", "Hour": "H", "Heure": "H", "Ora": "H",
        "Minute": "MIN", "Minute": "MIN", "Minuto": "MIN",
        "Sekunde": "SEC", "Second": "SEC", "Seconde": "SEC", "Secondo": "SEC",
        "Prozent": "%", "Percent": "%", "Pour cent": "%", "Percento": "%"
    }
    
    # Combine all mappings
    combined = {}
    combined.update(countries)
    combined.update(languages)
    combined.update(days)
    combined.update(months)
    combined.update(boolean)
    combined.update(units)
    
    return combined

def determine_value_type(values):
    """Try to determine what kind of values we're dealing with."""
    if not values:
        return "unknown"
    
    # Check if all values are countries
    known_mappings = get_known_code_mappings()
    countries = {k: v for k, v in known_mappings.items() if len(v) == 2 and v.isalpha() and v.isupper()}
    country_matches = sum(1 for v in values if v in countries)
    if country_matches > len(values) * 0.5:  # If more than half are countries
        return "countries"
    
    # Check if all values are languages
    language_match_prefixes = ["sprach", "language", "tongue", "idioma", "lingua"]
    if any(any(prefix in str(v).lower() for prefix in language_match_prefixes) for v in values):
        return "languages"
    
    # Check if we're dealing with days of the week
    days = ["montag", "dienstag", "mittwoch", "donnerstag", "freitag", "samstag", "sonntag",
            "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    day_matches = sum(1 for v in values if str(v).lower() in days)
    if day_matches > 0 and day_matches == len(values):
        return "days"
    
    # Check if we're dealing with months
    months = ["januar", "februar", "märz", "april", "mai", "juni", "juli", "august", "september", "oktober", "november", "dezember",
              "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"]
    month_matches = sum(1 for v in values if str(v).lower() in months)
    if month_matches > 0 and month_matches == len(values):
        return "months"
    
    # Check if we're dealing with boolean values
    boolean_values = ["ja", "nein", "yes", "no", "true", "false", "wahr", "falsch"]
    boolean_matches = sum(1 for v in values if str(v).lower() in boolean_values)
    if boolean_matches > 0 and boolean_matches == len(values):
        return "boolean"
    
    # Check if numeric values
    if all(str(v).isdigit() for v in values):
        return "numeric"
    
    # Default to "text"
    return "text"

@app.route('/api/generate-codes/<int:index>', methods=['POST'])
def generate_codes(index):
    """Generate codes for codelist values"""
    if 'session_data_id' not in session:
        return jsonify({'error': 'No session found. Please upload a file first.'}), 404
    
    session_data = load_session_data(session['session_data_id'])
    if not session_data:
        return jsonify({'error': 'Session expired. Please upload the file again.'}), 404
    
    if index < 0 or index >= len(session_data['columns']):
        return jsonify({'error': 'Invalid column index'}), 400
    
    column = session_data['columns'][index]
    
    if not column['is_codelist']:
        return jsonify({'error': 'This column is not a codelist'}), 400
    
    data = request.json
    code_length = data.get('codeLength', 2)
    
    if code_length < 1 or code_length > 10:
        return jsonify({'error': 'Code length must be between 1 and 10'}), 400
    
    # Get the unique values
    values = column.get('unique_values', [])
    
    if not values:
        return jsonify({'error': 'No values found in this column'}), 400
    
    # Try to determine what kind of values we're dealing with
    value_type = determine_value_type(values)
    
    # Get known mappings
    known_mappings = get_known_code_mappings()
    
    # Generate codes for each value
    generated_codes = []
    existing_codes = set()
    
    for value in values:
        code = generate_code_for_value(
            value, 
            code_length=code_length, 
            existing_codes=existing_codes,
            known_mappings=known_mappings
        )
        existing_codes.add(code)
        
        generated_codes.append({
            'value': value,
            'code': code
        })
    
    return jsonify({
        'success': True,
        'codes': generated_codes,
        'valueType': value_type
    })

@app.route('/api/translate', methods=['POST'])
def translate_text():
    """API endpoint to translate text using DeepL"""
    try:
        # Check if content type is JSON
        if not request.is_json:
            return jsonify({
                'success': False, 
                'error': f'Invalid content type. Expected application/json, got {request.content_type}'
            }), 400
        
        # Parse JSON safely
        try:
            data = request.get_json()
        except Exception as json_error:
            return jsonify({
                'success': False, 
                'error': f'Invalid JSON format: {str(json_error)}'
            }), 400
        
        # Validate request data
        if not data:
            return jsonify({'success': False, 'error': 'Empty request data'}), 400
            
        # Check for different possible formats
        response_data = {'success': True}
        
        # Import translator only when needed
        try:
            from utils.translator import create_multilingual_text
        except ImportError as e:
            return jsonify({'success': False, 'error': f'Translator module not available: {str(e)}'}), 500
            
        source_lang = data.get('source_lang', 'DE')
        
        # Process 'text' field if present
        if 'text' in data:
            text = data.get('text', '')
            if text and text.strip():
                try:
                    # Detect language if not provided
                    if not source_lang or source_lang == 'auto':
                        source_lang = detect_language(text)
                        
                    translations = create_multilingual_text(text, source_lang)
                    response_data['translations'] = translations
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    return jsonify({
                        'success': False,
                        'error': f'Translation failed: {str(e)}'
                    }), 500
        
        # Process 'title' field if present            
        if 'title' in data:
            title = data.get('title', '')
            if title and title.strip():
                try:
                    # Detect language if not provided
                    if not source_lang or source_lang == 'auto':
                        source_lang = detect_language(title)
                        
                    title_translations = create_multilingual_text(title, source_lang)
                    if 'title' not in response_data:
                        response_data['title'] = title_translations
                except Exception:
                    pass
        
        # Process 'description' field if present
        if 'description' in data:
            description = data.get('description', '')
            if description and description.strip():
                try:
                    # Detect language if not provided
                    if not source_lang or source_lang == 'auto':
                        source_lang = detect_language(description)
                        
                    desc_translations = create_multilingual_text(description, source_lang)
                    if 'description' not in response_data:
                        response_data['description'] = desc_translations
                except Exception:
                    pass
        
        # Process 'keywords' field if present
        if 'keywords' in data:
            keywords = data.get('keywords', '')
            if keywords and keywords.strip():
                try:
                    # Detect language if not provided
                    if not source_lang or source_lang == 'auto':
                        source_lang = detect_language(keywords)
                        
                    keywords_translations = create_multilingual_text(keywords, source_lang)
                    if 'keywords' not in response_data:
                        response_data['keywords'] = keywords_translations
                except Exception:
                    pass
        
        # If none of the expected fields were processed
        if len(response_data) <= 1:  # Only has 'success' key
            fields = list(data.keys())
            return jsonify({
                'success': False, 
                'error': f'No valid text fields to translate. Available fields: {fields}'
            }), 400
            
        return jsonify(response_data)
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Translation failed: {str(e)}'
        }), 500

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Verify token and return associated agencies"""
    data = request.json
    if not data or 'token' not in data:
        return jsonify({'success': False, 'error': 'Token is required'}), 400
    
    token = data['token']
    
    # Extract user email from token if possible
    user_email = None
    try:
        # JWT tokens are in format: header.payload.signature
        # We only need the payload part
        token_parts = token.split('.')
        if len(token_parts) >= 2:
            # Decode the payload part (second part of the token)
            # Add padding if needed
            payload = token_parts[1]
            payload += '=' * ((4 - len(payload) % 4) % 4)  # Add padding
            decoded_payload = base64.b64decode(payload).decode('utf-8')
            payload_data = json.loads(decoded_payload)
            
            # Extract email - it could be in different fields depending on the token issuer
            user_email = payload_data.get('email', payload_data.get('upn', payload_data.get('preferred_username')))
    except Exception:
        # If token decoding fails, just continue without the email
        pass
    
    # Fetch agencies for this user
    agencies = fetch_user_agencies(token)
    
    if not agencies:
        return jsonify({
            'success': False, 
            'error': 'Could not fetch any agencies with the provided token. Please verify your token is correct.'
        }), 400
    
    # Return the agencies and the extracted email
    return jsonify({
        'success': True,
        'agencies': agencies,
        'user_email': user_email  # Include the email in the response
    })

if __name__ == '__main__':
    app.run(debug=True)