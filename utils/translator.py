import requests
import config

def create_multilingual_text(text, source_lang='DE'):
    """
    Create a multilingual object with translations in all required languages.
    
    Args:
        text (str): The text to translate
        source_lang (str): The source language code (default: DE)
    
    Returns:
        dict: Dictionary with translations for all required languages
    """
    # Initialize with empty strings - only fill with actual translations
    result = {
        "de": "",
        "en": "",
        "fr": "",
        "it": "",
        "rm": ""  # Romansh - usually not translated but included for completeness
    }
    
    # Skip empty text
    if not text or not text.strip():
        return result
    
    # Set the source language with the original text
    source_key = source_lang.lower()
    if source_key in result:
        result[source_key] = text
        
    # Skip if no API key
    if not hasattr(config, 'DEEPL_API_KEY') or not config.DEEPL_API_KEY:
        # Return only the source language filled
        return result
    
    # Target languages (we'll translate to all except the source)
    target_langs = ['DE', 'EN', 'FR', 'IT']
    target_langs = [lang for lang in target_langs if lang != source_lang]
    
    try:
        # DeepL API URL
        url = "https://api-free.deepl.com/v2/translate"
        
        # Translate to each target language
        for target_lang in target_langs:
            # Prepare headers with authentication
            headers = {
                'Authorization': f'DeepL-Auth-Key {config.DEEPL_API_KEY}'
            }
            
            # Prepare request data (no auth_key in body anymore)
            data = {
                'text': text,
                'source_lang': source_lang,
                'target_lang': target_lang
            }
            
            # Make request with header-based authentication
            response = requests.post(url, headers=headers, data=data)
            
            # Parse response if successful
            if response.status_code == 200:
                data = response.json()
                if 'translations' in data and len(data['translations']) > 0:
                    translated_text = data['translations'][0]['text']
                    result[target_lang.lower()] = translated_text
                else:
                    print(f"No translations in response for {target_lang}: {data}")
            else:
                print(f"Translation API error for {target_lang}: {response.status_code} - {response.text}")
    
    except Exception as e:
        # If translation fails, log the error
        print(f"Translation error: {e}")
        import traceback
        traceback.print_exc()
    
    return result
