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
    # Always include the original text in all languages as fallback
    result = {
        "de": text,
        "en": text,
        "fr": text,
        "it": text,
        "rm": text  # Romansh - usually not translated but included for completeness
    }
    
    # Skip empty text
    if not text or not text.strip():
        return result
        
    # Skip if no API key
    if not hasattr(config, 'DEEPL_API_KEY') or not config.DEEPL_API_KEY:
        return result
    
    # Target languages (we'll translate to all except the source)
    target_langs = ['DE', 'EN', 'FR', 'IT']
    target_langs = [lang for lang in target_langs if lang != source_lang]
    
    # Set the correct language in the source slot
    source_key = source_lang.lower()
    if source_key in result:
        result[source_key] = text
    
    try:
        # DeepL API URL
        url = "https://api-free.deepl.com/v2/translate"
        
        # Translate to each target language
        for target_lang in target_langs:
            # Prepare request
            params = {
                'auth_key': config.DEEPL_API_KEY,
                'text': text,
                'source_lang': source_lang,
                'target_lang': target_lang
            }
            
            # Make request
            response = requests.post(url, data=params)
            
            # Parse response if successful
            if response.status_code == 200:
                data = response.json()
                if 'translations' in data and len(data['translations']) > 0:
                    translated_text = data['translations'][0]['text']
                    result[target_lang.lower()] = translated_text
    
    except Exception as e:
        # If translation fails, we still have the original text as fallback
        print(f"Translation error: {e}")
    
    return result
