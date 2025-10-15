# I14Y AutoImport

A web tool to help describe and publish metadata for existing datasets by guiding users through importing column information to the I14Y platform. Supports both Excel (.xlsx) and CSV (.csv) files.

## Overview

I14Y AutoImport analyzes Excel and CSV files, automatically detects column types, patterns, and codelists, then guides users through publishing these concepts to the I14Y platform. The tool streamlines metadata management for data catalog entries.

**AI-Powered Description Generation**:  
Optionally, users can leverage AI to automatically generate dataset descriptions. This feature uses OpenAI's language models to create summaries based on the dataset's content and structure.

**Keyword Extraction**:  
The tool automatically extracts keywords from the dataset by analyzing column names, detected patterns, and frequently occurring values. These keywords help improve discoverability and metadata quality.

## Features

- **Excel & CSV Support**: Upload and process both Excel (.xlsx) and CSV (.csv) files
- **Automatic Data Analysis**: Detects column types, patterns, and codelists from uploaded files
- **Smart Type Detection**: Identifies dates, numbers, text fields, and codelists with appropriate patterns
- **Multilingual Support**: Facilitates translation into German, French, Italian, and English
- **Codelist Generation**: Automatically generates standardized codes for codelist values
- **I14Y Integration**: Direct publishing to I14Y using API tokens
- **Step-by-Step Wizard**: User-friendly interface guides through the entire process
- **AI Description Generation**: Uses OpenAI to generate dataset descriptions on demand
- **Automatic Keyword Extraction**: Extracts relevant keywords from dataset structure and content

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions on deploying to DigitalOcean App Platform.

## Local Development

### Prerequisites
- Python 3.8 or higher
- DeepL API key (from https://www.deepl.com/pro-api)

### Setup

1. Clone the repository
```bash
git clone https://github.com/I14Y-ch/concept_import.git
cd concept-import
```

2. Create and activate a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages
```bash
pip install -r requirements.txt
```

4. Configure environment variables
```bash
cp .env.example .env
# Edit .env and add your actual credentials:
# - DEEPL_API_KEY: Your DeepL API key
# - FLASK_SECRET_KEY: Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
```

5. Run the application
```bash
python run.py
```

6. Open your browser and navigate to http://127.0.0.1:5000

## Usage Guide

1. **Obtain I14Y API Token** from the I14Y platform
2. **Enter API Token** in the first screen
3. **Select Your Organization** if you're associated with multiple agencies
4. **Upload Data File**: Choose either Excel (.xlsx) or CSV (.csv) format
5. **Review Column Analysis** results
6. **Enrich Concepts** for each column:
   - Edit generated descriptions
   - Translate to required languages
   - Generate and refine codes for codelists
7. **Publish** the concepts to I14Y

## Supported File Formats

- **Excel (.xlsx)**: All sheets and columns are analyzed
- **CSV (.csv)**: All columns are analyzed; ensure proper delimiter and encoding

## Column Type Detection

The system automatically detects:
- Dates (with format detection)
- Numbers (with pattern detection)
- Text fields
- Codelists (with automated code generation)

For columns identified as codelists, the system provides:
- Automated generation of standardized codes
- Smart recognition of common entities (countries, languages, dates)
- Translation of codelist labels into all supported languages