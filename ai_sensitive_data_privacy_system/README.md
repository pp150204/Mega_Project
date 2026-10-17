# PrivacyGuard AI — Sensitive Data Detection & Privacy Classification

A Python/Streamlit prototype that scans text or documents for possible sensitive data, assigns an example privacy classification, and produces a redacted copy.

## Features

- Detects email addresses, phone-like numbers, Aadhaar-like and PAN-like patterns, long card-like number sequences, and password/API-key assignments.
- Optional spaCy NER for possible person and organization names.
- Classifies findings as Restricted, Confidential, or Internal.
- Shows risk level, reason, and heuristic confidence.
- Uploads TXT, PDF, and DOCX files.
- Downloads findings as CSV and masked output as TXT.
- Includes unit tests.

> **Important:** This is an educational prototype, not a production Data Loss Prevention (DLP) system. It can produce false positives and false negatives. Pattern matches do not verify that an identifier is real. Do not upload real secrets or personal records to a public demo. Review legal and organizational requirements before deployment.

## 1. Requirements

- Python 3.10–3.12 recommended
- Internet access only for initial package/model installation

## 2. Install and run

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm
streamlit run app.py
```

If PowerShell blocks activation, run this in the same terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm
streamlit run app.py
```

The app opens in your browser, usually at `http://localhost:8501`.

If the spaCy model is not installed, regex detection still works; person/organization name detection is skipped.

## 3. Test

```bash
pytest -q
```

## 4. Example input

```text
Contact Alex at alex@example.com. Phone: +91 9876543210.
Customer ID: 1234 5678 9012. api_key=example_secret_123
```

The app reports possible findings, classifications, and a redacted preview. Use synthetic examples when demonstrating the project.

## 5. Architecture

1. **Input:** pasted text or TXT/PDF/DOCX.
2. **Extraction:** convert supported documents into text.
3. **Detection:** regex patterns plus optional spaCy named-entity recognition.
4. **Classification:** apply configurable example policy labels.
5. **Redaction:** mask selected findings from right to left to preserve text offsets.
6. **Reporting:** show findings and allow CSV/TXT downloads.

## 6. Limitations and production improvements

- Add Luhn validation for payment-card candidates and carefully validated country-specific formats.
- Add configurable policies by organization, jurisdiction, and data type.
- Use a trained NER/classification model and evaluate precision, recall, and F1 on a labeled dataset.
- Add tests for overlapping matches, Unicode, malformed files, and adversarial input.
- Add authentication, authorization, audit controls, retention limits, encryption, and rate limits before multi-user deployment.
- Avoid logging raw text or sensitive values. Consider showing masked values by default.
- For production, inspect dependency security, file size limits, scanned-PDF OCR needs, and secure temporary-file handling.

## Resume description (only after you have run and verified the project)

**PrivacyGuard AI — Sensitive Data Detection and Privacy Classification**
- Built a Python-based document scanner to identify potential PII and secret patterns in text, PDF, and DOCX inputs using regex and optional NLP entity recognition.
- Implemented risk-based privacy labels, masked output, and downloadable detection reports using Streamlit.
- Evaluated detection quality with unit tests; add measured precision/recall/F1 only after testing on a labeled dataset.
