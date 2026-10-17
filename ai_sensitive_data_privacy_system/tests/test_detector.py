from detector import analyze_text, redact_text

def test_email_detection_and_redaction():
    text = "Contact me at alex@example.com"
    findings = analyze_text(text, use_ner=False)
    assert any(item["type"] == "Email" for item in findings)
    result = redact_text(text, findings)
    assert "alex@example.com" not in result
    assert "@" in result

def test_secret_detection():
    text = "api_key=sk_test_123456"
    findings = analyze_text(text, use_ner=False)
    assert any(item["type"] == "Password / secret assignment" for item in findings)
    result = redact_text(text, findings)
    assert "sk_test_123456" not in result

def test_aadhaar_like_detection():
    text = "ID: 1234 5678 9012"
    findings = analyze_text(text, use_ner=False)
    assert any(item["type"] == "Aadhaar-like number" for item in findings)

def test_empty_text():
    assert analyze_text("", use_ner=False) == []
