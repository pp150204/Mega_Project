"""Rule-based sensitive-data detector with optional spaCy NER.

This is a learning prototype, not a certified DLP/security product.
Patterns identify possible matches, not verified identities or valid credentials.
"""
from __future__ import annotations
import re
from typing import Any

PATTERNS = [
    {
        "type": "Email",
        "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "classification": "Confidential", "risk": "Medium", "confidence": 0.98,
        "reason": "Email-address pattern may identify a person or account.",
        "mask": "email",
    },
    {
        "type": "Phone number",
        "regex": re.compile(r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3,5}\)?[-.\s]?)\d{5,8}(?!\w)"),
        "classification": "Confidential", "risk": "Medium", "confidence": 0.76,
        "reason": "Number resembles a phone number; false positives are possible.",
        "mask": "phone",
    },
    {
        "type": "Payment card-like number",
        "regex": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
        "classification": "Restricted", "risk": "High", "confidence": 0.55,
        "reason": "Long digit sequence may be a payment-card number; validate with a Luhn check in production.",
        "mask": "id",
    },
    {
        "type": "Aadhaar-like number",
        "regex": re.compile(r"(?<!\d)\d{4}[ -]\d{4}[ -]\d{4}(?!\d)"),
        "classification": "Restricted", "risk": "High", "confidence": 0.65,
        "reason": "Number matches a common 12-digit ID format; this does not validate an actual Aadhaar number.",
        "mask": "id",
    },
    {
        "type": "PAN-like number",
        "regex": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "classification": "Restricted", "risk": "High", "confidence": 0.65,
        "reason": "Value matches a common PAN format; authenticity is not verified.",
        "mask": "id",
    },
    {
        "type": "Password / secret assignment",
        "regex": re.compile(r"(?i)\b(?:password|passwd|api[_ -]?key|secret|access[_ -]?token)\s*[:=]\s*['\"]?([^\s,'\";]{4,})"),
        "classification": "Restricted", "risk": "High", "confidence": 0.86,
        "reason": "Text assigns a value to a password, key, secret, or token field.",
        "mask": "secret",
    },
]

CLASS_ORDER = {"Restricted": 0, "Confidential": 1, "Internal": 2}

def analyze_text(text: str, use_ner: bool = True) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    occupied: list[tuple[int, int]] = []

    # Higher-specificity patterns run first. Overlapping lower-quality matches are skipped.
    for pattern in PATTERNS:
        for match in pattern["regex"].finditer(text):
            start, end = match.span()
            # For secret assignments, include the entire assignment so it can be redacted safely.
            value = match.group(0)
            if pattern["type"] == "Password / secret assignment":
                value = match.group(0)
            if any(start < old_end and end > old_start for old_start, old_end in occupied):
                continue
            occupied.append((start, end))
            findings.append({
                "start": start, "end": end, "value": value,
                "type": pattern["type"], "classification": pattern["classification"],
                "risk": pattern["risk"], "confidence": pattern["confidence"],
                "reason": pattern["reason"], "mask": pattern["mask"],
            })

    if use_ner:
        try:
            import spacy
            nlp = spacy.load("en_core_web_sm")
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ not in {"PERSON", "ORG"}:
                    continue
                start, end = ent.start_char, ent.end_char
                if any(start < old_end and end > old_start for old_start, old_end in occupied):
                    continue
                classification = "Confidential" if ent.label_ == "PERSON" else "Internal"
                findings.append({
                    "start": start, "end": end, "value": ent.text,
                    "type": "Person name" if ent.label_ == "PERSON" else "Organization",
                    "classification": classification,
                    "risk": "Medium" if ent.label_ == "PERSON" else "Low",
                    "confidence": round(float(ent._.confidence), 2) if ent.has_extension("confidence") else 0.65,
                    "reason": "NER model identified a possible person or organization name.",
                    "mask": "name",
                })
        except (ImportError, OSError):
            # spaCy/model is optional; regex detection still works.
            pass

    findings.sort(key=lambda item: (item["start"], item["end"]))
    return findings

def _mask_value(value: str, kind: str) -> str:
    if kind == "email":
        if "@" not in value:
            return "[REDACTED_EMAIL]"
        local, domain = value.split("@", 1)
        visible = local[:2] if len(local) > 2 else local[:1]
        return f"{visible}{'*' * max(3, len(local) - len(visible))}@{domain}"
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        return "*" * max(0, len(digits) - 4) + digits[-4:] if digits else "[REDACTED_PHONE]"
    if kind == "id":
        digits = re.sub(r"\D", "", value)
        return "*" * max(0, len(digits) - 4) + digits[-4:] if digits else "[REDACTED_ID]"
    if kind == "secret":
        if ":" in value:
            key = value.split(":", 1)[0]
            return f"{key}: [REDACTED]"
        if "=" in value:
            key = value.split("=", 1)[0]
            return f"{key}= [REDACTED]"
        return "[REDACTED_SECRET]"
    if kind == "name":
        return "[REDACTED_NAME]"
    return "[REDACTED]"

def redact_text(text: str, findings: list[dict[str, Any]], mask_email=True, mask_phone=True, mask_ids=True) -> str:
    mask_by_kind = {"email": mask_email, "phone": mask_phone, "id": mask_ids, "secret": True, "name": True}
    output = text
    # Replace from right to left so earlier offsets remain valid.
    for item in sorted(findings, key=lambda x: x["start"], reverse=True):
        if not mask_by_kind.get(item["mask"], True):
            continue
        replacement = _mask_value(item["value"], item["mask"])
        output = output[:item["start"]] + replacement + output[item["end"]:]
    return output

def extract_text_from_upload(uploaded_file) -> str:
    suffix = uploaded_file.name.lower().rsplit(".", 1)[-1]
    data = uploaded_file.getvalue()
    if suffix == "txt":
        return data.decode("utf-8", errors="replace")
    if suffix == "pdf":
        import fitz
        doc = fitz.open(stream=data, filetype="pdf")
        return "\n".join(page.get_text() for page in doc)
    if suffix == "docx":
        from docx import Document
        document = Document(BytesIO(data))
        paragraphs = [p.text for p in document.paragraphs]
        for table in document.tables:
            for row in table.rows:
                paragraphs.append(" | ".join(cell.text for cell in row.cells))
        return "\n".join(paragraphs)
    raise ValueError("Unsupported file type. Upload TXT, PDF, or DOCX.")
