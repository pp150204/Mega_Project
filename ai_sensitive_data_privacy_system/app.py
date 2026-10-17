import streamlit as st
import pandas as pd
from io import BytesIO
from detector import analyze_text, redact_text, extract_text_from_upload

st.set_page_config(page_title="PrivacyGuard AI", page_icon="🛡️", layout="wide")
st.title("🛡️ PrivacyGuard AI")
st.caption("Sensitive Data Detection & Privacy Classification")
st.info("Prototype note: detection is rule-based plus optional NLP. It can miss sensitive data or flag ordinary text. Review results before relying on them.")

with st.sidebar:
    st.header("Settings")
    use_ner = st.checkbox("Enable spaCy NER", value=True, help="Detects person and organization names; it does not identify every kind of sensitive data.")
    mask_email = st.checkbox("Mask email addresses", value=True)
    mask_phone = st.checkbox("Mask phone numbers", value=True)
    mask_ids = st.checkbox("Mask ID / account-like numbers", value=True)
    st.caption("Privacy-first: this app processes input in the current app session. Avoid uploading real sensitive records to a hosted demo.")

tab_text, tab_file = st.tabs(["Paste text", "Upload document"])
text_input = ""
uploaded = None
with tab_text:
    text_input = st.text_area(
        "Text to scan",
        height=220,
        placeholder="Example: Contact me at alex@example.com or 9876543210."
    )
with tab_file:
    uploaded = st.file_uploader("Upload TXT, PDF, or DOCX", type=["txt", "pdf", "docx"])
    if uploaded:
        st.success(f"Selected: {uploaded.name}")

if st.button("Scan for sensitive data", type="primary", use_container_width=True):
    try:
        source_text = text_input
        if uploaded:
            source_text = extract_text_from_upload(uploaded)
        if not source_text.strip():
            st.warning("Enter text or upload a document first.")
        else:
            findings = analyze_text(source_text, use_ner=use_ner)
            redacted = redact_text(
                source_text,
                findings,
                mask_email=mask_email,
                mask_phone=mask_phone,
                mask_ids=mask_ids
            )
            st.session_state["last_source"] = source_text
            st.session_state["last_findings"] = findings
            st.session_state["last_redacted"] = redacted
    except Exception as exc:
        st.error(f"Could not scan this input: {exc}")

if "last_findings" in st.session_state:
    findings = st.session_state["last_findings"]
    source = st.session_state["last_source"]
    redacted = st.session_state["last_redacted"]
    counts = pd.Series([x["classification"] for x in findings]).value_counts() if findings else pd.Series(dtype=int)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Findings", len(findings))
    c2.metric("Restricted", int(counts.get("Restricted", 0)))
    c3.metric("Confidential", int(counts.get("Confidential", 0)))
    c4.metric("Internal", int(counts.get("Internal", 0)))

    st.subheader("Detection results")
    if findings:
        table = pd.DataFrame([{
            "Detected value": f["value"],
            "Type": f["type"],
            "Classification": f["classification"],
            "Risk": f["risk"],
            "Confidence": f["confidence"],
            "Reason": f["reason"]
        } for f in findings])
        st.dataframe(table, use_container_width=True, hide_index=True)
        st.download_button(
            "Download findings CSV",
            table.to_csv(index=False).encode("utf-8"),
            file_name="privacy_findings.csv",
            mime="text/csv"
        )
    else:
        st.success("No supported sensitive-data patterns were detected. This does not guarantee the text is safe.")

    st.subheader("Redacted preview")
    st.text_area("Masked text", value=redacted, height=220)
    st.download_button(
        "Download redacted text",
        data=redacted.encode("utf-8"),
        file_name="redacted_output.txt",
        mime="text/plain"
    )

    with st.expander("How this prototype classifies data"):
        st.markdown("""
- **Restricted:** password-like secrets, Aadhaar-like / government-ID patterns, account-like numbers.
- **Confidential:** email addresses, phone numbers, payment-card-like numbers, detected person names.
- **Internal:** detected organization names.
- **Public:** no finding is automatically labeled public; absence of detection is not proof that content is public.

Classification is an example policy for demonstration. Tune it to your organization and validate on a labeled dataset before production use.
""")
