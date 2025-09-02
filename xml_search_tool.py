import streamlit as st
import pandas as pd
import base64, gzip, io, json, re
from xml.dom import minidom

st.title("🔍 Flexible XML Search Tool")

uploaded_files = st.file_uploader(
    "Upload your XML or Encoded TXT files",
    type=["xml", "txt"],
    accept_multiple_files=True
)

st.sidebar.header("Search Parameters")
value1 = st.sidebar.text_input("Value 1 (e.g. 2025-09-01)", "")
value2 = st.sidebar.text_input("Value 2 (optional)", "")
value3 = st.sidebar.text_input("Value 3 (optional)", "")

payload_choice = st.sidebar.radio(
    "If JSON with XML inside:",
    options=["Auto", "RqPayload", "RsPayload", "Both"],
    index=0
)

results, preview_data, full_xml_data, xml_matches = [], {}, {}, []


# ---------------------- HELPERS ----------------------
def safe_b64decode(data: str):
    """Fix Base64 padding and decode safely"""
    data = data.strip().replace("\n", "").replace("\r", "")
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data)


def normalize_xml_text(text: str) -> str:
    """Clean XML/JSON text for searching"""
    return re.sub(r"\s+", " ", text).strip()


# ---------------------- DECODER ----------------------
def decode_if_needed(uploaded_file):
    """Decode plain XML/JSON, or Base64+Gzip containing XML/JSON-with-XML"""
    raw_bytes = uploaded_file.read()
    text = raw_bytes.decode("utf-8-sig", errors="ignore").strip()

    # --- Remove wrapper lines like ### Start / End ###
    lines = [line for line in text.splitlines() if not line.strip().startswith("#")]
    text = "".join(lines).strip()

    # --- Case 1: plain XML or JSON ---
    try:
        if text.startswith("<?xml"):
            st.info(f"✅ {uploaded_file.name}: detected plain XML")
            return [text]
        if text.startswith("{") or text.startswith("["):
            st.info(f"✅ {uploaded_file.name}: detected plain JSON")
            payload = json.loads(text)
            return extract_from_json(uploaded_file, payload)
    except Exception:
        pass

    # --- Case 2: Try Base64+Gzip ---
    try:
        decoded = safe_b64decode(text)
        decompressed = gzip.decompress(decoded).decode("utf-8-sig", errors="ignore").strip()

        if decompressed.startswith("<?xml"):
            st.info(f"✅ {uploaded_file.name}: decoded as XML (Base64+Gzip)")
            return [decompressed]
        if decompressed.startswith("{") or decompressed.startswith("["):
            st.info(f"✅ {uploaded_file.name}: decoded as JSON (Base64+Gzip)")
            payload = json.loads(decompressed)
            return extract_from_json(uploaded_file, payload)

    except Exception as e:
        st.error(f"⚠️ Could not decode {uploaded_file.name}: {e}")
        st.text_area(f"Raw content from {uploaded_file.name}", text[:500], height=150)

    return []


def extract_from_json(uploaded_file, payload):
    """Helper to extract XML from JSON payloads"""
    extracted = []
    keys = []
    if payload_choice == "RqPayload":
        keys = ["RqPayload"]
    elif payload_choice == "RsPayload":
        keys = ["RsPayload"]
    elif payload_choice == "Both":
        keys = ["RqPayload", "RsPayload"]
    else:
        keys = ["RqPayload", "RsPayload"]

    for key in keys:
        if key in payload:
            xml_candidate = payload[key].replace('\\"', '"').replace("\\n", "\n").strip()
            extracted.append(xml_candidate)
            st.text_area(f"Preview of {key} from {uploaded_file.name}", xml_candidate[:500], height=150)

    return extracted


# ---------------------- MAIN SEARCH ----------------------
if st.button("Search"):
    search_terms = [v.lower() for v in [value1, value2, value3] if v.strip()]
    if not uploaded_files:
        st.warning("Please upload at least one file.")
    elif not search_terms:
        st.warning("Please provide at least one search value.")
    else:
        for uploaded_file in uploaded_files:
            file_texts = decode_if_needed(uploaded_file)
            for idx, xml_text in enumerate(file_texts):
                try:
                    norm_text = normalize_xml_text(xml_text).lower()

                    # Check if all search terms are present (case-insensitive)
                    if all(term in norm_text for term in search_terms):
                        results.append({
                            "File": f"{uploaded_file.name} (part {idx+1})",
                            "Matches": ", ".join(search_terms)
                        })
                        xml_matches.append(xml_text)

                except Exception as e:
                    st.error(f"Error parsing {uploaded_file.name} (part {idx+1}): {e}")

        # ---------------------- RESULTS ----------------------
        if results:
            df = pd.DataFrame(results)
            st.success("✅ Matching records found!")
            st.dataframe(df)

            # Export XML
            if xml_matches:
                wrapper = "<Results>\n" + "\n".join(xml_matches) + "\n</Results>"

                try:
                    reparsed = minidom.parseString(wrapper)
                    pretty_xml = reparsed.toprettyxml(indent="  ")

                    st.download_button(
                        "⬇️ Download Matching XML",
                        pretty_xml.encode("utf-8"),
                        "results.xml",
                        "application/xml"
                    )
                except Exception as e:
                    st.error(f"⚠️ Could not format XML for download: {e}")
                    st.download_button(
                        "⬇️ Download Raw Matches",
                        wrapper.encode("utf-8"),
                        "results_raw.xml",
                        "application/xml"
                    )
        else:
            st.warning("❌ No matches found.")
