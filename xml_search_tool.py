import streamlit as st
import pandas as pd
import base64
import gzip
import io
import json
import re
import zipfile
from xml.dom import minidom
from typing import List, Tuple, Any

st.set_page_config(page_title="Flexible XML Search Tool", layout="wide")
st.title("🔍 Flexible XML Search Tool (ZIP Export with 4 Search Values)")

# ====== Wasabi secrets sanity check (safe, masked) ======
if st.secrets.get("wasabi"):
    w = st.secrets["wasabi"]
    st.sidebar.markdown("**Wasabi secrets loaded (masked)**")
    st.sidebar.write("Bucket:", w.get("bucket", "(not set)"))
    access = w.get("access_key", "")
    st.sidebar.write("Access key (masked):", (access[:4] + "..." if access else "(not set)"))
else:
    st.sidebar.info("No Wasabi secrets found (use Streamlit Cloud Secrets).")
# =====================================================

uploaded_files = st.file_uploader(
    "Upload your XML / Encoded TXT / ZIP files",
    type=["xml", "txt", "zip"],
    accept_multiple_files=True
)

st.sidebar.header("Search Parameters")
value1 = st.sidebar.text_input("Value 1 (e.g. 2025-09-01)", "")
value2 = st.sidebar.text_input("Value 2 (optional)", "")
value3 = st.sidebar.text_input("Value 3 (optional)", "")
value4 = st.sidebar.text_input("Value 4 (optional)", "")

payload_choice = st.sidebar.radio(
    "If JSON with XML inside:",
    options=["Auto", "RqPayload", "RsPayload", "Both"],
    index=0
)

use_regex = st.sidebar.checkbox("Treat search values as regular expressions (case-insensitive)", False)

debug_mode = st.sidebar.checkbox("Debug mode: show extracted parts & snippets", True)

results, fragment_files = [], []  # store fragments as (filename, xml_string)


# ---------------------- HELPERS ----------------------
def safe_b64decode(data: str) -> bytes:
    data = data.strip().replace("\n", "").replace("\r", "")
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data)
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data)


def normalize_xml_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def clean_filename(name: str) -> str:
    return re.sub(r"[^0-9A-Za-z._-]", "_", name)


def highlight_matches(text: str, terms: list) -> str:
    """Highlight search terms in the given text for debug display"""
    escaped_terms = [re.escape(t) for t in terms if t]
    if not escaped_terms:
        return text
    pattern = re.compile("(" + "|".join(escaped_terms) + ")", re.IGNORECASE)
    return pattern.sub(r"**\\1**", text)


# ---------------------- JSON EXTRACTION ----------------------
def recursive_find_payloads(obj: Any, keys_of_interest=None) -> List[str]:
    if keys_of_interest is None:
        keys_of_interest = ["RqPayload", "RsPayload"]
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys_of_interest and isinstance(v, str):
                found.append(v)
            else:
                found.extend(recursive_find_payloads(v, keys_of_interest))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(recursive_find_payloads(item, keys_of_interest))
    return found


def extract_from_json(uploaded_file, payload: Any) -> List[str]:
    extracted = []
    if payload_choice == "RqPayload":
        keys = ["RqPayload"]
    elif payload_choice == "RsPayload":
        keys = ["RsPayload"]
    elif payload_choice == "Both":
        keys = ["RqPayload", "RsPayload"]
    else:
        keys = ["RqPayload", "RsPayload"]

    candidates = recursive_find_payloads(payload, keys)

    for i, xml_candidate in enumerate(candidates):
        if not isinstance(xml_candidate, str):
            continue
        xml_candidate = xml_candidate.replace('\"', '"').replace('\\n', '\n').strip()
        extracted.append(xml_candidate)
        if debug_mode:
            preview = highlight_matches(xml_candidate[:500], [value1, value2, value3, value4])
            st.markdown(f"**Preview of JSON payload {i+1} from {uploaded_file.name}:**\n````\n{preview}\n````")
    return extracted


# ---------------------- DECODER ----------------------
def decode_if_needed(file_name: str, raw_bytes: bytes) -> List[str]:
    tries = []
    text = ""

    try:
        text = raw_bytes.decode("utf-8-sig", errors="ignore").strip()
        lines = [line for line in text.splitlines() if not line.strip().startswith("#") and not line.strip().startswith("---")]
        text = "\n".join(lines).strip()
        if text:
            tries.append(("text", text))
    except Exception:
        text = ""

    try:
        decompressed = gzip.decompress(raw_bytes).decode("utf-8-sig", errors="ignore").strip()
        if decompressed:
            tries.append(("gzip", decompressed))
    except Exception:
        pass

    try:
        source_for_b64 = text if text else raw_bytes.decode('utf-8', errors='ignore')
        b64_decoded = safe_b64decode(source_for_b64)
        if b64_decoded[:2] == b"\x1f\x8b":
            try:
                decompressed = gzip.decompress(b64_decoded).decode("utf-8-sig", errors="ignore").strip()
                tries.append(("b64+gzip", decompressed))
            except Exception:
                try:
                    tries.append(("b64_text", b64_decoded.decode("utf-8-sig", errors="ignore").strip()))
                except Exception:
                    pass
        else:
            try:
                tries.append(("b64_text", b64_decoded.decode("utf-8-sig", errors="ignore").strip()))
            except Exception:
                pass
    except Exception:
        pass

    outputs = []
    if debug_mode:
        st.write(f"Decode attempts for {file_name}: {[k for k,_ in tries]}")

    for kind, candidate in tries:
        if not candidate or len(candidate) < 6:
            continue
        c = candidate.strip()
        if c.startswith("<?xml") or c.lstrip().startswith("<"):
            outputs.append(c)
        elif c.startswith("{") or c.startswith("["):
            try:
                payload = json.loads(c)
                outputs.extend(extract_from_json(io.BytesIO(raw_bytes), payload))
            except Exception:
                xml_match = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", c)
                if xml_match:
                    outputs.append(xml_match.group(0))
        else:
            xml_match = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", c)
            if xml_match:
                outputs.append(xml_match.group(0))
    return outputs


# ---------------------- PROCESS UPLOADED FILES ----------------------
def process_uploaded_file(uploaded_file) -> List[Tuple[str, str]]:
    name = uploaded_file.name
    raw = uploaded_file.read()
    parts: List[Tuple[str, str]] = []

    if name.lower().endswith('.zip'):
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            for inner in z.namelist():
                try:
                    inner_bytes = z.read(inner)
                    subparts = decode_if_needed(inner, inner_bytes)
                    for i, s in enumerate(subparts):
                        parts.append((f"{clean_filename(name)}::{clean_filename(inner)}_part{i+1}.xml", s))
                except Exception as e:
                    st.warning(f"Could not read inner file {inner} from {name}: {e}")
            return parts
        except Exception:
            pass

    subparts = decode_if_needed(name, raw)
    for i, s in enumerate(subparts):
        parts.append((f"{clean_filename(name)}_part{i+1}.xml", s))
    return parts


# ---------------------- MAIN SEARCH ----------------------
if st.button("Search"):
    search_terms = [v for v in [value1, value2, value3, value4] if v.strip()]
    if not uploaded_files:
        st.warning("Please upload at least one file.")
    elif not search_terms:
        st.warning("Please provide at least one search value.")
    else:
        all_parts = []
        for uploaded_file in uploaded_files:
            try:
                file_parts = process_uploaded_file(uploaded_file)
                if debug_mode:
                    st.write(f"From {uploaded_file.name} extracted {len(file_parts)} parts")
                all_parts.extend(file_parts)
            except Exception as e:
                st.error(f"Failed processing {uploaded_file.name}: {e}")

        for fname, xml_text in all_parts:
            try:
                norm_text = normalize_xml_text(xml_text)
                if use_regex:
                    ok = True
                    for term in search_terms:
                        try:
                            if not re.search(term, norm_text, flags=re.IGNORECASE):
                                ok = False
                                if debug_mode:
                                    st.write(f"Regex '{term}' not found in {fname}")
                                break
                        except re.error:
                            if term.lower() not in norm_text.lower():
                                ok = False
                                if debug_mode:
                                    st.write(f"Invalid regex, literal '{term}' not found in {fname}")
                                break
                else:
                    ok = all(term.lower() in norm_text.lower() for term in search_terms)

                if ok:
                    results.append({"File": fname, "Matches": ", ".join(search_terms)})
                    fragment_files.append((fname, xml_text))

                    if debug_mode:
                        preview = highlight_matches(xml_text[:500], search_terms)
                        st.markdown(f"**Preview with highlights from {fname}:**\n````\n{preview}\n````")

            except Exception as e:
                st.error(f"Error searching {fname}: {e}")

        if results:
            df = pd.DataFrame(results)
            st.success(f"✅ {len(results)} matching records found!")
            st.dataframe(df)

            if fragment_files:
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, "w") as zipf:
                    for fname, xml_str in fragment_files:
                        try:
                            reparsed = minidom.parseString(xml_str)
                            pretty_xml = reparsed.toprettyxml(indent="  ")
                        except Exception:
                            pretty_xml = xml_str
                        zipf.writestr(fname, pretty_xml)
                zip_buffer.seek(0)
                st.download_button(
                    "⬇️ Download All Matching XMLs (ZIP)",
                    zip_buffer,
                    "results.zip",
                    "application/zip"
                )
        else:
            st.warning("❌ No matches found.")

st.markdown("---")
st.caption("Tips: Enable Debug mode to see extracted parts, highlighted matches, and why matches may fail.")
