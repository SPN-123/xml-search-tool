import streamlit as st
import pandas as pd
import base64
import gzip
import io
import json
import re
import zipfile
import html
from xml.dom import minidom
from typing import List, Tuple, Any

st.set_page_config(page_title="Flexible XML Search Tool", layout="wide")
st.title("🔍 Flexible XML Search Tool (ZIP Export with 4 Search Values)")

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

debug_mode = st.sidebar.checkbox("Debug mode: show extracted parts & snippets & highlights", True)

results, fragment_files = [], []  # store fragments as (filename, xml_string)


# ---------------------- HELPERS ----------------------
def safe_b64decode(data: str) -> bytes:
    """Fix Base64 padding and decode safely"""
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


def clean_search_term(term: str) -> str:
    if term is None:
        return ""
    term = term.strip()
    term = term.replace("\ufeff", "")
    term = re.sub(r"[\u200B-\u200F\uFEFF\u2060\u00AD]", "", term)
    return term


def highlight_matches(text: str, terms: List[str], regex_mode: bool) -> str:
    """Return HTML with matches wrapped in <mark>. Keeps original whitespace using <pre>."""
    if not terms:
        return "<pre>" + html.escape(text[:10000]) + ("..." if len(text) > 10000 else "") + "</pre>"

    escaped = html.escape(text)
    matches = []
    lower = escaped.lower()

    for t in terms:
        if not t:
            continue
        if regex_mode:
            try:
                # Note: operate on escaped text; regex will still match sequences of characters
                for m in re.finditer(t, escaped, flags=re.IGNORECASE):
                    matches.append((m.start(), m.end()))
            except re.error:
                # fallback to literal
                idx = lower.find(t.lower())
                if idx != -1:
                    matches.append((idx, idx + len(t)))
        else:
            # literal search, case-insensitive
            start = 0
            tl = t.lower()
            while True:
                idx = lower.find(tl, start)
                if idx == -1:
                    break
                matches.append((idx, idx + len(tl)))
                start = idx + len(tl)

    if not matches:
        return "<pre>" + escaped[:10000] + ("..." if len(escaped) > 10000 else "") + "</pre>"

    # merge overlapping ranges
    matches.sort()
    merged = [matches[0]]
    for s, e in matches[1:]:
        last_s, last_e = merged[-1]
        if s <= last_e:
            merged[-1] = (last_s, max(last_e, e))
        else:
            merged.append((s, e))

    # construct highlighted HTML
    out = []
    pos = 0
    for s, e in merged:
        out.append(escaped[pos:s])
        out.append("<mark>")
        out.append(escaped[s:e])
        out.append("</mark>")
        pos = e
    out.append(escaped[pos:])
    html_snippet = "".join(out)

    # limit size to avoid huge outputs
    if len(html_snippet) > 20000:
        html_snippet = html_snippet[:20000] + "..."

    return "<pre style=\"white-space: pre-wrap;word-break:break-word;\">" + html_snippet + "</pre>"


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
        xml_candidate = xml_candidate.replace('\\"', '"').replace('\\n', '\n').strip()
        extracted.append(xml_candidate)
        if debug_mode:
            # show a short text preview so you can inspect the payload structure
            st.markdown(f"**Preview of JSON payload {i+1} from {uploaded_file.name}**")
            st.text_area(f"payload_preview_{i+1}", xml_candidate[:500], height=120)
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
    raw_terms = [value1, value2, value3, value4]
    search_terms = [clean_search_term(t) for t in raw_terms if t and t.strip()]

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
                    ok = True
                    for term in search_terms:
                        if term.lower() not in norm_text.lower():
                            ok = False
                            if debug_mode:
                                snip = (norm_text.lower().find(term.lower()) and norm_text[max(0, norm_text.lower().find(term.lower())-120):norm_text.lower().find(term.lower())+120]) or ''
                                st.write(f"Literal term '{term}' not found in {fname}. Snippet near expected term: {snip}")
                            break

                if ok:
                    results.append({"File": fname, "Matches": ", ".join(search_terms)})
                    fragment_files.append((fname, xml_text))

                    # show highlighted preview when Debug mode ON
                    if debug_mode:
                        st.markdown(f"**Highlighted preview for: {fname}**")
                        highlighted_html = highlight_matches(xml_text, search_terms, use_regex)
                        st.markdown(highlighted_html, unsafe_allow_html=True)
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
st.caption("Tips: Enable Debug mode to see extracted parts and why matches may fail.")
