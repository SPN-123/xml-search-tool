import streamlit as st
import pandas as pd
import base64
import gzip
import io
import json
import re
import zipfile
import html
import os
from xml.dom import minidom
from typing import List, Tuple, Any

# Optional dependencies: boto3 (required for Wasabi), lxml (recommended for XPath)
try:
    import boto3
    from botocore.config import Config
except Exception:
    boto3 = None

try:
    from lxml import etree
    LXML_AVAILABLE = True
except Exception:
    LXML_AVAILABLE = False

st.set_page_config(page_title="Wasabi XML Search — Full Automation + XPath + Index", layout="wide")
st.title("🔎 Wasabi XML Search — Full Automation (Wasabi-only) + XPath + Cached Index")

# ------------------------ Wasabi secrets (must be set in Streamlit secrets) ------------------------
wasabi_secrets = st.secrets.get("wasabi", {}) if isinstance(st.secrets, dict) or hasattr(st, "secrets") else {}
if wasabi_secrets:
    st.sidebar.markdown("**Wasabi secrets loaded (masked)**")
    st.sidebar.write("Bucket:", wasabi_secrets.get("bucket", "(not set)"))
    ak = wasabi_secrets.get("access_key", "")
    st.sidebar.write("Access key (masked):", (ak[:4] + "..." if ak else "(not set)"))
else:
    st.sidebar.warning("No Wasabi secrets found. Please add them in Streamlit Cloud -> Settings -> Secrets.")
    st.stop()

# ------------------------ Sidebar: search parameters ------------------------
st.sidebar.header("Search & Wasabi Options (Full Automation)")

# Search inputs (up to 4)
value1 = st.sidebar.text_input("Value 1 (required)", "")
value2 = st.sidebar.text_input("Value 2 (optional)", "")
value3 = st.sidebar.text_input("Value 3 (optional)", "")
value4 = st.sidebar.text_input("Value 4 (optional)", "")

search_mode = st.sidebar.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (node/attribute search)"])
# 'use_regex' variable is relevant only for Regex mode; for UX we enable regex mode by selecting it above
use_regex = (search_mode == "Regular expression")

# XPath field (only used in XPath mode)
xpath_expr = st.sidebar.text_input("XPath expression (used when Search mode = XPath)", "")

debug_mode = st.sidebar.checkbox("Debug mode: show decode attempts & snippets", False)

# Wasabi scanning controls
st.sidebar.markdown("---")
st.sidebar.markdown("**Wasabi object selection & index**")
default_prefix = wasabi_secrets.get("prefix", "") if wasabi_secrets else ""
prefix = st.sidebar.text_input("Prefix (optional) — list only under this folder", default_prefix)
name_contains = st.sidebar.text_input("Filename contains (optional) — quick filename filter", "")
max_objects = st.sidebar.number_input("Max objects to scan", min_value=1, value=200, step=1)

# Index controls
st.sidebar.markdown("---")
index_action = st.sidebar.selectbox("Index action", ["Use cache if available", "Rebuild cache now", "Clear cache"])
index_sample_bytes = st.sidebar.number_input("Bytes to sample per object for index (Range GET)", min_value=256, max_value=65536, value=2048, step=256)

# Button to run
run_search = st.sidebar.button("Run Wasabi Search")

# ------------------------ Helpers: decoding/searching ------------------------
def safe_b64decode(data: str) -> bytes:
    data = data.strip().replace("\n", "").replace("\r", "")
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data)
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data)

def normalize_text_for_search(text: str) -> str:
    if text is None:
        return ""
    text = text.replace("\ufeff", "")
    text = re.sub(r"[\u200B-\u200F\uFEFF\u2060\u00AD]", "", text)
    text = re.sub(r"[^\x09\x0A\x0D\x20-\x7E\u0080-\uFFFF]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def highlight_matches_html(text: str, terms: List[str], regex_mode: bool) -> str:
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
                for m in re.finditer(t, escaped, flags=re.IGNORECASE):
                    matches.append((m.start(), m.end()))
            except re.error:
                idx = lower.find(t.lower())
                if idx != -1:
                    matches.append((idx, idx + len(t)))
        else:
            tl = t.lower()
            start = 0
            while True:
                idx = lower.find(tl, start)
                if idx == -1:
                    break
                matches.append((idx, idx + len(tl)))
                start = idx + len(tl)
    if not matches:
        return "<pre>" + escaped[:10000] + ("..." if len(escaped) > 10000 else "") + "</pre>"
    matches.sort()
    merged = [matches[0]]
    for s, e in matches[1:]:
        ls, le = merged[-1]
        if s <= le:
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s, e))
    out = []
    pos = 0
    for s, e in merged:
        out.append(escaped[pos:s])
        out.append("<mark>")
        out.append(escaped[s:e])
        out.append("</mark>")
        pos = e
    out.append(escaped[pos:])
    html_snip = "".join(out)
    if len(html_snip) > 20000:
        html_snip = html_snip[:20000] + "..."
    return "<pre style=\"white-space: pre-wrap;word-break:break-word;\">" + html_snip + "</pre>"

# decode function (handles text / gzip / base64+gzip / base64_text / JSON with embedded XML)
def decode_if_needed(file_name: str, raw_bytes: bytes) -> List[str]:
    tries = []
    text = ""
    # try plain text
    try:
        text = raw_bytes.decode("utf-8-sig", errors="ignore").strip()
        lines = [line for line in text.splitlines() if not line.strip().startswith("#") and not line.strip().startswith("---")]
        text = "\n".join(lines).strip()
        if text:
            tries.append(("text", text))
    except Exception:
        text = ""
    # try gzip
    try:
        decompressed = gzip.decompress(raw_bytes).decode("utf-8-sig", errors="ignore").strip()
        if decompressed:
            tries.append(("gzip", decompressed))
    except Exception:
        pass
    # try base64 (then gzip)
    try:
        source_for_b64 = text if text else raw_bytes.decode('utf-8', errors='ignore')
        b64_decoded = safe_b64decode(source_for_b64)
        if b64_decoded[:2] == b"\x1f\x8b":  # gzip magic
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
        st.write(f"Decode attempts for {file_name}: {[k for k, _ in tries]}")
    for kind, candidate in tries:
        if not candidate or len(candidate) < 6:
            continue
        c = candidate.strip()
        if c.startswith("<?xml") or c.lstrip().startswith("<"):
            outputs.append(c)
        elif c.startswith("{") or c.startswith("["):
            try:
                payload = json.loads(c)
                # recursively search payload for typical keys and extract XML-like values
                candidates = []
                def rec(o):
                    if isinstance(o, dict):
                        for kk, vv in o.items():
                            if kk in ("RqPayload", "RsPayload") and isinstance(vv, str):
                                candidates.append(vv)
                            else:
                                rec(vv)
                    elif isinstance(o, list):
                        for it in o:
                            rec(it)
                rec(payload)
                for p in candidates:
                    outputs.append(p)
            except Exception:
                xml_match = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", c)
                if xml_match:
                    outputs.append(xml_match.group(0))
        else:
            xml_match = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", c)
            if xml_match:
                outputs.append(xml_match.group(0))
    return outputs

# ------------------------ Wasabi helpers ------------------------
def get_s3_client(secrets: dict):
    if boto3 is None:
        raise RuntimeError("boto3 is required for Wasabi access. Run: pip install boto3")
    cfg = Config(signature_version='s3v4', retries={'max_attempts': 3})
    session = boto3.session.Session()
    client = session.client(
        service_name='s3',
        region_name=secrets.get("region") or None,
        endpoint_url=secrets.get("endpoint_url"),
        aws_access_key_id=secrets.get("access_key"),
        aws_secret_access_key=secrets.get("secret_key"),
        config=cfg
    )
    return client

def list_wasabi_keys(client, bucket: str, prefix: str = "", max_items: int = 500) -> List[str]:
    paginator = client.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
            if len(keys) >= max_items:
                return keys
    return keys

def fetch_object_bytes(client, bucket: str, key: str, byte_range: str = None) -> bytes:
    kwargs = {"Bucket": bucket, "Key": key}
    if byte_range:
        kwargs["Range"] = byte_range
    resp = client.get_object(**kwargs)
    return resp["Body"].read()

# ------------------------ Indexing (cached) ------------------------
@st.cache_data(show_spinner=False)
def build_index(secrets_serial: Tuple, bucket: str, prefix: str, name_contains: str, max_objects: int, sample_bytes: int) -> List[dict]:
    """Build a small index of object keys and a sample of their bytes to allow fast pre-filtering.
    secrets_serial is a small serializable form of secrets so cache keys change when secrets change.
    Returns a list of dicts: {key, sample_text}
    """
    # secrets_serial is not used directly except to vary the cache key
    client = get_s3_client(wasabi_secrets)
    keys = list_wasabi_keys(client, bucket, prefix=prefix or "", max_items=max_objects)
    if name_contains:
        keys = [k for k in keys if name_contains in k]
    index = []
    for k in keys:
        try:
            # fetch a small sample using Range header
            sample = b""
            try:
                sample = fetch_object_bytes(client, bucket, k, byte_range=f"bytes=0-{sample_bytes-1}")
            except Exception:
                # fallback to full fetch if Range not supported
                sample = fetch_object_bytes(client, bucket, k)
            # decode best-effort
            try:
                s = sample.decode('utf-8-sig', errors='ignore')
            except Exception:
                s = ''
            index.append({"key": k, "sample_text": s})
        except Exception:
            # skip problematic objects
            continue
    return index

# ------------------------ Run search ------------------------
def run_full_wasabi_scan():
    # Prepare search terms
    raw_terms = [value1, value2, value3, value4]
    search_terms = [t for t in [rt.strip() for rt in raw_terms if rt and rt.strip()]]
    if not search_terms and search_mode != "XPath (node/attribute search)":
        st.warning("Please provide at least one search value in Value 1..4.")
        return
    if search_mode == "XPath (node/attribute search)" and not xpath_expr.strip():
        st.warning("Please provide an XPath expression when Search mode = XPath.")
        return

    bucket = wasabi_secrets.get("bucket")
    if not bucket:
        st.error("Bucket not set in Wasabi secrets. Add 'bucket' to the st.secrets wasabi section.")
        return

    # Build S3 client
    try:
        client = get_s3_client(wasabi_secrets)
    except Exception as e:
        st.error(f"Failed to create S3 client: {e}")
        return

    # Handle index actions
    secrets_serial = (wasabi_secrets.get('access_key','')[:4], wasabi_secrets.get('endpoint_url',''),)
    index_key = (secrets_serial, bucket, prefix or '', name_contains or '', int(max_objects), int(index_sample_bytes))

    if index_action == "Clear cache":
        st.cache_data.clear()
        st.success("Index cache cleared. Re-run to rebuild.")
        return

    if index_action == "Rebuild cache now":
        with st.spinner("Rebuilding index..."):
            try:
                index = build_index(secrets_serial, bucket, prefix or '', name_contains or '', int(max_objects), int(index_sample_bytes))
                st.success(f"Index built with {len(index)} entries.")
            except Exception as e:
                st.error(f"Failed to build index: {e}")
                return
    else:
        # Use cache if available (build_index will use cache automatically)
        try:
            index = build_index(secrets_serial, bucket, prefix or '', name_contains or '', int(max_objects), int(index_sample_bytes))
            if debug_mode:
                st.write(f"Index contains {len(index)} entries (cached or fresh).")
        except Exception as e:
            st.error(f"Failed to build/load index: {e}")
            return

    # At this point we have an index of candidate keys and small samples
    candidate_keys = [entry['key'] for entry in index]
    st.write(f"{len(candidate_keys)} candidate objects after index & filename filtering.")
    if not candidate_keys:
        st.warning("No objects to scan. Adjust prefix / filename filter or increase max_objects.")
        return

    results = []
    fragment_files = []
    pbar = st.progress(0)
    for idx, key in enumerate(candidate_keys):
        try:
            # Fetch full object for scanning (could be optimized to attempt partial checks first)
            raw = fetch_object_bytes(client, bucket, key)
            parts = decode_if_needed(key, raw)
            if debug_mode:
                st.write(f"Decoded {len(parts)} parts from {key}.")
            for pi, txt in enumerate(parts):
                norm = normalize_text_for_search(txt)
                ok = False
                # XPath mode
                if search_mode == "XPath (node/attribute search)":
                    if not LXML_AVAILABLE:
                        st.error("lxml is required for XPath mode. Install with: pip install lxml")
                        return
                    try:
                        root = etree.fromstring(txt.encode('utf-8'))
                        # attempt namespace-aware XPath: collect namespace map from root
                        nsmap = {k if k is not None else 'ns': v for k, v in root.nsmap.items()}
                        matches = root.xpath(xpath_expr, namespaces=nsmap)
                        if matches:
                            ok = True
                    except Exception as e:
                        if debug_mode:
                            st.write(f"XPath eval failed for {key} part {pi+1}: {e}")
                        ok = False
                else:
                    # Text / Regex modes
                    if search_mode == "Regular expression":
                        ok = True
                        for term in search_terms:
                            try:
                                if not re.search(term, norm, flags=re.IGNORECASE):
                                    ok = False
                                    break
                            except re.error:
                                if term.lower() not in norm.lower():
                                    ok = False
                                    break
                    else:
                        ok = True
                        for term in search_terms:
                            if term.lower() not in norm.lower():
                                ok = False
                                break
                if ok:
                    fname = f"{key.replace('/', '_')}_part{pi+1}.xml"
                    results.append({"File": fname, "SourceKey": key, "Part": pi+1})
                    fragment_files.append((fname, txt))
                    if debug_mode:
                        st.success(f"Match in {key} (part {pi+1})")
                        if search_mode == "XPath (node/attribute search)":
                            st.write("XPath matched — showing fragment preview:")
                            st.text_area(f"preview_{key}_{pi}", txt[:2000], height=200)
                        else:
                            html_preview = highlight_matches_html(txt, search_terms, search_mode=="Regular expression")
                            st.markdown(html_preview, unsafe_allow_html=True)
        except Exception as e:
            st.warning(f"Failed to fetch/decode {key}: {e}")
        pbar.progress(int((idx + 1) / len(candidate_keys) * 100))
    pbar.empty()

    # Show results & download
    if results:
        df = pd.DataFrame(results)
        st.success(f"✅ {len(results)} matching fragments found!")
        st.dataframe(df)
        # produce ZIP
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            for fname, txt in fragment_files:
                try:
                    pretty = minidom.parseString(txt).toprettyxml(indent="  ")
                except Exception:
                    pretty = txt
                zf.writestr(fname, pretty)
        zip_buf.seek(0)
        st.download_button("⬇️ Download matching XMLs (ZIP)", zip_buf, "wasabi_matches.zip", "application/zip")
    else:
        st.warning("❌ No matches found across scanned objects.")

# Run when user presses the button
if run_search:
    run_full_wasabi_scan()

# Footer
st.markdown("---")
st.caption("Notes: This app reads Wasabi credentials from Streamlit secrets. Use prefix/filename filters and the cached index to limit scanned objects. XPath mode requires lxml and is namespace-aware.")
