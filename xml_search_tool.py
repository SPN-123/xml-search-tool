# --- Wasabi XML Search — Full Automation (drop-in script) ---
# Paste this entire file over your existing app.py

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
from typing import List, Tuple

# Optional dependencies: boto3 (required for Wasabi), lxml (recommended for XPath)
try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
except Exception:
    boto3 = None
    Config = None
    ClientError = Exception

try:
    from lxml import etree
    LXML_AVAILABLE = True
except Exception:
    LXML_AVAILABLE = False

# ------------------------ Page ------------------------
st.set_page_config(page_title="Wasabi XML Search — Full Automation + XPath + Index", layout="wide")
st.title("🔎 Wasabi XML Search — Full Automation (Wasabi-only) + XPath + Cached Index")

# ------------------------ Wasabi secrets ------------------------
wasabi_secrets = st.secrets.get("wasabi", {}) if isinstance(st.secrets, dict) or hasattr(st, "secrets") else {}
if wasabi_secrets:
    st.sidebar.markdown("**Wasabi secrets loaded (masked)**")
    st.sidebar.write("Bucket:", wasabi_secrets.get("bucket", "(not set)"))
    ak = wasabi_secrets.get("access_key", "")
    st.sidebar.write("Access key (masked):", (ak[:4] + "..." if ak else "(not set)"))
else:
    st.sidebar.warning("No Wasabi secrets found. Add them in Streamlit → Settings → Secrets.")
    st.stop()

# ------------------------ Sidebar: search params ------------------------
st.sidebar.header("Search & Wasabi Options (Full Automation)")
value1 = st.sidebar.text_input("Value 1 (required)", "")
value2 = st.sidebar.text_input("Value 2 (optional)", "")
value3 = st.sidebar.text_input("Value 3 (optional)", "")
value4 = st.sidebar.text_input("Value 4 (optional)", "")

search_mode = st.sidebar.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (node/attribute search)"])
use_regex = (search_mode == "Regular expression")
xpath_expr = st.sidebar.text_input("XPath expression (used when Search mode = XPath)", "")
debug_mode = st.sidebar.checkbox("Debug mode: show decode attempts & snippets", False)

st.sidebar.markdown("---")
st.sidebar.markdown("**Wasabi object selection & index**")
default_prefix = wasabi_secrets.get("prefix", "") if wasabi_secrets else ""
prefix = st.sidebar.text_input("Prefix (optional) — list only under this folder", default_prefix)
name_contains = st.sidebar.text_input("Filename contains (optional) — quick filename filter", "")
max_objects = st.sidebar.number_input("Max objects to scan", min_value=1, value=200, step=1)

st.sidebar.markdown("---")
index_action = st.sidebar.selectbox("Index action", ["Use cache if available", "Rebuild cache now", "Clear cache"])
index_sample_bytes = st.sidebar.number_input("Bytes to sample per object for index (Range GET)", min_value=256, max_value=65536, value=2048, step=256)

# Buttons
test_conn_btn = st.sidebar.button("Test Wasabi connection")
run_search = st.sidebar.button("Run Wasabi Search")

# ------------------------ Helpers: text/decoding ------------------------
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
    return '<pre style="white-space: pre-wrap;word-break:break-word;">' + html_snip + "</pre>"

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
    for _, candidate in tries:
        if not candidate or len(candidate) < 6:
            continue
        c = candidate.strip()
        if c.startswith("<?xml") or c.lstrip().startswith("<"):
            outputs.append(c)
        elif c.startswith("{") or c.startswith("["):
            try:
                payload = json.loads(c)
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

# ------------------------ Wasabi client (auto region/endpoint) ------------------------
def _endpoint_for_region(region: str) -> str:
    if not region or region == "us-east-1":
        return "https://s3.wasabisys.com"
    return f"https://s3.{region}.wasabisys.com"

def _discover_bucket_region(access_key: str, secret_key: str, bucket: str) -> str:
    if boto3 is None:
        raise RuntimeError("boto3 is required for Wasabi access. Run: pip install boto3")
    session = boto3.session.Session()
    s3_global = session.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url="https://s3.wasabisys.com",
        config=Config(signature_version="s3v4"),
    )
    try:
        resp = s3_global.head_bucket(Bucket=bucket)
        return resp["ResponseMetadata"]["HTTPHeaders"].get("x-amz-bucket-region", "us-east-1")
    except ClientError as e:
        headers = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        region = headers.get("x-amz-bucket-region")
        if region:
            return region
        raise

def get_s3_client(secrets: dict):
    if boto3 is None:
        raise RuntimeError("boto3 is required for Wasabi access. Run: pip install boto3")

    access_key = secrets.get("access_key")
    secret_key = secrets.get("secret_key")
    bucket     = secrets.get("bucket")
    if not (access_key and secret_key and bucket):
        raise RuntimeError("Missing wasabi.access_key / wasabi.secret_key / wasabi.bucket in Streamlit secrets.")

    # Region: use secrets if present else discover
    region = secrets.get("region") or _discover_bucket_region(access_key, secret_key, bucket)
    # Endpoint: use secrets if forced else build from region
    endpoint = secrets.get("endpoint_url") or _endpoint_for_region(region)
    # Addressing: path for buckets with dots (TLS host mismatch), else virtual
    addressing = "path" if "." in bucket else "virtual"

    cfg = Config(
        signature_version="s3v4",
        retries={"max_attempts": 4},
        s3={"addressing_style": addressing}
    )

    session = boto3.session.Session()
    client = session.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=cfg,
    )
    return client, region, endpoint, addressing

# ------------------------ S3 list/get with clear errors ------------------------
def list_wasabi_keys(client, bucket: str, prefix: str = "", max_items: int = 500) -> List[str]:
    try:
        paginator = client.get_paginator("list_objects_v2")
        keys = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
                if len(keys) >= max_items:
                    return keys
        return keys
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        msg  = e.response.get("Error", {}).get("Message")
        raise RuntimeError(f"S3 list error ({code}): {msg}")

def fetch_object_bytes(client, bucket: str, key: str, byte_range: str = None) -> bytes:
    try:
        kwargs = {"Bucket": bucket, "Key": key}
        if byte_range:
            kwargs["Range"] = byte_range
        resp = client.get_object(**kwargs)
        return resp["Body"].read()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        msg  = e.response.get("Error", {}).get("Message")
        raise RuntimeError(f"S3 get_object error for '{key}' ({code}): {msg}")

# ------------------------ Indexing (cached) ------------------------
@st.cache_data(show_spinner=False)
def build_index(secrets_serial: Tuple, bucket: str, prefix: str, name_contains: str, max_objects: int, sample_bytes: int) -> List[dict]:
    client, _, _, _ = get_s3_client(wasabi_secrets)
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
                sample = fetch_object_bytes(client, bucket, k)
            try:
                s = sample.decode('utf-8-sig', errors='ignore')
            except Exception:
                s = ''
            index.append({"key": k, "sample_text": s})
        except Exception:
            continue
    return index

# ------------------------ Search runner ------------------------
def run_full_wasabi_scan():
    # Prepare terms
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
        st.error("Bucket not set in Wasabi secrets. Add 'bucket' to the [wasabi] section.")
        return

    # Build client (auto region/endpoint)
    try:
        client, resolved_region, resolved_endpoint, addressing = get_s3_client(wasabi_secrets)
        if debug_mode:
            st.info(f"Resolved Wasabi → region={resolved_region} | endpoint={resolved_endpoint} | addressing={addressing}")
    except Exception as e:
        st.error(f"Failed to create S3 client: {e}")
        return

    # Handle index
    secrets_serial = (wasabi_secrets.get('access_key','')[:4], wasabi_secrets.get('endpoint_url',''),)
    if index_action == "Clear cache":
        st.cache_data.clear()
        st.success("Index cache cleared. Re-run to rebuild.")
        return

    try:
        if index_action == "Rebuild cache now":
            with st.spinner("Rebuilding index..."):
                index = build_index(secrets_serial, bucket, prefix or '', name_contains or '', int(max_objects), int(index_sample_bytes))
                st.success(f"Index built with {len(index)} entries.")
        else:
            index = build_index(secrets_serial, bucket, prefix or '', name_contains or '', int(max_objects), int(index_sample_bytes))
            if debug_mode:
                st.write(f"Index contains {len(index)} entries (cached or fresh).")
    except Exception as e:
        st.error(f"Failed to build/load index: {e}")
        return

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
            raw = fetch_object_bytes(client, bucket, key)
            parts = decode_if_needed(key, raw)
            if debug_mode:
                st.write(f"Decoded {len(parts)} parts from {key}.")
            for pi, txt in enumerate(parts):
                norm = normalize_text_for_search(txt)
                ok = False
                if search_mode == "XPath (node/attribute search)":
                    if not LXML_AVAILABLE:
                        st.error("lxml is required for XPath mode. Install with: pip install lxml")
                        return
                    try:
                        root = etree.fromstring(txt.encode('utf-8'))
                        nsmap = {k if k is not None else 'ns': v for k, v in root.nsmap.items()}
                        matches = root.xpath(xpath_expr, namespaces=nsmap)
                        ok = bool(matches)
                    except Exception as e:
                        if debug_mode:
                            st.write(f"XPath eval failed for {key} part {pi+1}: {e}")
                        ok = False
                else:
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
                        ok = all(term.lower() in norm.lower() for term in search_terms)

                if ok:
                    fname = f"{key.replace('/', '_')}_part{pi+1}.xml"
                    results.append({"File": fname, "SourceKey": key, "Part": pi+1})
                    fragment_files.append((fname, txt))
                    if debug_mode:
                        st.success(f"Match in {key} (part {pi+1})")
                        if search_mode == "XPath (node/attribute search)":
                            st.text_area(f"preview_{key}_{pi}", txt[:2000], height=200)
                        else:
                            html_preview = highlight_matches_html(txt, search_terms, search_mode=="Regular expression")
                            st.markdown(html_preview, unsafe_allow_html=True)
        except Exception as e:
            st.warning(f"Failed to fetch/decode {key}: {e}")
        pbar.progress(int((idx + 1) / len(candidate_keys) * 100))
    pbar.empty()

    if results:
        df = pd.DataFrame(results)
        st.success(f"✅ {len(results)} matching fragments found!")
        st.dataframe(df)
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

# ------------------------ Buttons handlers ------------------------
if test_conn_btn:
    try:
        client, rr, ep, addr = get_s3_client(wasabi_secrets)
        resp = client.head_bucket(Bucket=wasabi_secrets["bucket"])
        hdrs = resp["ResponseMetadata"]["HTTPHeaders"]
        st.sidebar.success(f"Connected ✓  region={rr}  endpoint={ep}  addressing={addr}")
        st.sidebar.write("x-amz-bucket-region:", hdrs.get("x-amz-bucket-region"))
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        msg  = e.response.get("Error", {}).get("Message")
        hdrs = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        st.sidebar.error(f"HeadBucket failed: {code}: {msg}")
        if hdrs.get("x-amz-bucket-region"):
            st.sidebar.info(f"Server suggests region: {hdrs.get('x-amz-bucket-region')}")
    except Exception as e:
        st.sidebar.error(f"Connection test failed: {e}")

if run_search:
    run_full_wasabi_scan()

# ------------------------ Footer ------------------------
st.markdown("---")
st.caption("Notes: Credentials come from Streamlit secrets [wasabi]. Endpoint/region are auto-resolved. Use prefix/filename filters and cached index to limit scans. XPath mode requires lxml.")
