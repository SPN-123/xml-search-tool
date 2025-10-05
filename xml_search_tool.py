# app.py — Wasabi File Viewer + Prefix Browser + Search (single-file)
# Paste this entire script into Streamlit Cloud (or local). No other files needed.

import sys, subprocess
# Ensure deps (boto3 & lxml) are present on Cloud; Streamlit is already there.
for pkg in ("boto3", "lxml"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

import re, gzip, base64, html
import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
try:
    from lxml import etree
    LXML_AVAILABLE = True
except Exception:
    LXML_AVAILABLE = False

# ================= UI =================
st.set_page_config(page_title="Wasabi File Viewer + Browser + Search", layout="wide")
st.title("🔎 Wasabi File Viewer + Browser + Search")

st.markdown("Fill **Bucket**, either a full **S3 path** (`s3://bucket/key`) or **Bucket + File Path**.\n"
            "Use the **Prefix Browser** to list files if you’re unsure of the exact key.")

cpath = st.text_input("Full S3 Path (optional, e.g. s3://rzgnprdws-code-90d/RZBPD/05102025/.../file.txt)", "")
c1, c2 = st.columns(2)
with c1:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with c2:
    file_path = st.text_input("File Path (key under bucket, e.g. RZBPD/05102025/.../file.txt)", "")

ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.divider()
# Prefix browser
st.subheader("📁 Prefix Browser (list files in a folder)")
bp1, bp2 = st.columns([2,1])
with bp1:
    prefix = st.text_input("Prefix (folder), e.g. RZBPD/05102025/Agoda/7140/611431_3541090/UpdateRestrictions/", "")
with bp2:
    list_btn = st.button("List under Prefix")

sel_key = st.selectbox("Select a file from the prefix (if listed below)", options=[], index=None, placeholder="— nothing listed yet —")

st.divider()
# Search controls
c3, c4, c5 = st.columns([1.2, 1.2, 1])
with c3:
    search_mode = st.selectbox("Search Mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with c4:
    search_value = st.text_input("Search term / Regex / XPath", "")
with c5:
    debug = st.checkbox("Debug")

cA, cB = st.columns(2)
with cA:
    test_btn = st.button("🧪 Test Connection")
with cB:
    run_btn = st.button("🔍 Fetch & Search")

st.divider()

# ================= Helpers =================
def endpoint_for(region: str) -> str:
    return "https://s3.wasabisys.com" if not region or region == "us-east-1" else f"https://s3.{region}.wasabisys.com"

def discover_region(ak: str, sk: str, bucket: str) -> str:
    s3g = boto3.client(
        "s3", aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url="https://s3.wasabisys.com",
        config=Config(signature_version="s3v4")
    )
    try:
        resp = s3g.head_bucket(Bucket=bucket)
        return resp["ResponseMetadata"]["HTTPHeaders"].get("x-amz-bucket-region", "us-east-1")
    except ClientError as e:
        hdrs = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        return hdrs.get("x-amz-bucket-region", "us-east-1")

def get_client(ak: str, sk: str, bucket: str):
    region = discover_region(ak, sk, bucket)
    endpoint = endpoint_for(region)
    addressing = "path" if "." in bucket else "virtual"
    s3 = boto3.client(
        "s3",
        aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url=endpoint, region_name=region,
        config=Config(signature_version="s3v4", s3={"addressing_style": addressing})
    )
    return s3, region, endpoint, addressing

def parse_path(s3_path: str, bucket: str, key: str):
    s3_path = (s3_path or "").strip()
    bucket = (bucket or "").strip()
    key = (key or "").strip()
    if s3_path.startswith("s3://"):
        m = re.match(r"^s3://([^/]+)/(.+)$", s3_path)
        if not m: raise ValueError("Invalid S3 path. Expect s3://bucket/key")
        return m.group(1).strip(), sanitize_key(m.group(2))
    if not bucket or not key:
        raise ValueError("Provide either a full S3 path OR both Bucket and File Path.")
    return bucket, sanitize_key(key)

def sanitize_key(key: str) -> str:
    # remove leading slashes/spaces, collapse duplicate slashes, strip trailing spaces
    key = key.replace("\\", "/").strip()
    key = re.sub(r"^/+", "", key)
    key = re.sub(r"/{2,}", "/", key)
    return key

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data.strip().replace("\n", "").replace("\r", ""))
    pad = len(data) % 4
    if pad: data += "=" * (4 - pad)
    return base64.b64decode(data)

def decode_to_text(raw: bytes, dbg=False) -> str:
    tries = []
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except Exception: pass
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except Exception: pass
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b[:2] == b"\x1f\x8b":
            try:
                t = gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()
                if t: tries.append(("b64+gzip", t))
            except Exception: pass
        else:
            try:
                t = b.decode("utf-8-sig", errors="ignore").strip()
                if t: tries.append(("b64_text", t))
            except Exception: pass
    except Exception: pass
    if dbg: st.write("Decode attempts:", [k for k,_ in tries])
    for _,t in tries:
        if t.startswith("<?xml") or t.lstrip().startswith("<"):
            return t
    if tries: return tries[0][1]
    return raw.decode("utf-8", errors="ignore")

def highlight_html(text: str, term: str, use_regex: bool) -> str:
    if not term: return f"<pre>{html.escape(text[:10000])}</pre>"
    esc = html.escape(text); matches=[]
    if use_regex:
        try:
            matches = [(m.start(), m.end()) for m in re.finditer(term, esc, flags=re.IGNORECASE)]
        except re.error:
            return f"<pre>{esc[:10000]}</pre>"
    else:
        low, tl = esc.lower(), term.lower()
        i = 0
        while True:
            i = low.find(tl, i)
            if i == -1: break
            matches.append((i, i+len(tl)))
            i += len(tl)
    if not matches: return f"<pre>{esc[:10000]}</pre>"
    out, p = [], 0
    for s,e in matches:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>")
        p = e
    out.append(esc[p:])
    snip = "".join(out)
    if len(snip) > 20000: snip = snip[:20000] + "..."
    return f'<pre style="white-space:pre-wrap;word-break:break-word;">{snip}</pre>'

def list_under_prefix(ak, sk, bucket, prefix, max_keys=500):
    s3, *_ = get_client(ak, sk, bucket)
    paginator = s3.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=sanitize_key(prefix or "")):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
            if len(keys) >= max_keys:
                return keys
    return keys

def head_exists(ak, sk, bucket, key) -> bool:
    s3, *_ = get_client(ak, sk, bucket)
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
            return False
        raise

# ============== Actions ==============
if test_btn:
    try:
        if cpath:
            bkt, _ = parse_path(cpath, "", "")
        else:
            if not bucket: raise ValueError("Bucket required for test.")
            bkt = bucket.strip()
        s3, region, endpoint, addr = get_client(ak, sk, bkt)
        s3.head_bucket(Bucket=bkt)
        st.success(f"Connected ✓ region={region} | endpoint={endpoint} | addressing={addr}")
    except Exception as e:
        st.error(f"Test failed: {e}")

# List prefix
if list_btn:
    try:
        if not (bucket and ak and sk):
            st.error("Bucket, Access Key, Secret Key required to list."); 
        else:
            p = sanitize_key(prefix)
            st.info(f"Listing up to 500 keys under prefix: `{p}` …")
            keys = list_under_prefix(ak, sk, bucket, p, max_keys=500)
            if not keys:
                st.warning("No objects under that prefix.")
            else:
                st.success(f"Found {len(keys)} objects.")
                # Render a selectbox with keys; user can copy one into File Path
                choice = st.selectbox("Keys found (copy one into 'File Path'):", keys, index=0)
                st.code(choice)
                st.info("Tip: copy the selected key and paste it into the 'File Path' field above, then click Fetch.")
    except Exception as e:
        st.error(f"List failed: {e}")

# User-picked selection (from the top selectbox) overwrites file_path if chosen there
if sel_key:
    file_path = sel_key

if run_btn:
    try:
        bkt, key = parse_path(cpath, bucket, file_path)
        key = sanitize_key(key)
        st.info(f"Bucket: `{bkt}` | Key: `{key}`")

        # If key missing, suggest nearby matches under its parent prefix
        if not head_exists(ak, sk, bkt, key):
            parent = key.rsplit("/", 1)[0] + "/" if "/" in key else ""
            st.error("NoSuchKey — that exact file was not found.")
            st.info(f"Browsing parent prefix: `{parent}`")
            nearby = list_under_prefix(ak, sk, bkt, parent, max_keys=200)
            if nearby:
                st.write("Here are nearby keys (copy the correct one into 'File Path'):")
                st.code("\n".join(nearby[:50]))
            st.stop()

        s3, region, endpoint, addr = get_client(ak, sk, bkt)
        if debug: st.info(f"Resolved → region={region} | endpoint={endpoint} | addressing={addr}")
        obj = s3.get_object(Bucket=bkt, Key=key)
        raw = obj["Body"].read()
        text = decode_to_text(raw, dbg=debug)
        st.success(f"Fetched OK. Decoded size: {len(text)} chars.")
        st.download_button("⬇️ Download decoded content", text, file_name="decoded.xml", mime="text/xml")

        if search_mode == "XPath (requires lxml)":
            if not LXML_AVAILABLE:
                st.error("lxml unavailable; install failed in this session. XPath not supported.")
            elif not text.strip().startswith("<"):
                st.warning("File is not XML; XPath won't work.")
            elif not search_value.strip():
                st.warning("Enter an XPath expression.")
            else:
                try:
                    root = etree.fromstring(text.encode("utf-8"))
                    nsmap = {}
                    if hasattr(root, "nsmap") and isinstance(root.nsmap, dict):
                        nsmap = {k if k else 'ns': v for k, v in root.nsmap.items()}
                    result = root.xpath(search_value, namespaces=nsmap)
                    st.info(f"XPath matched {len(result)} nodes (showing up to 10).")
                    for node in result[:10]:
                        try:
                            frag = etree.tostring(node, pretty_print=True, encoding=str)
                        except Exception:
                            frag = str(node)
                        st.code(frag[:2000], language="xml")
                except Exception as e:
                    st.error(f"XPath error: {e}")
        else:
            st.markdown(
                highlight_html(text, search_value, use_regex=(search_mode == "Regular expression")),
                unsafe_allow_html=True
            )
    except Exception as e:
        st.error(str(e))
