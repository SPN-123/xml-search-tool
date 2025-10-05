# app.py — Wasabi File Viewer & Search (single-file, paste-into-Streamlit)
# Works on Streamlit Cloud with NO extra files. Auto-installs boto3/lxml if missing.

import sys, subprocess

# --- Auto-install minimal dependencies if missing (Streamlit is already available on Cloud) ---
for pkg in ("boto3", "lxml"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

# --- Imports (after ensuring deps) ---
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

# ============================ UI ============================
st.set_page_config(page_title="Wasabi File Viewer & Search", layout="wide")
st.title("🔎 Wasabi File Viewer & Search — Single Script")

st.markdown(
    "Paste your **Wasabi S3 path** (e.g. `s3://my-bucket/folder/file.xml`), **or** fill **Bucket + File Path**.\n\n"
    "Enter your **Wasabi Access Key** and **Secret Key**, then click **Fetch & Search**."
)

with st.container():
    s3_path = st.text_input("S3 Path (example: s3://rzgnprdws-code-90d/RZBPD/05102025/.../UpdateAri.txt)")
    st.markdown("**— OR —**")
    c1, c2 = st.columns(2)
    with c1:
        bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
    with c2:
        file_path = st.text_input("File Path (relative under bucket)", "")

ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

c3, c4, c5 = st.columns([1.2, 1.2, 1])
with c3:
    search_mode = st.selectbox("Search Mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with c4:
    search_value = st.text_input("Search term / Regex / XPath", "")
with c5:
    debug = st.checkbox("Debug")

colA, colB = st.columns(2)
with colA:
    test_btn = st.button("🧪 Test Connection")
with colB:
    run_btn = st.button("🔍 Fetch & Search")

st.divider()

# ============================ Helpers ============================
def endpoint_for(region: str) -> str:
    return "https://s3.wasabisys.com" if not region or region == "us-east-1" else f"https://s3.{region}.wasabisys.com"

def discover_region(ak: str, sk: str, bucket: str) -> str:
    """Use HeadBucket to learn the bucket's region (x-amz-bucket-region)."""
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
    """Build a region-correct Wasabi S3 client. Path-style for dotted buckets."""
    region = discover_region(ak, sk, bucket)
    endpoint = endpoint_for(region)
    addressing = "path" if "." in bucket else "virtual"
    s3 = boto3.client(
        "s3",
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        endpoint_url=endpoint,
        region_name=region,
        config=Config(signature_version="s3v4", s3={"addressing_style": addressing})
    )
    return s3, region, endpoint, addressing

def parse_input_path(s3_path: str, bucket: str, key: str):
    """Return (bucket, key) from either s3://bucket/key or separate fields."""
    s3_path = (s3_path or "").strip()
    if s3_path.startswith("s3://"):
        m = re.match(r"^s3://([^/]+)/(.+)$", s3_path)
        if not m:
            raise ValueError("Invalid S3 path. Expecting s3://bucket/key")
        return m.group(1), m.group(2)
    if not bucket or not key:
        raise ValueError("Provide either a full S3 Path, or both Bucket and File Path.")
    return bucket.strip(), key.strip()

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data.strip().replace("\n", "").replace("\r", ""))
    pad = len(data) % 4
    if pad: data += "=" * (4 - pad)
    return base64.b64decode(data)

def decode_to_text(raw: bytes, debug=False) -> str:
    """Try plain → gzip → base64(+maybe gzip); prefer XML-looking if multiple succeed."""
    attempts = []
    # plain
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: attempts.append(("plain", t))
    except Exception: pass
    # gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: attempts.append(("gzip", t))
    except Exception: pass
    # base64 (+maybe gzip)
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b[:2] == b"\x1f\x8b":
            try:
                t = gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()
                attempts.append(("b64+gzip", t))
            except Exception: pass
        else:
            try:
                t = b.decode("utf-8-sig", errors="ignore").strip()
                attempts.append(("b64_text", t))
            except Exception: pass
    except Exception: pass

    if debug: st.write("Decode attempts:", [k for k, _ in attempts])
    for _, t in attempts:
        if t.startswith("<?xml") or t.lstrip().startswith("<"):
            return t
    if attempts: return attempts[0][1]
    return raw.decode("utf-8", errors="ignore")

def highlight_html(text: str, term: str, use_regex: bool) -> str:
    if not term:
        return f"<pre>{html.escape(text[:10000])}</pre>"
    esc = html.escape(text)
    matches = []
    if use_regex:
        try:
            matches = [(m.start(), m.end()) for m in re.finditer(term, esc, flags=re.IGNORECASE)]
        except re.error:
            return f"<pre>{esc[:10000]}</pre>"
    else:
        low = esc.lower(); tl = term.lower(); i = 0
        while True:
            i = low.find(tl, i)
            if i == -1: break
            matches.append((i, i + len(tl)))
            i += len(tl)
    if not matches:
        return f"<pre>{esc[:10000]}</pre>"
    out, p = [], 0
    for s, e in matches:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>")
        p = e
    out.append(esc[p:])
    snippet = "".join(out)
    if len(snippet) > 20000: snippet = snippet[:20000] + "..."
    return f'<pre style="white-space:pre-wrap;word-break:break-word;">{snippet}</pre>'

# ============================ Actions ============================
def test_connection(ak, sk, resolved_bucket):
    try:
        s3, region, endpoint, addr = get_client(ak, sk, resolved_bucket)
        s3.head_bucket(Bucket=resolved_bucket)
        st.success(f"Connected ✓  region={region} | endpoint={endpoint} | addressing={addr}")
    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"HeadBucket failed: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Test failed: {e}")

def fetch_and_search(ak, sk, resolved_bucket, key, mode, term, debug):
    st.info(f"Bucket: `{resolved_bucket}`  |  Key: `{key}`")
    try:
        s3, region, endpoint, addr = get_client(ak, sk, resolved_bucket)
        if debug: st.info(f"Resolved → region={region} | endpoint={endpoint} | addressing={addr}")
        obj = s3.get_object(Bucket=resolved_bucket, Key=key)
        raw = obj["Body"].read()
        text = decode_to_text(raw, debug=debug)
        st.success(f"Fetched OK. Decoded length: {len(text)} chars.")
        st.download_button("⬇️ Download decoded content", text, file_name="decoded.xml", mime="text/xml")

        if mode == "XPath (requires lxml)":
            if not LXML_AVAILABLE:
                st.error("Install lxml failed/unavailable; XPath not supported in this session.")
                return
            if not text.strip().startswith("<"):
                st.warning("File does not look like XML; XPath may fail.")
                return
            if not term.strip():
                st.warning("Enter an XPath expression to search.")
                return
            try:
                root = etree.fromstring(text.encode("utf-8"))
                nsmap = {}
                if hasattr(root, "nsmap") and isinstance(root.nsmap, dict):
                    nsmap = {k if k else 'ns': v for k, v in root.nsmap.items()}
                result = root.xpath(term, namespaces=nsmap)
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
            use_regex = (mode == "Regular expression")
            st.markdown(highlight_html(text, term, use_regex), unsafe_allow_html=True)

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Failed: {e}")

# ============================ Buttons ============================
if test_btn:
    try:
        bkt, key = parse_input_path(s3_path, bucket, file_path)
        test_connection(ak, sk, bkt)
    except Exception as e:
        st.error(str(e))

if run_btn:
    try:
        bkt, key = parse_input_path(s3_path, bucket, file_path)
        fetch_and_search(ak, sk, bkt, key, search_mode, search_value, debug)
    except Exception as e:
        st.error(str(e))
