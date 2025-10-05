# app.py — Wasabi Prefix Scanner: decode + find the ONE XML by date (single-file)
# Works on Streamlit Cloud. Auto-installs boto3/lxml if missing.

import sys, subprocess
for pkg in ("boto3", "lxml"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

import re, gzip, base64, html, io, json
import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from xml.dom import minidom
try:
    from lxml import etree
    LXML_AVAILABLE = True
except Exception:
    LXML_AVAILABLE = False

# ============================ UI ============================
st.set_page_config(page_title="Wasabi XML Finder — decode + date filter", layout="wide")
st.title("🔎 Wasabi XML Finder — Decode + Date Filter (Single Script)")

st.markdown("Fill your **Bucket**, a **Prefix** (folder), and your Wasabi **Access/Secret**. "
            "Enter the **date (e.g., 2025-10-25)** to find the **one** XML that contains it.")

c1, c2 = st.columns([1.2, 2])
with c1:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with c2:
    prefix = st.text_input("Prefix to scan (e.g. RZBPD/05102025/Agoda/7140/611431_3541090/UpdateRestrictions/)", "")

ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

c3, c4, c5 = st.columns([1.2, 1.2, 1])
with c3:
    search_mode = st.selectbox("Search Mode (for preview)", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with c4:
    search_value = st.text_input("Search term / Regex / XPath (optional preview)", "")
with c5:
    debug = st.checkbox("Debug")

st.markdown("**Target date (required)** — the app will pick the ONE XML that contains this date:")
target_date = st.text_input("Date string (e.g. 2025-10-25)", "")

cA, cB, cC = st.columns([1,1,1])
with cA:
    test_btn = st.button("🧪 Test Connection")
with cB:
    list_btn = st.button("📂 List under Prefix")
with cC:
    run_btn = st.button("🎯 Find XML that contains the date")

st.divider()

# ============================ Helpers ============================
def endpoint_for(region: str) -> str:
    return "https://s3.wasabisys.com" if not region or region == "us-east-1" else f"https://s3.{region}.wasabisys.com"

def discover_region(ak: str, sk: str, bucket: str) -> str:
    s3g = boto3.client("s3",
        aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url="https://s3.wasabisys.com",
        config=Config(signature_version="s3v4"))
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

def sanitize_prefix(p: str) -> str:
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p)
    p = re.sub(r"/{2,}", "/", p)
    return p

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data.strip().replace("\n","").replace("\r",""))
    if len(data) % 4: data += "=" * (4 - len(data) % 4)
    return base64.b64decode(data)

def decode_candidates(raw: bytes, debug=False):
    """
    Return list of (kind, text) decoding attempts.
    We’ll later choose the most XML-looking candidate, or scan all for XML fragments.
    """
    tries = []
    # 1) plain
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except Exception: pass
    # 2) gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except Exception: pass
    # 3) base64 (+maybe gzip)
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

    if debug: st.write("Decode attempts kinds:", [k for k,_ in tries])
    return tries

def extract_xml_from_text(t: str) -> list[str]:
    """
    Tries to pull XML body out of a text that might contain JSON or extra wrappers.
    - Handles JSON with RqPayload/RsPayload
    - Otherwise uses a relaxed XML-ish regex to capture first XML block
    Returns list of XML strings (may be multiple if present).
    """
    outs = []
    s = t.strip()
    # JSON with payloads
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            payload = json.loads(s)
            candidates = []
            def rec(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if k in ("RqPayload","RsPayload","xml","XML") and isinstance(v, str):
                            candidates.append(v)
                        else:
                            rec(v)
                elif isinstance(o, list):
                    for it in o: rec(it)
            rec(payload)
            for c in candidates:
                cs = c.strip()
                if cs.startswith("<") or cs.startswith("<?xml"):
                    outs.append(cs)
        except Exception:
            pass
    # Generic regex for XML-like block
    if not outs:
        m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
        if m:
            outs.append(m.group(0))
    # Plain XML
    if s.startswith("<") or s.startswith("<?xml"):
        outs.append(s)
    # Unique
    uniq = []
    for x in outs:
        if x not in uniq:
            uniq.append(x)
    return uniq

def pretty_xml(xml_text: str) -> str:
    try:
        return minidom.parseString(xml_text).toprettyxml(indent="  ")
    except Exception:
        return xml_text

def list_keys_under_prefix(ak, sk, bucket, prefix, max_keys=2000):
    s3, *_ = get_client(ak, sk, bucket)
    paginator = s3.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
            if len(keys) >= max_keys:
                return keys
    return keys

def highlight(text: str, term: str, use_regex: bool) -> str:
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
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>"); p=e
    out.append(esc[p:])
    snip = "".join(out)
    if len(snip)>20000: snip = snip[:20000] + "..."
    return f'<pre style="white-space:pre-wrap;word-break:break-word;">{snip}</pre>'

# ============================ Actions ============================
if test_btn:
    try:
        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        s3.head_bucket(Bucket=bucket)
        st.success(f"Connected ✓  region={region}  endpoint={endpoint}  addressing={addr}")
    except Exception as e:
        st.error(f"Test failed: {e}")

if list_btn:
    try:
        pf = sanitize_prefix(prefix)
        st.info(f"Listing up to 2,000 keys under: `{pf}`")
        keys = list_keys_under_prefix(ak, sk, bucket, pf, max_keys=2000)
        if not keys:
            st.warning("No objects under that prefix.")
        else:
            st.success(f"Found {len(keys)} objects. Showing first 100:")
            st.code("\n".join(keys[:100]))
    except Exception as e:
        st.error(f"List failed: {e}")

if run_btn:
    if not (bucket and ak and sk and target_date.strip()):
        st.error("Bucket, Access, Secret, and Target Date are required.")
        st.stop()
    pf = sanitize_prefix(prefix)
    if not pf:
        st.error("Please provide a prefix (folder) to scan.")
        st.stop()

    try:
        keys = list_keys_under_prefix(ak, sk, bucket, pf, max_keys=2000)
        if not keys:
            st.warning("No objects found under that prefix."); st.stop()

        st.info(f"Scanning {len(keys)} objects to find the one containing: **{target_date}**")
        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        if debug: st.info(f"Resolved → region={region} | endpoint={endpoint} | addressing={addr}")

        match_key = None
        match_xml = None
        details = []

        prog = st.progress(0)
        for i, key in enumerate(keys):
            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()

                # try several decode candidates and extract XML from each
                tries = decode_candidates(raw, debug=False)
                # also include raw utf-8 fallback
                texts = [t for _, t in tries]
                if not texts:
                    texts = [raw.decode("utf-8", errors="ignore")]

                found_xmls = []
                for t in texts:
                    found_xmls.extend(extract_xml_from_text(t))
                # de-dup
                seen = set(); found_xmls = [x for x in found_xmls if not (x in seen or seen.add(x))]

                # If no XML found, continue
                if not found_xmls:
                    details.append((key, "no-xml"))
                else:
                    # If any XML contains the target date, pick the first one and stop
                    for xml in found_xmls:
                        if target_date in xml:
                            match_key = key
                            match_xml = xml
                            break
                if match_key:
                    break
            except Exception as e:
                details.append((key, f"error: {e}"))
            finally:
                prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not match_key:
            st.error(f"❌ No XML containing **{target_date}** was found under the prefix.")
            if debug and details:
                st.write("Scan details:", details[:20])
            st.stop()

        # Pretty print + download
        pretty = pretty_xml(match_xml)
        st.success(f"✅ Found matching XML in object:\n\n`{match_key}`")
        st.download_button("⬇️ Download decoded XML", pretty, file_name="matched.xml", mime="text/xml")

        # Optional preview search on the chosen XML
        if search_mode == "XPath (requires lxml)":
            if not LXML_AVAILABLE:
                st.error("lxml not available for XPath.")
            else:
                try:
                    root = etree.fromstring(match_xml.encode("utf-8"))
                    nsmap = {}
                    if hasattr(root, "nsmap") and isinstance(root.nsmap, dict):
                        nsmap = {k if k else 'ns': v for k, v in root.nsmap.items()}
                    if search_value.strip():
                        found = root.xpath(search_value, namespaces=nsmap)
                        st.info(f"XPath matched {len(found)} node(s). Showing up to 10.")
                        for node in found[:10]:
                            try:
                                frag = etree.tostring(node, pretty_print=True, encoding=str)
                            except Exception:
                                frag = str(node)
                            st.code(frag[:2000], language="xml")
                except Exception as e:
                    st.error(f"XPath error: {e}")
        else:
            # Highlight (literal/regex) within the pretty XML
            use_regex = (search_mode == "Regular expression")
            term = search_value.strip() or target_date  # default to date if preview term empty
            st.markdown(highlight(pretty, term, use_regex), unsafe_allow_html=True)

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Failed: {e}")
