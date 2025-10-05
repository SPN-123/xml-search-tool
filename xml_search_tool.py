# app.py — Wasabi Finder (Path + Decoded Text + XML + XPath) with strong diagnostics
# Paste into Streamlit Cloud. No other files needed.

import sys, subprocess
for pkg in ("boto3", "lxml"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

import re, gzip, base64, json, html
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

# ---------------- UI ----------------
st.set_page_config(page_title="Wasabi Finder — Path + Decoded + XML", layout="wide")
st.title("🔍 Wasabi Finder — Search in Path, Decoded Text, XML (with Diagnostics)")

col1, col2 = st.columns([1.2, 2])
with col1:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with col2:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.markdown("### 📁 Prefix Scan (returns only objects that match)")
prefix = st.text_input("Prefix to scan (folder; I will auto-append “/”)", "")
c1, c2, c3, c4 = st.columns([1.2, 1.6, 1.2, 1])
with c1:
    scan_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with c2:
    query = st.text_input("Search text / Regex / XPath (matched in path, decoded text, and XML)", "")
with c3:
    scope = st.selectbox("Where to search", ["All (Path + Decoded + XML)", "Path only", "Decoded+XML only", "XML only"])
with c4:
    max_keys = st.number_input("Max objects", min_value=1, value=500, step=1)

dbg1, dbg2 = st.columns([1,1])
with dbg1:
    debug = st.checkbox("Debug (show decoding per object)")
with dbg2:
    case_sensitive = st.checkbox("Case sensitive", value=False)

run = st.button("🚀 Scan Prefix & Find Matches")

st.divider()
st.markdown("### 🧪 Peek one object (paste exact key to see how it decodes)")
peek_key = st.text_input("Exact object key (optional, e.g. RZBPD/.../UpdateRestrictions/abc.txt)", "")
peek_btn = st.button("🔍 Peek this object")

st.divider()

# ---------------- Helpers ----------------
def endpoint_for(region):
    return "https://s3.wasabisys.com" if not region or region == "us-east-1" else f"https://s3.{region}.wasabisys.com"

def discover_region(ak, sk, bucket):
    s3g = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk,
                       endpoint_url="https://s3.wasabisys.com",
                       config=Config(signature_version="s3v4"))
    try:
        resp = s3g.head_bucket(Bucket=bucket)
        return resp["ResponseMetadata"]["HTTPHeaders"].get("x-amz-bucket-region", "us-east-1")
    except ClientError as e:
        hdrs = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        return hdrs.get("x-amz-bucket-region", "us-east-1")

def get_client(ak, sk, bucket):
    region = discover_region(ak, sk, bucket)
    endpoint = endpoint_for(region)
    s3 = boto3.client("s3",
        aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url=endpoint, region_name=region,
        config=Config(signature_version="s3v4"))
    return s3, region, endpoint

def fix_prefix(p):
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p)
    p = re.sub(r"/{2,}", "/", p)
    if p and not p.endswith("/"): p += "/"
    return p

def list_keys(s3, bucket, prefix, max_items):
    paginator = s3.get_paginator("list_objects_v2")
    out = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            out.append(obj["Key"])
            if len(out) >= max_items: return out
    return out

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", (data or "").strip().replace("\n","").replace("\r",""))
    if not data: return b""
    if len(data) % 4: data += "=" * (4 - len(data) % 4)
    return base64.b64decode(data)

def decode_candidates(raw: bytes):
    """
    Return list[(kind, text)] from raw bytes:
    - plain
    - gzip
    - base64_text
    - b64+gzip
    Always returns at least one candidate (utf-8 ignore) when possible.
    """
    tries = []
    # plain
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except Exception: pass
    # gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except Exception: pass
    # base64 (+maybe gzip)
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b:
            if len(b) > 2 and b[:2] == b"\x1f\x8b":
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
    # fallback
    if not tries:
        try:
            t = raw.decode("utf-8", errors="ignore")
            if t: tries.append(("fallback", t))
        except Exception:
            pass
    return tries

def extract_xmls_from_text(t: str):
    outs = []
    s = (t or "").strip()
    # JSON payloads that contain XML strings
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            payload = json.loads(s)
            def rec(o):
                if isinstance(o, dict):
                    for _, v in o.items():
                        if isinstance(v, str):
                            vs = v.strip()
                            if vs.startswith("<") or vs.startswith("<?xml"):
                                outs.append(vs)
                        else:
                            rec(v)
                elif isinstance(o, list):
                    for it in o: rec(it)
            rec(payload)
        except Exception:
            pass
    # Full XML text
    if s.startswith("<") or s.startswith("<?xml"):
        outs.append(s)
    else:
        # Relaxed XML-ish block
        m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
        if m: outs.append(m.group(0))
    # unique
    seen=set(); uniq=[]
    for x in outs:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def pretty_xml(txt):
    try:
        return minidom.parseString(txt).toprettyxml(indent="  ")
    except Exception:
        return txt

def compile_text_pattern(term: str, case_sensitive: bool, regex: bool):
    flags = 0 if case_sensitive else re.IGNORECASE
    if regex:
        return re.compile(term, flags)
    return re.compile(re.escape(term), flags)

def highlight(text, pattern: re.Pattern):
    esc = html.escape(text or "")
    spans = [(m.start(), m.end()) for m in pattern.finditer(esc)]
    if not spans: return f"<pre>{esc[:2000]}</pre>"
    out, p = [], 0
    for s,e in spans:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>"); p=e
    out.append(esc[p:])
    snip = "".join(out)
    if len(snip) > 20000: snip = snip[:20000] + "..."
    return f"<pre style='white-space:pre-wrap;word-break:break-word'>{snip}</pre>"

# ---------------- Peek one object ----------------
if peek_btn:
    try:
        if not (bucket and ak and sk and peek_key.strip()):
            st.error("Bucket, keys and exact object key are required.")
            st.stop()
        s3, region, endpoint = get_client(ak, sk, bucket)
        st.info(f"Fetching `{peek_key}` …")
        obj = s3.get_object(Bucket=bucket, Key=peek_key.strip())
        raw = obj["Body"].read()
        tries = decode_candidates(raw)
        if not tries:
            st.warning("Could not decode anything.")
        else:
            st.success(f"Decode kinds found: {[k for k,_ in tries]}")
            for kind, text in tries[:3]:   # show up to 3 variants
                st.write(f"**{kind}** — preview:")
                st.code(text[:2000])
            # Show XML extraction, if any
            extracted = []
            for _, t in tries:
                extracted.extend(extract_xmls_from_text(t))
            if extracted:
                st.info(f"Extracted {len(extracted)} XML candidate(s) — showing first pretty copy:")
                st.code(pretty_xml(extracted[0])[:4000], language="xml")
            else:
                st.warning("No XML block extracted from decoded text (file may be plain text).")
    except Exception as e:
        st.error(f"Peek failed: {e}")

# ---------------- Scan prefix ----------------
if run:
    try:
        if not (bucket and prefix and ak and sk and query.strip()):
            st.error("Please fill Bucket, Prefix, Access/Secret and Query.")
            st.stop()

        pf = fix_prefix(prefix)
        s3, region, endpoint = get_client(ak, sk, bucket)
        keys = list_keys(s3, bucket, pf, int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix."); st.stop()

        st.info(f"Scanning {len(keys)} object(s) under `{pf}` (region {region}) …")

        use_xpath = (scan_mode == "XPath (requires lxml)")
        if use_xpath and not LXML_AVAILABLE:
            st.error("lxml not available for XPath."); st.stop()
        text_pat = None if use_xpath else compile_text_pattern(query, case_sensitive, regex=(scan_mode=="Regular expression"))

        matches = []
        prog = st.progress(0)

        for i, key in enumerate(keys):
            key_hit = False
            # A) Path search
            if scope in ("All (Path + Decoded + XML)", "Path only"):
                if (query in key) if case_sensitive else (query.lower() in key.lower()):
                    matches.append({"key": key, "where": "path", "content": None})
                    key_hit = True

            if scope == "Path only":
                prog.progress(int((i+1)/len(keys)*100)); continue

            # B/C) Decode object and search decoded text + XML
            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()
                tries = decode_candidates(raw)
                decoded_texts = [t for _, t in tries] or [raw.decode("utf-8", errors="ignore")]

                # Optional debug
                if debug:
                    st.write(f"**{key}** → decode kinds: {[k for k,_ in tries] or ['fallback']}")

                # B) Decoded text match (even if not XML)
                if scope in ("All (Path + Decoded + XML)", "Decoded+XML only"):
                    if not use_xpath:
                        for txt in decoded_texts:
                            if text_pat.search(txt):
                                matches.append({"key": key, "where": "decoded", "content": txt})
                                key_hit = True
                                break

                # C) XML extraction + match
                if not key_hit and scope in ("All (Path + Decoded + XML)", "Decoded+XML only", "XML only"):
                    xmls = []
                    for t in decoded_texts:
                        xmls.extend(extract_xmls_from_text(t))
                    # unique
                    seen=set(); xmls=[x for x in xmls if not (x in seen or seen.add(x))]
                    for xml in xmls:
                        if use_xpath:
                            try:
                                root = etree.fromstring(xml.encode("utf-8"))
                                nsmap = {k if k else 'ns': v for k, v in (getattr(root, "nsmap", {}) or {}).items()}
                                if root.xpath(query, namespaces=nsmap):
                                    matches.append({"key": key, "where": "xml:xpath", "content": pretty_xml(xml)})
                                    key_hit = True
                                    break
                            except Exception:
                                continue
                        else:
                            if text_pat.search(xml):
                                matches.append({"key": key, "where": "xml:text", "content": pretty_xml(xml)})
                                key_hit = True
                                break

            except Exception as e:
                if debug:
                    st.write(f"{key}: error {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not matches:
            st.error("❌ No matches found in path, decoded text, or XML.")
            st.stop()

        st.success(f"✅ Found {len(matches)} match(es).")
        st.dataframe([{"Key": m["key"], "Where": m["where"]} for m in matches])

        sel = st.selectbox("Preview which match?", [m["key"] for m in matches])
        chosen = next(m for m in matches if m["key"] == sel)

        content = chosen["content"]
        if content is None:
            st.info("Matched by PATH; no content to preview.")
        else:
            if chosen["where"].startswith("xml"):
                st.subheader("Preview (XML)")
                st.code(content[:4000], language="xml")
            else:
                st.subheader("Preview (decoded text)")
                st.markdown(highlight(content, text_pat), unsafe_allow_html=True)

        st.download_button("⬇️ Download matched content", (content or "").encode("utf-8"), file_name="match.txt")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Error: {e}")
