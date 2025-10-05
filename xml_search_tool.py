# app.py — Wasabi XML/Text Finder: path + decoded text + XML (and XPath)
# Paste into Streamlit Cloud. Auto-installs boto3/lxml if needed.

import sys, subprocess
for pkg in ("boto3", "lxml"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

import re, gzip, base64, html, json
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
st.set_page_config(page_title="Wasabi Finder — Path + Decoded Text + XML", layout="wide")
st.title("🔍 Wasabi Finder — Search in Path, Decoded Text, and XML")

col1, col2 = st.columns([1.2, 2])
with col1:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with col2:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.markdown("### 📁 Prefix Scan (returns only objects that match)")
prefix = st.text_input("Prefix to scan (folder, ends with /)", "")
c1, c2, c3, c4 = st.columns([1.2, 1.6, 1.2, 1])
with c1:
    scan_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with c2:
    query = st.text_input("Search text / Regex / XPath (matched in path, decoded text, and XML)", "")
with c3:
    scope = st.selectbox("Where to search", ["All (Path + Decoded + XML)", "Path only", "Decoded+XML only", "XML only"])
with c4:
    max_keys = st.number_input("Max objects", min_value=1, value=500, step=1)

debug = st.checkbox("Debug")
run = st.button("🚀 Scan Prefix & Find Matches")

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

def sanitize_prefix(p):
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p); p = re.sub(r"/{2,}", "/", p)
    if p and not p.endswith("/"): p += "/"
    return p

def list_keys(s3, bucket, prefix, max_items):
    paginator = s3.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
            if len(keys) >= max_items: return keys
    return keys

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data.strip().replace("\n","").replace("\r",""))
    if len(data) % 4: data += "=" * (4 - len(data) % 4)
    return base64.b64decode(data)

def decode_candidates(raw: bytes):
    """Return list[(kind,text)] from: plain, gzip, base64(+gzip)."""
    tries = []
    # plain text
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except: pass
    # gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except: pass
    # base64 (+ maybe gzip)
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b[:2] == b"\x1f\x8b":
            try:
                t = gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()
                if t: tries.append(("b64+gzip", t))
            except: pass
        else:
            try:
                t = b.decode("utf-8-sig", errors="ignore").strip()
                if t: tries.append(("b64_text", t))
            except: pass
    except: pass
    return tries

def extract_xmls_from_text(t: str):
    """Pull XML out of text or JSON payloads. Return list[str] XMLs."""
    outs = []
    s = t.strip()
    # JSON payloads with embedded XML strings
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            payload = json.loads(s)
            def rec(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(v, str) and (v.strip().startswith("<") or v.strip().startswith("<?xml")):
                            outs.append(v.strip())
                        else:
                            rec(v)
                elif isinstance(o, list):
                    for it in o: rec(it)
            rec(payload)
        except: pass
    # XML-ish block or full XML
    if s.startswith("<") or s.startswith("<?xml"):
        outs.append(s)
    else:
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
    except:
        return txt

def highlight(text, term):
    esc = html.escape(text)
    pat = re.compile(re.escape(term), re.IGNORECASE)
    spans = [(m.start(), m.end()) for m in pat.finditer(esc)]
    if not spans: return f"<pre>{esc[:2000]}</pre>"
    out, p = [], 0
    for s,e in spans:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>"); p=e
    out.append(esc[p:])
    return f"<pre style='white-space:pre-wrap;word-break:break-word'>{''.join(out)[:20000]}</pre>"

# ---------------- Run ----------------
if run:
    try:
        if not (bucket and prefix and ak and sk and query.strip()):
            st.error("Please fill Bucket, Prefix, Access/Secret, and Query.")
            st.stop()

        pf = sanitize_prefix(prefix)
        s3, region, endpoint = get_client(ak, sk, bucket)
        keys = list_keys(s3, bucket, pf, int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix."); st.stop()

        use_xpath = (scan_mode == "XPath (requires lxml)")
        use_regex = (scan_mode == "Regular expression")
        if use_xpath and not LXML_AVAILABLE:
            st.error("lxml not available for XPath."); st.stop()

        # Prepare matcher for text/regex
        if not use_xpath:
            try:
                term_re = re.compile(query, re.IGNORECASE) if use_regex else re.compile(re.escape(query), re.IGNORECASE)
            except re.error as e:
                st.error(f"Invalid regex: {e}"); st.stop()

        matches = []  # [{key, where, preview, xml_or_text}]
        prog = st.progress(0)

        for i, key in enumerate(keys):
            found = False
            # A) PATH match
            if scope in ("All (Path + Decoded + XML)", "Path only"):
                if query.lower() in key.lower():
                    matches.append({"key": key, "where": "path", "preview": key, "xml_or_text": None})
                    found = True

            if scope != "Path only" and not found:
                try:
                    obj = s3.get_object(Bucket=bucket, Key=key)
                    raw = obj["Body"].read()
                    decoded_texts = [t for _, t in decode_candidates(raw)]
                    if not decoded_texts:
                        decoded_texts = [raw.decode("utf-8", errors="ignore")]

                    # B) DECODED TEXT match (even if not XML)
                    if scope in ("All (Path + Decoded + XML)", "Decoded+XML only"):
                        if not use_xpath:  # XPath only applies on XML
                            for txt in decoded_texts:
                                if term_re.search(txt):
                                    matches.append({"key": key, "where": "decoded", "preview": txt[:2000], "xml_or_text": txt})
                                    found = True
                                    break

                    # C) XML match (extracted)
                    if not found and scope in ("All (Path + Decoded + XML)", "Decoded+XML only", "XML only"):
                        xmls = []
                        for txt in decoded_texts:
                            xmls.extend(extract_xmls_from_text(txt))
                        seen=set(); xmls=[x for x in xmls if not (x in seen or seen.add(x))]

                        for xml in xmls:
                            if use_xpath:
                                try:
                                    root = etree.fromstring(xml.encode("utf-8"))
                                    nsmap = {k if k else 'ns': v for k,v in (getattr(root,"nsmap",{}) or {}).items()}
                                    res = root.xpath(query, namespaces=nsmap)
                                    if res:
                                        matches.append({"key": key, "where": "xpath", "preview": pretty_xml(xml)[:2000], "xml_or_text": pretty_xml(xml)})
                                        found = True; break
                                except Exception:
                                    continue
                            else:
                                if term_re.search(xml):
                                    px = pretty_xml(xml)
                                    matches.append({"key": key, "where": "xml", "preview": px[:2000], "xml_or_text": px})
                                    found = True; break
                except Exception as e:
                    if debug: st.write(f"{key}: {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not matches:
            st.error("❌ No matches found in path, decoded text, or XML.")
            st.stop()

        st.success(f"✅ Found {len(matches)} match(es).")
        st.dataframe([{"Key": m["key"], "Where": m["where"]} for m in matches])

        sel = st.selectbox("Preview which object?", [m["key"] for m in matches])
        chosen = next(m for m in matches if m["key"] == sel)

        # Download whichever content we have (XML if present, otherwise decoded text)
        content = chosen["xml_or_text"] or chosen["preview"] or ""
        st.download_button("⬇️ Download matched content", content, file_name="match.txt")

        if chosen["where"] in ("xml", "xpath"):
            st.subheader("Preview (XML)")
            st.code(content[:4000], language="xml")
        elif chosen["where"] == "decoded":
            st.subheader("Preview (decoded text)")
            st.markdown(highlight(content, query), unsafe_allow_html=True)
        else:
            st.info("Matched in path only (no content preview).")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Error: {e}")
