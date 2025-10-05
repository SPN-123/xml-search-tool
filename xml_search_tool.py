# app.py — Wasabi XML Finder: Single File + Prefix Scan (Generic Search) + Decode + Preview
# Paste into Streamlit Cloud. Ensures boto3/lxml are available at runtime.

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

# --------- UI ---------
st.set_page_config(page_title="Wasabi XML Finder — Generic Search", layout="wide")
st.title("🔎 Wasabi XML Finder — Generic Search Across XMLs")

st.markdown(
    "Use **File Path** to fetch/preview one file, or **Prefix Scan** to search **all XMLs** in a folder.\n"
    "The tool auto-decodes plain / gzip / base64(+gzip) and extracts XML even if embedded in JSON."
)

col_bucket, col_ak = st.columns([1.2, 2])
with col_bucket:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with col_ak:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.markdown("### 📄 Single File Mode (exact path)")
file_path = st.text_input("File Path (exact object key under bucket, e.g. RZBPD/05102025/.../UpdateAri.txt)", "")

s_c1, s_c2, s_c3 = st.columns([1.1, 1.2, 1])
with s_c1:
    single_search_mode = st.selectbox("Preview search", ["None", "Literal text", "Regular expression", "XPath (requires lxml)"])
with s_c2:
    single_search_value = st.text_input("Search term / Regex / XPath (for single file)", "")
with s_c3:
    debug = st.checkbox("Debug")

fetch_btn = st.button("📥 Fetch & Preview Single File")

st.divider()

st.markdown("### 📁 Prefix Scan Mode (search across all XMLs in a folder)")
prefix = st.text_input("Prefix to scan (folder, ends with /)", "")
p_c1, p_c2, p_c3 = st.columns([1.3, 1.3, 1])
with p_c1:
    scan_search_mode = st.selectbox("Scan search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with p_c2:
    scan_query = st.text_input("Search text / Regex / XPath to match **inside** XML", "")
with p_c3:
    max_keys = st.number_input("Max objects to scan", min_value=1, value=500, step=1)

scan_btn = st.button("🚀 Scan Prefix & Return Only Matched XMLs")

st.divider()

# --------- Helpers ---------
def endpoint_for(region: str) -> str:
    return "https://s3.wasabisys.com" if not region or region == "us-east-1" else f"https://s3.{region}.wasabisys.com"

def discover_region(ak: str, sk: str, bucket: str) -> str:
    s3g = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk,
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
    s3 = boto3.client("s3",
        aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url=endpoint, region_name=region,
        config=Config(signature_version="s3v4", s3={"addressing_style": addressing}))
    return s3, region, endpoint, addressing

def sanitize_key(key: str) -> str:
    key = (key or "").replace("\\", "/").strip()
    key = re.sub(r"^/+", "", key)
    key = re.sub(r"/{2,}", "/", key)
    return key

def sanitize_prefix(p: str) -> str:
    p = sanitize_key(p)
    if p and not p.endswith("/"): p += "/"
    return p

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data.strip().replace("\n","").replace("\r",""))
    if len(data) % 4: data += "=" * (4 - len(data) % 4)
    return base64.b64decode(data)

def decode_candidates(raw: bytes):
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
    return tries

def extract_xmls_from_text(t: str) -> list[str]:
    outs = []
    s = t.strip()
    # JSON payloads with embedded XML
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
    # relaxed XML-ish regex
    m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
    if m: outs.append(m.group(0))
    # plain full XML
    if s.startswith("<") or s.startswith("<?xml"): outs.append(s)
    # unique
    seen=set(); final=[]
    for x in outs:
        if x not in seen:
            seen.add(x); final.append(x)
    return final

def pretty_xml(xml_text: str) -> str:
    try:
        return minidom.parseString(xml_text).toprettyxml(indent="  ")
    except Exception:
        return xml_text

def list_keys(ak, sk, bucket, prefix, max_items=500):
    s3, *_ = get_client(ak, sk, bucket)
    paginator = s3.get_paginator("list_objects_v2")
    out = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            out.append(obj["Key"])
            if len(out) >= max_items: return out
    return out

def regex_from_literal(term: str) -> re.Pattern:
    return re.compile(re.escape(term), re.IGNORECASE)

def highlight_html_with_regex(text: str, term_re: re.Pattern) -> str:
    esc = html.escape(text)
    spans = [(m.start(), m.end()) for m in term_re.finditer(esc)]
    if not spans: return f"<pre>{esc[:10000]}</pre>"
    parts, p = [], 0
    for s, e in spans:
        parts.append(esc[p:s]); parts.append("<mark>"); parts.append(esc[s:e]); parts.append("</mark>")
        p = e
    parts.append(esc[p:])
    snip = "".join(parts)
    if len(snip) > 20000: snip = snip[:20000] + "..."
    return f'<pre style="white-space:pre-wrap;word-break:break-word;">{snip}</pre>'

# --------- Single File Mode ---------
if fetch_btn:
    try:
        if not (bucket and file_path and ak and sk):
            st.error("Bucket, File Path, Access, and Secret are required for single file mode.")
            st.stop()
        key = sanitize_key(file_path)
        st.info(f"Fetching `{key}` from `{bucket}` …")
        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        if debug: st.info(f"Resolved → region={region} | endpoint={endpoint} | addressing={addr}")
        obj = s3.get_object(Bucket=bucket, Key=key)
        raw = obj["Body"].read()

        texts = [t for _, t in decode_candidates(raw)]
        if not texts: texts = [raw.decode("utf-8", errors="ignore")]
        found_xmls = []
        for t in texts: found_xmls.extend(extract_xmls_from_text(t))
        seen=set(); found_xmls=[x for x in found_xmls if not (x in seen or seen.add(x))]

        if not found_xmls:
            st.error("No XML content found in this file after decoding."); st.stop()

        pretty = pretty_xml(found_xmls[0])
        st.success("Decoded XML extracted.")
        st.download_button("⬇️ Download decoded XML", pretty, file_name="decoded.xml", mime="text/xml")

        if single_search_mode == "XPath (requires lxml)":
            if not LXML_AVAILABLE:
                st.error("lxml not available for XPath.")
            else:
                try:
                    root = etree.fromstring(found_xmls[0].encode("utf-8"))
                    nsmap = {k if k else 'ns': v for k, v in (getattr(root, "nsmap", {}) or {}).items()}
                    if single_search_value.strip():
                        nodes = root.xpath(single_search_value, namespaces=nsmap)
                        st.info(f"XPath matched {len(nodes)} node(s). Showing up to 10.")
                        for node in nodes[:10]:
                            try: frag = etree.tostring(node, pretty_print=True, encoding=str)
                            except Exception: frag = str(node)
                            st.code(frag[:2000], language="xml")
                    else:
                        st.code(pretty[:4000], language="xml")
                except Exception as e:
                    st.error(f"XPath error: {e}")
        elif single_search_mode in ("Literal text", "Regular expression"):
            term = single_search_value.strip()
            if term:
                try:
                    term_re = re.compile(term, re.IGNORECASE) if single_search_mode == "Regular expression" else regex_from_literal(term)
                    st.markdown(highlight_html_with_regex(pretty, term_re), unsafe_allow_html=True)
                except re.error as e:
                    st.warning(f"Invalid regex: {e}")
            else:
                st.code(pretty[:4000], language="xml")
        else:
            st.code(pretty[:4000], language="xml")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Failed: {e}")

# --------- Prefix Scan Mode (generic search inside XMLs) ---------
if scan_btn:
    try:
        if not (bucket and prefix and ak and sk and scan_query.strip()):
            st.error("Bucket, Prefix, Access, Secret, and Search query are required for prefix scan.")
            st.stop()

        pf = sanitize_prefix(prefix)
        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        keys = list_keys(ak, sk, bucket, pf, max_items=int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix."); st.stop()

        st.info(f"Scanning {len(keys)} object(s) under `{pf}` for {scan_search_mode} match.")
        term = scan_query.strip()

        # Prepare matcher
        use_xpath = (scan_search_mode == "XPath (requires lxml)")
        if use_xpath and not LXML_AVAILABLE:
            st.error("lxml not available for XPath search."); st.stop()
        if not use_xpath:
            if scan_search_mode == "Regular expression":
                try:
                    term_re = re.compile(term, re.IGNORECASE)
                except re.error as e:
                    st.error(f"Invalid regex: {e}"); st.stop()
            else:
                term_re = regex_from_literal(term)

        matches = []  # [{key, xml, where}]
        prog = st.progress(0)
        for i, key in enumerate(keys):
            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()

                texts = [t for _, t in decode_candidates(raw)]
                if not texts: texts = [raw.decode("utf-8", errors="ignore")]
                found_xmls = []
                for t in texts: found_xmls.extend(extract_xmls_from_text(t))
                # unique
                seen=set(); found_xmls=[x for x in found_xmls if not (x in seen or seen.add(x))]

                hit_xml = None
                if use_xpath:
                    for xml in found_xmls:
                        try:
                            root = etree.fromstring(xml.encode("utf-8"))
                            nsmap = {k if k else 'ns': v for k, v in (getattr(root, "nsmap", {}) or {}).items()}
                            res = root.xpath(term, namespaces=nsmap)
                            if res:
                                hit_xml = xml; break
                        except Exception:
                            continue
                else:
                    for xml in found_xmls:
                        if term_re.search(xml):
                            hit_xml = xml; break

                if hit_xml:
                    matches.append({"key": key, "xml": pretty_xml(hit_xml), "where": "content"})
            except Exception:
                pass
            finally:
                prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not matches:
            st.error("❌ No XMLs matched that query inside their content.")
            st.stop()

        st.success(f"✅ Found {len(matches)} matching XML file(s).")
        st.write([{"key": m["key"]} for m in matches])

        sel = st.selectbox("Preview which object?", [m["key"] for m in matches])
        chosen = next(m for m in matches if m["key"] == sel)

        st.download_button("⬇️ Download matched XML", chosen["xml"], file_name="matched.xml", mime="text/xml")

        # Highlight for text/regex modes
        if not use_xpath:
            st.subheader("Preview (query highlighted)")
            st.markdown(highlight_html_with_regex(chosen["xml"], term_re), unsafe_allow_html=True)
        else:
            st.subheader("Preview")
            st.code(chosen["xml"][:4000], language="xml")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Failed: {e}")
