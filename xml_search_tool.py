# app.py — Wasabi XML Finder: Single File (Path) + Prefix Scan (Date) + Decode + Preview
# Paste directly into Streamlit Cloud. Ensures boto3/lxml are available.

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

# ================= UI =================
st.set_page_config(page_title="Wasabi XML Finder — Path & Prefix", layout="wide")
st.title("🔎 Wasabi XML Finder — Path Fetch + Prefix Scan + Decode + Preview")

st.markdown(
    "Use **File Path (exact key)** to fetch 1 file, **or** **Prefix to scan (folder)** to find all XMLs that "
    "contain a **date** in the filename or inside the XML content."
)

c0a, c0b = st.columns([1.2, 2])
with c0a:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with c0b:
    ak = st.text_input("Wasabi Access Key", type="password")

sk = st.text_input("Wasabi Secret Key", type="password")

st.markdown("### 📄 Single File Mode (exact path)")
file_path = st.text_input("File Path (exact object key under bucket, e.g. RZBPD/05102025/.../UpdateAri.txt)", "")

c1, c2, c3 = st.columns([1.1, 1.2, 1])
with c1:
    single_search_mode = st.selectbox("Preview search", ["None", "Literal text", "Regular expression", "XPath (requires lxml)"])
with c2:
    single_search_value = st.text_input("Search term / Regex / XPath (for single file)", "")
with c3:
    debug = st.checkbox("Debug")

fetch_btn = st.button("📥 Fetch & Preview Single File")

st.divider()

st.markdown("### 📁 Prefix Scan Mode (find XMLs that contain a date)")
prefix = st.text_input("Prefix to scan (folder, ends with /)", "")
c4, c5, c6 = st.columns([1.1, 1.1, 1.1])
with c4:
    date_str = st.text_input("Target date (e.g. 2025-10-05)", "")
with c5:
    date_mode = st.selectbox("Date match mode", ["Exact YYYY-MM-DD", "Smart variants (recommended)"])
with c6:
    max_keys = st.number_input("Max objects to scan", min_value=1, value=500, step=1)

scan_btn = st.button("🚀 Scan Prefix & Find Matches")

st.divider()

# ================= Helpers =================
def endpoint_for(region: str) -> str:
    return "https://s3.wasabisys.com" if not region or region == "us-east-1" else f"https://s3.{region}.wasabisys.com"

def discover_region(ak: str, sk: str, bucket: str) -> str:
    s3g = boto3.client(
        "s3", aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url="https://s3.wasabisys.com", config=Config(signature_version="s3v4")
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
        "s3", aws_access_key_id=ak, aws_secret_access_key=sk,
        endpoint_url=endpoint, region_name=region,
        config=Config(signature_version="s3v4", s3={"addressing_style": addressing})
    )
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
    # JSON payloads
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
    # relaxed XML-ish pattern
    m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
    if m:
        outs.append(m.group(0))
    if s.startswith("<") or s.startswith("<?xml"):
        outs.append(s)
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
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
            if len(keys) >= max_items:
                return keys
    return keys

def build_date_regex(date_str: str, smart: bool) -> re.Pattern:
    ds = date_str.strip()
    if not smart:
        return re.compile(re.escape(ds), re.IGNORECASE)
    m = re.match(r"^\s*(\d{4})[-/](\d{1,2})[-/](\d{1,2})\s*$", ds)
    if not m:
        return re.compile(re.escape(ds), re.IGNORECASE)
    Y, M, D = m.groups()
    M2, D2 = M.zfill(2), D.zfill(2)
    variants = {
        f"{Y}-{M}-{D}", f"{Y}-{M2}-{D2}", f"{Y}/{M}/{D}", f"{Y}/{M2}/{D2}",
        f"{D}-{M}-{Y}", f"{D2}-{M2}-{Y}", f"{D}/{M}/{Y}", f"{D2}/{M2}/{Y}",
        f"{M}-{D}-{Y}", f"{M2}-{D2}-{Y}", f"{M}/{D}/{Y}", f"{M2}/{D2}/{Y}"
    }
    alts = "|".join(re.escape(v) for v in sorted(variants))
    return re.compile(rf"(?:{alts})", re.IGNORECASE)

def highlight_html_with_regex(text: str, term_re: re.Pattern) -> str:
    esc = html.escape(text)
    matches = [(m.start(), m.end()) for m in term_re.finditer(esc)]
    if not matches: return f"<pre>{esc[:10000]}</pre>"
    out, p = [], 0
    for s, e in matches:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>")
        p = e
    out.append(esc[p:])
    snip = "".join(out)
    if len(snip) > 20000: snip = snip[:20000] + "..."
    return f'<pre style="white-space:pre-wrap;word-break:break-word;">{snip}</pre>'

# ================= Single File Mode =================
if fetch_btn:
    try:
        if not (bucket and file_path and ak and sk):
            st.error("Bucket, File Path, Access, and Secret are required for single file mode.")
            st.stop()
        key = sanitize_key(file_path)
        st.info(f"Fetching `{key}` from bucket `{bucket}` …")
        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        if debug: st.info(f"Resolved → region={region} | endpoint={endpoint} | addressing={addr}")
        obj = s3.get_object(Bucket=bucket, Key=key)
        raw = obj["Body"].read()

        # decode & extract
        texts = [t for _, t in decode_candidates(raw)]
        if not texts: texts = [raw.decode("utf-8", errors="ignore")]
        found_xmls = []
        for t in texts:
            found_xmls.extend(extract_xmls_from_text(t))
        seen=set(); found_xmls=[x for x in found_xmls if not (x in seen or seen.add(x))]

        if not found_xmls:
            st.error("No XML content found in this file after decoding.")
            st.stop()

        pretty = pretty_xml(found_xmls[0])
        st.success("Decoded XML extracted.")
        st.download_button("⬇️ Download decoded XML", pretty, file_name="decoded.xml", mime="text/xml")

        # preview with optional search
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
                    term_re = re.compile(term, re.IGNORECASE) if single_search_mode == "Regular expression" else re.compile(re.escape(term), re.IGNORECASE)
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

# ================= Prefix Scan Mode =================
if scan_btn:
    try:
        if not (bucket and prefix and ak and sk and date_str.strip()):
            st.error("Bucket, Prefix, Access, Secret, and Date are required for prefix scan.")
            st.stop()

        pf = sanitize_prefix(prefix)
        date_re = build_date_regex(date_str, smart=(date_mode == "Smart variants (recommended)"))
        st.info(f"Scanning up to {max_keys} object(s) under `{pf}` for date: **{date_str}**")

        keys = list_keys(ak, sk, bucket, pf, max_items=int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix.")
            st.stop()

        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        matches = []
        prog = st.progress(0)
        for i, key in enumerate(keys):
            where_hits = []
            if date_re.search(key):  # match in path/filename
                where_hits.append("path")

            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()
                size = len(raw)
                texts = [t for _, t in decode_candidates(raw)]
                if not texts: texts = [raw.decode("utf-8", errors="ignore")]
                found_xmls = []
                for t in texts:
                    found_xmls.extend(extract_xmls_from_text(t))
                seen=set(); found_xmls=[x for x in found_xmls if not (x in seen or seen.add(x))]

                xml_hit = None
                for xml in found_xmls:
                    if date_re.search(xml):
                        where_hits.append("content")
                        xml_hit = xml
                        break

                if where_hits:
                    pretty = pretty_xml(xml_hit) if xml_hit else (found_xmls[0] if found_xmls else "")
                    matches.append({"key": key, "where": ",".join(sorted(set(where_hits))), "size": size, "xml": pretty})
            except Exception as e:
                if debug: st.write(f"{key}: {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not matches:
            st.error("❌ No XMLs matched that date in name or content.")
            st.stop()

        st.success(f"✅ Found {len(matches)} matching object(s).")
        st.write([{"key": m["key"], "where": m["where"], "size": m["size"]} for m in matches])

        # choose a match to preview
        sel = st.selectbox("Preview which object?", [m["key"] for m in matches])
        chosen = next(m for m in matches if m["key"] == sel)

        st.download_button("⬇️ Download matched XML", chosen["xml"] or "", file_name="matched.xml", mime="text/xml")

        # show preview & optional search
        if chosen["xml"]:
            st.subheader("Preview (date highlighted)")
            st.markdown(highlight_html_with_regex(chosen["xml"], date_re), unsafe_allow_html=True)

            # extra preview search
            if single_search_mode == "XPath (requires lxml)":
                if not LXML_AVAILABLE:
                    st.error("lxml not available for XPath.")
                elif not single_search_value.strip():
                    pass
                else:
                    try:
                        root = etree.fromstring(chosen["xml"].encode("utf-8"))
                        nsmap = {k if k else 'ns': v for k, v in (getattr(root, "nsmap", {}) or {}).items()}
                        nodes = root.xpath(single_search_value, namespaces=nsmap)
                        st.info(f"XPath matched {len(nodes)} node(s). Showing up to 10.")
                        for node in nodes[:10]:
                            try: frag = etree.tostring(node, pretty_print=True, encoding=str)
                            except Exception: frag = str(node)
                            st.code(frag[:2000], language="xml")
                    except Exception as e:
                        st.error(f"XPath error: {e}")
            elif single_search_mode in ("Literal text", "Regular expression") and single_search_value.strip():
                try:
                    term_re = re.compile(single_search_value, re.IGNORECASE) if single_search_mode == "Regular expression" else re.compile(re.escape(single_search_value), re.IGNORECASE)
                    st.subheader("Extra preview highlighting")
                    st.markdown(highlight_html_with_regex(chosen["xml"], term_re), unsafe_allow_html=True)
                except re.error as e:
                    st.warning(f"Invalid regex: {e}")
        else:
            st.warning("Matched by path only; no XML body extracted.")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Failed: {e}")
