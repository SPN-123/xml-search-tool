# app.py — Wasabi XML Finder: decode + date filter + multi-match browser (single file)
# Designed for Streamlit Cloud. It will ensure boto3/lxml are available.

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
st.set_page_config(page_title="Wasabi XML Finder — Date Search", layout="wide")
st.title("🔎 Wasabi XML Finder — Date Search + Decode + Preview")

st.markdown("Fill **Bucket**, **Prefix (folder)**, and **Wasabi keys**. "
            "Enter your **date** (e.g. `2025-10-05`). "
            "The app will find **ALL** XMLs that contain the date either in the **filename/path** or **inside the XML content**.")

c1, c2 = st.columns([1.2, 2])
with c1:
    bucket = st.text_input("Bucket (e.g. rzgnprdws-code-90d)", "")
with c2:
    prefix = st.text_input("Prefix to scan (ends with /)", "")

ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

c3, c4, c5 = st.columns([1.2, 1.2, 1.2])
with c3:
    date_str = st.text_input("Target date (e.g. 2025-10-05)", "")
with c4:
    smart_variants = st.selectbox("Date match mode", ["Exact YYYY-MM-DD", "Smart variants (recommended)"])
with c5:
    max_keys = st.number_input("Max objects to scan", min_value=1, value=500, step=1)

st.markdown("Optional content search for preview (after match found):")
c6, c7 = st.columns([1.2, 1.2])
with c6:
    search_mode = st.selectbox("Preview search", ["None", "Literal text", "Regular expression", "XPath (requires lxml)"])
with c7:
    search_value = st.text_input("Preview search term / regex / XPath", "")

debug = st.checkbox("Debug")
run_btn = st.button("🚀 Scan & Find Matches")

st.divider()

# ============================ Helpers ============================
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

def sanitize_prefix(p: str) -> str:
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p)
    p = re.sub(r"/{2,}", "/", p)
    if p and not p.endswith("/"): p += "/"
    return p

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

def safe_b64decode(data: str) -> bytes:
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data.strip().replace("\n","").replace("\r",""))
    if len(data) % 4: data += "=" * (4 - len(data) % 4)
    return base64.b64decode(data)

def decode_candidates(raw: bytes):
    """Return list of decoded text attempts (kind, text)."""
    tries = []
    # Plain
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except Exception: pass
    # Gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except Exception: pass
    # Base64 → maybe gzip
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
    # XML-ish regex
    m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
    if m:
        outs.append(m.group(0))
    # Plain XML whole
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

def build_date_regex(date_str: str, smart: bool) -> re.Pattern:
    ds = date_str.strip()
    if not smart:
        # exact yyyy-mm-dd only
        patt = re.escape(ds)
        return re.compile(patt, re.IGNORECASE)
    # Smart variants:
    # yyyy-mm-dd, yyyy/mm/dd, dd-mm-yyyy, dd/mm/yyyy, mm-dd-yyyy, mm/dd/yyyy
    # also tolerate single-digit day/month (e.g., 2025-10-5)
    m = re.match(r"^\s*(\d{4})[-/](\d{1,2})[-/](\d{1,2})\s*$", ds)
    if not m:
        # default to literal if not yyyy-mm-dd-like
        return re.compile(re.escape(ds), re.IGNORECASE)
    Y, M, D = m.groups()
    # lead-zero & non-zero variants
    variants = set()
    M2 = M.zfill(2); D2 = D.zfill(2)
    # Y-M-D
    variants.add(f"{Y}-{M}-{D}")
    variants.add(f"{Y}-{M2}-{D2}")
    variants.add(f"{Y}/{M}/{D}")
    variants.add(f"{Y}/{M2}/{D2}")
    # D-M-Y
    variants.add(f"{D}-{M}-{Y}")
    variants.add(f"{D2}-{M2}-{Y}")
    variants.add(f"{D}/{M}/{Y}")
    variants.add(f"{D2}/{M2}/{Y}")
    # M-D-Y
    variants.add(f"{M}-{D}-{Y}")
    variants.add(f"{M2}-{D2}-{Y}")
    variants.add(f"{M}/{D}/{Y}")
    variants.add(f"{M2}/{D2}/{Y}")
    # Build regex that matches any of the variants
    alts = "|".join(re.escape(v) for v in sorted(variants))
    return re.compile(rf"(?:{alts})", re.IGNORECASE)

def highlight_html(text: str, term_regex: re.Pattern) -> str:
    esc = html.escape(text)
    matches = [ (m.start(), m.end()) for m in term_regex.finditer(esc) ]
    if not matches: return f"<pre>{esc[:10000]}</pre>"
    out, p = [], 0
    for s, e in matches:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>"); p = e
    out.append(esc[p:])
    snip = "".join(out)
    if len(snip) > 20000: snip = snip[:20000] + "..."
    return f'<pre style="white-space:pre-wrap;word-break:break-word;">{snip}</pre>'

# ============================ Run ============================
if run_btn:
    if not (bucket and prefix and ak and sk and date_str.strip()):
        st.error("Bucket, Prefix, Access, Secret, and Date are required.")
        st.stop()

    prefix = sanitize_prefix(prefix)
    try:
        keys = list_keys(ak, sk, bucket, prefix, max_items=int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix.")
            st.stop()
        st.info(f"Scanning {len(keys)} object(s) under `{prefix}` for date: **{date_str}**")

        s3, region, endpoint, addr = get_client(ak, sk, bucket)
        if debug:
            st.info(f"Resolved → region={region} | endpoint={endpoint} | addressing={addr}")

        date_re = build_date_regex(date_str, smart=(smart_variants == "Smart variants (recommended)"))

        matches = []  # list of dicts: {key, where, size, xml}
        prog = st.progress(0)

        for i, key in enumerate(keys):
            where_hits = []
            # 1) filename/path match first (cheap)
            if date_re.search(key):
                where_hits.append("path")

            # 2) fetch content and check inside (decode & extract xml)
            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()
                size = len(raw)

                texts = [t for _, t in decode_candidates(raw)]
                if not texts:
                    texts = [raw.decode("utf-8", errors="ignore")]

                found_xmls = []
                for t in texts:
                    found_xmls.extend(extract_xmls_from_text(t))
                # de-dup
                seen=set(); found_xmls=[x for x in found_xmls if not (x in seen or seen.add(x))]

                # Scan XML content for the date
                xml_hit = None
                for xml in found_xmls:
                    if date_re.search(xml):
                        where_hits.append("content")
                        xml_hit = xml
                        break

                if where_hits:
                    # prefer pretty xml if we have it
                    pretty = pretty_xml(xml_hit) if xml_hit else None
                    matches.append({
                        "key": key,
                        "where": ",".join(sorted(set(where_hits))),
                        "size": size,
                        "xml": pretty or (found_xmls[0] if found_xmls else ""),
                    })
            except Exception as e:
                if debug: st.write(f"{key}: error {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not matches:
            st.error("❌ No XMLs matched that date (in name or content).")
            st.stop()

        st.success(f"✅ Found {len(matches)} matching object(s).")
        # simple table
        st.write([{"key": m["key"], "where": m["where"], "size": m["size"]} for m in matches])

        # pick one to preview
        options = [m["key"] for m in matches]
        sel = st.selectbox("Preview which object?", options)
        sel_match = next(m for m in matches if m["key"] == sel)

        # Download matched XML
        st.download_button("⬇️ Download matched XML", sel_match["xml"] or "", file_name="matched.xml", mime="text/xml")

        # Show preview & optional extra search
        if sel_match["xml"]:
            st.subheader("Preview (with date highlighted)")
            st.markdown(highlight_html(sel_match["xml"], date_re), unsafe_allow_html=True)
        else:
            st.warning("This object matched by path only; no XML body extracted.")

        # Optional extra preview search
        if search_mode != "None" and sel_match["xml"]:
            if search_mode == "XPath (requires lxml)":
                if not LXML_AVAILABLE:
                    st.error("lxml not available for XPath.")
                elif not search_value.strip():
                    st.warning("Enter an XPath expression.")
                else:
                    try:
                        root = etree.fromstring(sel_match["xml"].encode("utf-8"))
                        nsmap = {}
                        if hasattr(root, "nsmap") and isinstance(root.nsmap, dict):
                            nsmap = {k if k else 'ns': v for k, v in root.nsmap.items()}
                        nodes = root.xpath(search_value, namespaces=nsmap)
                        st.info(f"XPath matched {len(nodes)} node(s). Showing up to 10.")
                        for node in nodes[:10]:
                            try:
                                frag = etree.tostring(node, pretty_print=True, encoding=str)
                            except Exception:
                                frag = str(node)
                            st.code(frag[:2000], language="xml")
                    except Exception as e:
                        st.error(f"XPath error: {e}")
            else:
                # Literal/Regex search within the selected XML
                term = search_value.strip()
                if term:
                    try:
                        term_re = re.compile(term, re.IGNORECASE) if search_mode == "Regular expression" else re.compile(re.escape(term), re.IGNORECASE)
                        st.subheader("Extra preview highlighting")
                        st.markdown(highlight_html(sel_match["xml"], term_re), unsafe_allow_html=True)
                    except re.error as e:
                        st.warning(f"Invalid regex: {e}")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Failed: {e}")
