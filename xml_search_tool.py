# app.py — Wasabi Multi-Search (content-only optional filters) + Auto "Unescape & Pretty" XML
# - Mandatory term can include PATH (toggle)
# - Optional filters (up to 3) are applied to CONTENT ONLY and must ALL match the SAME body
# - Robust decode pipeline: plain / gzip / base64 / base64+gzip + embedded base64 payloads
# - NEW: auto-unescape string-escaped XML (\", \\n, &amp; etc.) and pretty-print before preview/download
# - Download selected match or ALL matches as a ZIP

import sys, subprocess
for pkg in ("boto3", "lxml", "streamlit"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

import re, gzip, base64, json, html, io, zipfile, os
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
st.set_page_config(page_title="Wasabi Multi-Search — Content Filters + XML Unescape", layout="wide")
st.title("🔍 Wasabi Multi-Search — Content Filters + Auto-Unescape & Pretty XML")

c1, c2 = st.columns([1.2, 2])
with c1:
    bucket = st.text_input("Bucket", "")
with c2:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.subheader("📁 Prefix Scan & Search")
prefix = st.text_input("Prefix to scan (folder path; no leading '/', trailing '/' optional)", "")

row1 = st.columns(4)
with row1[0]:
    search_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with row1[1]:
    main_query = st.text_input("🔹 Mandatory Search Term (required)", "")
with row1[2]:
    opt_query1 = st.text_input("Optional Filter 1 (content only)", "")
with row1[3]:
    opt_query2 = st.text_input("Optional Filter 2 (content only)", "")
opt_query3 = st.text_input("Optional Filter 3 (content only)", "")

row2 = st.columns(5)
with row2[0]:
    include_path_for_main = st.checkbox("Include PATH for main term", value=True)
with row2[1]:
    whole_word_optionals = st.checkbox("Whole word for optionals", value=False)
with row2[2]:
    where_scope = st.selectbox("Where to search content", [
        "All (Decoded + Embedded + XML)",
        "XML only",
        "Decoded + Embedded only",
    ])
with row2[3]:
    max_keys = st.number_input("Max objects to scan", min_value=1, value=500, step=1)
with row2[4]:
    debug = st.checkbox("Debug (show decode kinds & embedded hits)")

run_btn = st.button("🚀 Scan Prefix & Find Matches")

# ================= Helpers =================
def fix_prefix(p: str) -> str:
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p); p = re.sub(r"/{2,}", "/", p)
    if p and not p.endswith("/"): p += "/"
    return p

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
        return e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amz-bucket-region", "us-east-1")

def get_client(ak: str, sk: str, bucket: str):
    region = discover_region(ak, sk, bucket)
    endpoint = endpoint_for(region)
    s3 = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk,
                      endpoint_url=endpoint, region_name=region,
                      config=Config(signature_version="s3v4"))
    return s3

def list_keys(s3, bucket: str, prefix: str, max_items: int):
    paginator = s3.get_paginator("list_objects_v2")
    out = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            out.append(obj["Key"])
            if len(out) >= max_items: return out
    return out

def safe_b64decode(s: str) -> bytes:
    s = re.sub(r"[^A-Za-z0-9+/=]", "", (s or "").strip().replace("\n","").replace("\r",""))
    if not s: return b""
    pad = len(s) % 4
    if pad: s += "=" * (4 - pad)
    try: return base64.b64decode(s)
    except Exception: return b""

def decode_candidates(raw: bytes):
    tries=[]
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except: pass
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except: pass
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b:
            if len(b)>2 and b[:2]==b"\x1f\x8b":
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
    if not tries:
        try: tries.append(("fallback", raw.decode("utf-8", errors="ignore")))
        except: pass
    return tries

# Find embedded base64 payloads (H4sIA... gzip or long base64)
B64_CHUNK = re.compile(r"(H4sIA[A-Za-z0-9+/=]{40,}|[A-Za-z0-9+/]{80,}={0,2})")

def embedded_payloads_from_text(txt: str):
    outs=[]
    for m in B64_CHUNK.finditer(txt or ""):
        b = safe_b64decode(m.group(0))
        if not b: continue
        if len(b)>2 and b[:2]==b"\x1f\x8b":
            try:
                dec = gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()
                if dec: outs.append(dec)
            except: pass
        else:
            try:
                dec = b.decode("utf-8-sig", errors="ignore").strip()
                if dec: outs.append(dec)
            except: pass
    return outs

# ---- NEW: Unescape helpers ----
def unescape_stringish(s: str) -> str:
    """
    Best-effort: turn a string-escaped payload into raw text/XML.
    Handles: \", \\n, \\t, &amp; etc.
    """
    if s is None: return ""
    t = s

    # If it looks like a JSON-escaped string, try json.loads on it safely.
    # We wrap it in quotes then escape any existing backslashes/quotes appropriately.
    try:
        wrapped = '"' + t.replace('\\', '\\\\').replace('"', '\\"') + '"'
        t2 = json.loads(wrapped)
        t = t2
    except Exception:
        # fallback manual unescapes
        t = t.replace(r'\"', '"').replace(r"\\'", "'")
        t = t.replace(r"\\n", "\n").replace(r"\\r", "\r").replace(r"\\t", "\t").replace("\\/", "/")
        t = t.replace("\\\\", "\\")
    # HTML entities
    t = html.unescape(t)
    # Trim surrounding quotes if any
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        t = t[1:-1]
    return t.strip()

def extract_xmls_from_text(txt: str):
    """
    Pull XML from raw/escaped text. Also tries to unescape JSON-stringified XML.
    """
    outs=[]
    s = (txt or "").strip()
    # If it looks escaped (lots of \" or \n), try unescape first
    if '\\"' in s or "\\n" in s or "&lt;" in s or "&gt;" in s:
        s_un = unescape_stringish(s)
        s_candidates = [s_un, s]
    else:
        s_candidates = [s]

    for cand in s_candidates:
        c = cand.strip()
        if c.startswith("<") or c.startswith("<?xml"):
            outs.append(c)
        else:
            m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", c)
            if m: outs.append(m.group(0))

    # unique
    seen=set(); uniq=[]
    for x in outs:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def pretty_xml(x: str) -> str:
    try: 
        return minidom.parseString(x).toprettyxml(indent="  ")
    except Exception:
        # try after unescape once more
        try:
            u = unescape_stringish(x)
            return minidom.parseString(u).toprettyxml(indent="  ")
        except Exception:
            return x

def compile_pat(term: str, regex: bool, whole_word: bool):
    if regex:
        return re.compile(term, re.IGNORECASE)
    if whole_word:
        return re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
    return re.compile(re.escape(term), re.IGNORECASE)

# ================= Scan =================
if run_btn:
    try:
        if not (bucket and ak and sk and prefix and main_query.strip()):
            st.error("Please fill bucket, credentials, prefix, and the mandatory term."); st.stop()

        s3 = get_client(ak, sk, bucket)
        pf = fix_prefix(prefix)
        keys = list_keys(s3, bucket, pf, int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix."); st.stop()

        use_xpath = (search_mode == "XPath (requires lxml)")
        if use_xpath and not LXML_AVAILABLE:
            st.error("lxml is not available for XPath searches."); st.stop()

        main_pat = None if use_xpath else compile_pat(main_query, regex=(search_mode=="Regular expression"), whole_word=False)
        opt_terms = [q.strip() for q in (opt_query1, opt_query2, opt_query3) if q.strip()]
        opt_pats = [] if use_xpath else [compile_pat(q, regex=(search_mode=="Regular expression"), whole_word=whole_word_optionals) for q in opt_terms]

        st.info(f"Scanning {len(keys)} objects under `{pf}` …")
        results=[]
        prog = st.progress(0)

        for i, key in enumerate(keys):
            try:
                # Fetch and decode
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()
                tries = decode_candidates(raw)
                decoded = [t for _, t in tries]
                if debug: st.write(f"{key} → decode kinds: {[k for k,_ in tries]}")

                # Unescape decoded payloads (if string-escaped)
                decoded = [unescape_stringish(t) for t in decoded]

                # Embedded payloads + unescape
                embedded=[]
                for t in decoded:
                    embedded.extend(embedded_payloads_from_text(t))
                embedded = [unescape_stringish(t) for t in embedded]

                # Extract XMLs from both decoded & embedded (with unescape attempts)
                xmls=[]
                for t in decoded + embedded:
                    xmls.extend(extract_xmls_from_text(t))

                # Select primary content body for optional filters:
                bodies=[]
                if where_scope in ("All (Decoded + Embedded + XML)", "XML only"): bodies += xmls
                if where_scope in ("All (Decoded + Embedded + XML)", "Decoded + Embedded only"):
                    bodies += embedded + decoded
                primary=None
                for b in bodies:
                    if b and len(b.strip())>0:
                        primary=b; break

                # 1) Mandatory term must match:
                main_ok=False
                if use_xpath:
                    for x in xmls:
                        try:
                            root = etree.fromstring(x.encode("utf-8"))
                            nsmap = {k if k else 'ns': v for k, v in (getattr(root,"nsmap",{}) or {}).items()}
                            if root.xpath(main_query, namespaces=nsmap):
                                main_ok=True; break
                        except Exception:
                            continue
                else:
                    hay=[]
                    if primary: hay.append(primary)
                    if include_path_for_main: hay.append(key)
                    if any(main_pat.search(h) for h in hay if h is not None):
                        main_ok=True

                if not main_ok:
                    prog.progress(int((i+1)/len(keys)*100)); continue

                # 2) Optional filters: ALL must match the SAME primary body (content only)
                opt_ok=True
                if opt_pats:
                    if not primary:
                        opt_ok=False
                    else:
                        for p in opt_pats:
                            if not p.search(primary):
                                opt_ok=False; break
                if not opt_ok:
                    prog.progress(int((i+1)/len(keys)*100)); continue

                # Final content: pretty XML if available; else primary (unescaped)
                content = xmls[0] if xmls else (primary or "")
                content = pretty_xml(content)
                results.append({"Key": key, "Content": content})

            except Exception as e:
                if debug: st.write(f"{key}: {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not results:
            st.error("❌ No files matched your criteria.")
            st.stop()

        st.success(f"✅ Found {len(results)} matches.")
        st.dataframe([{"Key": r["Key"], "Preview": (r["Content"] or "")[:180]} for r in results])

        sel = st.selectbox("Select XML to preview", [r["Key"] for r in results])
        chosen = next(r for r in results if r["Key"] == sel)
        st.code((chosen["Content"] or "")[:4000], language="xml")

        # Single download
        st.download_button(
            "⬇️ Download Selected XML",
            (chosen["Content"] or "").encode("utf-8"),
            file_name=os.path.basename(chosen["Key"]) or "matched.xml",
            mime="text/xml",
        )

        # ALL as ZIP
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
            for r in results:
                fname = os.path.basename(r["Key"]) or "file.xml"
                if not fname.lower().endswith(".xml"):
                    fname += ".xml"
                z.writestr(fname, r["Content"] or "")
        zip_buf.seek(0)
        st.download_button("📦 Download ALL matched XMLs (ZIP)", data=zip_buf, file_name="matched_xmls.zip", mime="application/zip")

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Error: {e}")
