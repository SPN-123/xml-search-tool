# app.py — Wasabi XML Finder (robust) — deep-unescape + base64/gzip + content-only filters + ZIP download

import sys, subprocess
for pkg in ("boto3", "lxml", "streamlit"):
    try:
        __import__(pkg)
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

import re, gzip, base64, json, html, io, zipfile, os, codecs
import streamlit as st
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from xml.dom import minidom

# lxml is optional (only needed for XPath mode)
try:
    from lxml import etree
    LXML_AVAILABLE = True
except Exception:
    LXML_AVAILABLE = False

# ================= UI =================
st.set_page_config(page_title="Wasabi XML Finder — robust", layout="wide")
st.title("🔍 Wasabi XML Finder — robust decode + deep unescape + filters")

with st.sidebar:
    st.header("🔐 Wasabi")
    bucket = st.text_input("Bucket")
    ak = st.text_input("Access key", type="password")
    sk = st.text_input("Secret key", type="password")
    endpoint = st.text_input("Endpoint", "https://s3.wasabisys.com")

st.subheader("📁 Prefix Scan & Search")
prefix = st.text_input("Prefix to scan (folder, trailing '/' optional)")

c1, c2, c3, c4 = st.columns(4)
with c1:
    search_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with c2:
    main_query = st.text_input("🔹 Mandatory term (required)")
with c3:
    opt1 = st.text_input("Optional filter 1 (content only)")
with c4:
    opt2 = st.text_input("Optional filter 2 (content only)")
opt3 = st.text_input("Optional filter 3 (content only)")

d1, d2, d3, d4 = st.columns(4)
with d1:
    include_path_for_main = st.checkbox("Include PATH for mandatory term", True)
with d2:
    whole_word_optionals = st.checkbox("Whole word for optional filters", False)
with d3:
    where_scope = st.selectbox("Where to search content",
                               ["All (Decoded + Embedded + XML)", "XML only", "Decoded + Embedded only"])
with d4:
    max_keys = st.number_input("Max objects", min_value=1, value=500, step=1)

debug = st.checkbox("Debug (show decode kinds)")
run_btn = st.button("🚀 Scan")

# ================= Helpers =================
def fix_prefix(p: str) -> str:
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p); p = re.sub(r"/{2,}", "/", p)
    if p and not p.endswith("/"): p += "/"
    return p

def get_client():
    return boto3.client(
        "s3",
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        endpoint_url=endpoint,
        config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
    )

def list_keys(s3, bucket, prefix, limit):
    out = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            out.append(obj["Key"])
            if len(out) >= limit:
                return out
    return out

# ---- Deep unescape (much stronger) ----
def deep_unescape(s: str) -> str:
    if s is None:
        return ""
    out = s
    for _ in range(3):
        prev = out
        # Try JSON decoding of a string
        try:
            if (out.startswith('"') and out.endswith('"')) or (out.startswith("'") and out.endswith("'")):
                out = json.loads(out)
            else:
                out = json.loads('"' + out.replace('\\', '\\\\').replace('"', '\\"') + '"')
        except Exception:
            # Try unicode escape
            try:
                out = codecs.decode(out, "unicode_escape")
            except Exception:
                pass
        # Normalize \/ and HTML entities
        out = out.replace("\\/", "/")
        out = html.unescape(out)
        # Strip enclosing quotes if they remain
        if (out.startswith('"') and out.endswith('"')) or (out.startswith("'") and out.endswith("'")):
            out = out[1:-1]
        if out == prev:
            break
    return out.strip()

def pretty_xml(x: str) -> str:
    if not x:
        return x or ""
    for cand in (x, deep_unescape(x)):
        try:
            return minidom.parseString(cand).toprettyxml(indent="  ")
        except Exception:
            continue
    return deep_unescape(x)

def decode_candidates(raw: bytes):
    tries = []
    # plain
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except Exception:
        pass
    # gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except Exception:
        pass
    # base64 (full-object)
    try:
        # attempt decode using plain text view
        s = tries[0][1] if tries else raw.decode("utf-8", errors="ignore")
        b = base64.b64decode(re.sub(r"[^A-Za-z0-9+/=]", "", s))
        if b:
            if len(b) > 2 and b[:2] == b"\x1f\x8b":
                try:
                    t = gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()
                    if t: tries.append(("b64+gzip", t))
                except Exception:
                    pass
            else:
                try:
                    t = b.decode("utf-8-sig", errors="ignore").strip()
                    if t: tries.append(("b64_text", t))
                except Exception:
                    pass
    except Exception:
        pass
    if not tries:
        try:
            t = raw.decode("utf-8", errors="ignore")
            tries.append(("fallback", t))
        except Exception:
            pass
    return tries

# Robust embedded base64: H4sIA… and long base64 chunks anywhere
B64_CHUNK = re.compile(r"(H4sIA[A-Za-z0-9+/=]{40,}|[A-Za-z0-9+/]{160,}={0,2})")

def embedded_payloads_from_text(txt: str):
    outs = []
    for m in B64_CHUNK.finditer(txt or ""):
        blob = m.group(0)
        try:
            b = base64.b64decode(re.sub(r"[^A-Za-z0-9+/=]", "", blob))
        except Exception:
            continue
        if not b:
            continue
        if len(b) > 2 and b[:2] == b"\x1f\x8b":
            try:
                dec = gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()
                if dec: outs.append(dec)
            except Exception:
                pass
        else:
            try:
                dec = b.decode("utf-8-sig", errors="ignore").strip()
                if dec: outs.append(dec)
            except Exception:
                pass
    return outs

def extract_xmls_from_text(txt: str):
    outs = []
    if not txt: return outs
    # try both raw and deeply unescaped
    candidates = [txt]
    u = deep_unescape(txt)
    if u != txt: candidates.insert(0, u)
    for c in candidates:
        s = c.strip()
        if s.startswith("<") or s.startswith("<?xml"):
            outs.append(s)
        else:
            m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
            if m: outs.append(m.group(0))
    # unique
    uniq=[]; seen=set()
    for x in outs:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def compile_pat(term: str, regex: bool, whole_word: bool):
    if regex:
        return re.compile(term, re.IGNORECASE)
    if whole_word:
        return re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE)
    return re.compile(re.escape(term), re.IGNORECASE)

# ================= Scan =================
if run_btn:
    # basic checks
    if not (bucket and ak and sk and prefix and main_query.strip()):
        st.error("Please fill bucket, keys, prefix, and the mandatory term.")
        st.stop()

    s3 = get_client()
    pf = fix_prefix(prefix)

    try:
        keys = list_keys(s3, bucket, pf, int(max_keys))
    except ClientError as e:
        st.error(f"S3 error: {e}")
        st.stop()

    if not keys:
        st.warning("No objects under that prefix.")
        st.stop()

    use_xpath = (search_mode == "XPath (requires lxml)")
    if use_xpath and not LXML_AVAILABLE:
        st.error("XPath mode needs lxml. Please install lxml.")
        st.stop()

    main_pat = None if use_xpath else compile_pat(main_query, regex=(search_mode=="Regular expression"), whole_word=False)
    opt_terms = [q.strip() for q in (opt1, opt2, opt3) if q.strip()]
    opt_pats = [] if use_xpath else [compile_pat(q, regex=(search_mode=="Regular expression"), whole_word=whole_word_optionals) for q in opt_terms]

    results=[]
    prog = st.progress(0)

    for i, key in enumerate(keys):
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            raw = obj["Body"].read()

            # Decode
            tries = decode_candidates(raw)
            if debug: st.write(f"{key} → decode kinds: {[k for k,_ in tries] or ['(none)']}")

            decoded = [deep_unescape(t) for _, t in tries]  # unescape decoded
            # Embedded payloads (base64 blobs), then unescape
            embedded = []
            for t in decoded:
                embedded.extend(embedded_payloads_from_text(t))
            embedded = [deep_unescape(t) for t in embedded]

            # Extract XMLs from decoded + embedded (with unescape)
            xmls = []
            for t in decoded + embedded:
                xmls.extend(extract_xmls_from_text(t))

            # PRIMARY content body for optional filters (prefer XML)
            bodies = []
            if where_scope in ("All (Decoded + Embedded + XML)", "XML only"):
                bodies += xmls
            if where_scope in ("All (Decoded + Embedded + XML)", "Decoded + Embedded only"):
                bodies += embedded + decoded
            primary = next((b for b in bodies if b and b.strip()), None)

            # ---- Mandatory term must match ----
            main_ok = False
            if use_xpath:
                # XPath against any extracted XML
                for x in xmls:
                    try:
                        root = etree.fromstring(x.encode("utf-8"))
                        nsmap = {k if k else 'ns': v for k, v in (getattr(root,"nsmap",{}) or {}).items()}
                        if root.xpath(main_query, namespaces=nsmap):
                            main_ok = True; break
                    except Exception:
                        continue
            else:
                hay = []
                if primary: hay.append(primary)
                if include_path_for_main: hay.append(key)
                if any(main_pat.search(h) for h in hay if h):
                    main_ok = True

            if not main_ok:
                prog.progress(int((i+1)/len(keys)*100)); continue

            # ---- Optional filters: ALL must match SAME primary body (content only) ----
            opt_ok = True
            if opt_pats:
                if not primary:
                    opt_ok = False
                else:
                    for p in opt_pats:
                        if not p.search(primary):
                            opt_ok = False; break

            if not opt_ok:
                prog.progress(int((i+1)/len(keys)*100)); continue

            # Choose content to save: pretty XML if available, else pretty of primary
            content = xmls[0] if xmls else primary or ""
            content = pretty_xml(content)
            results.append({"Key": key, "Content": content})

        except Exception as e:
            if debug: st.write(f"{key}: {e}")

        prog.progress(int((i+1)/len(keys)*100))
    prog.empty()

    if not results:
        st.error("❌ No matches found. Tips: ensure prefix ends with '/', main term present, and try 'All (Decoded + Embedded + XML)'.")
        st.stop()

    st.success(f"✅ Found {len(results)} matches.")
    st.dataframe([{"Key": r["Key"], "Preview": (r["Content"] or '')[:200]} for r in results])

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

    # ZIP all
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in results:
            fname = os.path.basename(r["Key"]) or "file.xml"
            if not fname.lower().endswith(".xml"):
                fname += ".xml"
            z.writestr(fname, r["Content"] or "")
    zip_buf.seek(0)
    st.download_button("📦 Download ALL matched XMLs (ZIP)", data=zip_buf, file_name="matched_xmls.zip", mime="application/zip")
