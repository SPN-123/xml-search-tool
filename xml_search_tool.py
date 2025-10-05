# app.py — Multi-Filter Wasabi Finder (Path + Embedded Payloads + XML)
# Supports 1 mandatory term and 3 optional filters

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

# --- Streamlit UI ---
st.set_page_config(page_title="Wasabi Multi-Search XML Finder", layout="wide")
st.title("🔍 Wasabi Multi-Search — Find Decoded XMLs with Multiple Filters")

col1, col2 = st.columns([1.2, 2])
with col1:
    bucket = st.text_input("Bucket name", "")
with col2:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.subheader("📁 Prefix Scan & Search")
prefix = st.text_input("Prefix to scan (folder path, must end with /)", "")

r1, r2, r3, r4 = st.columns(4)
with r1:
    search_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with r2:
    main_query = st.text_input("🔹 Mandatory Search Term", "")
with r3:
    opt_query1 = st.text_input("Optional Filter 1", "")
with r4:
    opt_query2 = st.text_input("Optional Filter 2", "")

opt_query3 = st.text_input("Optional Filter 3 (e.g. RatePlanCode=NonRefundable)", "")

scope = st.selectbox("Where to search", ["All (Path + Decoded + Embedded + XML)", "Path only", "Decoded+XML only", "XML only"])
max_keys = st.number_input("Max objects to scan", 1, 5000, 500, 1)
debug = st.checkbox("Debug (show decode kinds & embedded hits)")
run = st.button("🚀 Scan Prefix & Find Matches")

# --- Utility Functions ---
def fix_prefix(p):
    p = (p or "").strip().replace("\\", "/")
    if p.startswith("/"): p = p[1:]
    if p and not p.endswith("/"): p += "/"
    return p

def endpoint_for(region):
    return "https://s3.wasabisys.com" if region in ("", "us-east-1") else f"https://s3.{region}.wasabisys.com"

def discover_region(ak, sk, bucket):
    s3g = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk, endpoint_url="https://s3.wasabisys.com")
    try:
        r = s3g.head_bucket(Bucket=bucket)
        return r["ResponseMetadata"]["HTTPHeaders"].get("x-amz-bucket-region", "us-east-1")
    except Exception:
        return "us-east-1"

def get_client(ak, sk, bucket):
    region = discover_region(ak, sk, bucket)
    s3 = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk,
                      endpoint_url=endpoint_for(region), region_name=region,
                      config=Config(signature_version="s3v4"))
    return s3

def list_keys(s3, bucket, prefix, max_items):
    paginator = s3.get_paginator("list_objects_v2")
    keys = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for o in page.get("Contents", []):
            keys.append(o["Key"])
            if len(keys) >= max_items: return keys
    return keys

def safe_b64decode(s):
    s = re.sub(r"[^A-Za-z0-9+/=]", "", s.strip())
    pad = len(s) % 4
    if pad: s += "=" * (4 - pad)
    try: return base64.b64decode(s)
    except: return b""

def decode_candidates(raw: bytes):
    tries=[]
    # plain
    try:
        txt = raw.decode("utf-8-sig", errors="ignore").strip()
        if txt: tries.append(("plain", txt))
    except: pass
    # gzip
    try:
        txt = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if txt: tries.append(("gzip", txt))
    except: pass
    # base64 whole
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b:
            if b[:2] == b"\x1f\x8b":
                tries.append(("b64+gzip", gzip.decompress(b).decode("utf-8-sig", errors="ignore").strip()))
            else:
                tries.append(("b64_text", b.decode("utf-8-sig", errors="ignore").strip()))
    except: pass
    return tries or [("raw", raw.decode("utf-8", errors="ignore"))]

# embedded base64 strings
def embedded_payloads_from_text(txt):
    outs=[]
    for m in re.finditer(r"(H4sIA[A-Za-z0-9+/=]{40,})", txt):
        b = safe_b64decode(m.group(1))
        if not b: continue
        if b[:2]==b"\x1f\x8b":
            try:
                outs.append(gzip.decompress(b).decode("utf-8-sig","ignore"))
            except: pass
    return outs

def extract_xmls_from_text(txt):
    outs=[]
    s=(txt or "").strip()
    if s.startswith("<") or s.startswith("<?xml"): outs.append(s)
    else:
        m=re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
        if m: outs.append(m.group(0))
    return outs

def compile_pat(term, regex=False):
    return re.compile(term, re.I) if regex else re.compile(re.escape(term), re.I)

# --- Search logic ---
if run:
    if not bucket or not ak or not sk or not prefix or not main_query.strip():
        st.error("❗ Please fill bucket, prefix, credentials, and the mandatory search term.")
        st.stop()

    s3 = get_client(ak, sk, bucket)
    pf = fix_prefix(prefix)
    keys = list_keys(s3, bucket, pf, max_keys)
    if not keys:
        st.warning("No files found under prefix.")
        st.stop()

    st.info(f"Scanning {len(keys)} objects under `{pf}`...")
    pat_main = compile_pat(main_query, regex=(search_mode=="Regular expression"))
    optional_terms = [t for t in [opt_query1, opt_query2, opt_query3] if t.strip()]
    pats_optional = [compile_pat(t, regex=(search_mode=="Regular expression")) for t in optional_terms]

    results=[]
    prog=st.progress(0)

    for i,key in enumerate(keys):
        hit=False
        content_preview=""
        try:
            obj=s3.get_object(Bucket=bucket, Key=key)
            raw=obj["Body"].read()
            decs=[t for _,t in decode_candidates(raw)]
            all_txt=" ".join(decs)
            embeds=[]
            for d in decs:
                embeds.extend(embedded_payloads_from_text(d))
            all_txt+=" ".join(embeds)
            xmls=[]
            for d in decs+embeds:
                xmls.extend(extract_xmls_from_text(d))
            xml_text=" ".join(xmls)
            all_data=f"{key}\n{all_txt}\n{xml_text}"

            if not pat_main.search(all_data):
                continue

            # Optional filters check (must all match if provided)
            if optional_terms:
                if not all(pat.search(all_data) for pat in pats_optional):
                    continue

            hit=True
            content_preview = xml_text if xmls else all_txt
            results.append({"Key": key, "Preview": content_preview[:4000]})

        except Exception as e:
            if debug: st.write(f"{key}: {e}")
        prog.progress(int((i+1)/len(keys)*100))
    prog.empty()

    if not results:
        st.error("❌ No XMLs matched all provided filters.")
        st.stop()

    st.success(f"✅ Found {len(results)} matching XMLs.")
    df = [{"Key":r["Key"], "Preview": r["Preview"][:500]} for r in results]
    st.dataframe(df)
    sel = st.selectbox("Select XML to preview:", [r["Key"] for r in results])
    chosen = next(r for r in results if r["Key"] == sel)
    st.code(chosen["Preview"], language="xml")
    st.download_button("⬇️ Download Matched XML", chosen["Preview"].encode("utf-8"), "match.xml")
