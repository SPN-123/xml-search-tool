# app.py — Wasabi Finder (Path + Decoded Text + Embedded b64+gzip + XML + XPath)
# Paste into Streamlit Cloud. No extra files required.

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
st.set_page_config(page_title="Wasabi Finder — Path + Embedded b64+gzip + XML", layout="wide")
st.title("🔍 Wasabi Finder — Search in Path, Decoded Text, Embedded b64+gzip Payloads, and XML")

c1, c2 = st.columns([1.2, 2])
with c1:
    bucket = st.text_input("Bucket", "")
with c2:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.markdown("### 📁 Prefix Scan")
prefix = st.text_input("Prefix to scan (folder; trailing slash optional)", "")
r1, r2, r3, r4 = st.columns([1.1, 1.6, 1.2, 1])
with r1:
    search_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with r2:
    query = st.text_input("Text / Regex / XPath (matched in path, decoded text, embedded payloads, and XML)", "")
with r3:
    scope = st.selectbox("Where to search", ["All (Path + Decoded + Embedded + XML)", "Path only", "Decoded+Embedded+XML only", "XML only"])
with r4:
    max_keys = st.number_input("Max objects", 1, 5000, 500, 1)

debug = st.checkbox("Debug (show decode kinds & embedded hits)")
run = st.button("🚀 Scan Prefix & Find Matches")

st.divider()
st.markdown("### 🧪 Peek one object (paste exact key to see how it decodes)")
peek_key = st.text_input("Exact object key (optional)", "")
peek = st.button("🔍 Peek this object")

# ---------------- Helpers ----------------
def endpoint_for(region): return "https://s3.wasabisys.com" if not region or region=="us-east-1" else f"https://s3.{region}.wasabisys.com"
def fix_prefix(p):
    p = (p or "").replace("\\","/").strip()
    p = re.sub(r"^/+", "", p); p = re.sub(r"/{2,}", "/", p)
    return p + ("" if p.endswith("/") or not p else "/")

def discover_region(ak, sk, bucket):
    s3g = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk,
                       endpoint_url="https://s3.wasabisys.com",
                       config=Config(signature_version="s3v4"))
    try:
        resp = s3g.head_bucket(Bucket=bucket)
        return resp["ResponseMetadata"]["HTTPHeaders"].get("x-amz-bucket-region","us-east-1")
    except ClientError as e:
        return e.response.get("ResponseMetadata",{}).get("HTTPHeaders",{}).get("x-amz-bucket-region","us-east-1")

def get_client(ak, sk, bucket):
    region = discover_region(ak, sk, bucket)
    endpoint = endpoint_for(region)
    s3 = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk,
                      endpoint_url=endpoint, region_name=region,
                      config=Config(signature_version="s3v4"))
    return s3, region, endpoint

def list_keys(s3, bucket, prefix, max_items):
    paginator = s3.get_paginator("list_objects_v2")
    out=[]
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for o in page.get("Contents", []):
            out.append(o["Key"])
            if len(out) >= max_items: return out
    return out

def safe_b64decode(s):
    s = re.sub(r"[^A-Za-z0-9+/=]", "", (s or "").strip().replace("\n","").replace("\r",""))
    if not s: return b""
    pad = len(s) % 4
    if pad: s += "=" * (4 - pad)
    try:
        return base64.b64decode(s)
    except Exception:
        return b""

def decode_candidates(raw: bytes):
    tries=[]
    # plain
    try:
        t = raw.decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("plain", t))
    except: pass
    # gzip
    try:
        t = gzip.decompress(raw).decode("utf-8-sig", errors="ignore").strip()
        if t: tries.append(("gzip", t))
    except: pass
    # base64 (+maybe gzip) when the WHOLE object is base64
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
        if b:
            if len(b) > 2 and b[:2] == b"\x1f\x8b":
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
    # fallback
    if not tries:
        try:
            t = raw.decode("utf-8", errors="ignore")
            if t: tries.append(("fallback", t))
        except: pass
    return tries

# --- NEW: find and decode base64 *substrings* (e.g., JSON fields with H4sIA... or long base64)
B64_CHUNK = re.compile(r"(?:H4sIA[A-Za-z0-9+/=]{40,}|[A-Za-z0-9+/]{80,}={0,2})")  # long-ish to avoid noise
def embedded_payloads_from_text(txt: str):
    """Return list of decoded strings from base64 or base64+gzip substrings embedded in txt."""
    outs=[]
    for m in B64_CHUNK.finditer(txt or ""):
        bs = m.group(0)
        b = safe_b64decode(bs)
        if not b: continue
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

def extract_xmls_from_text(t: str):
    outs=[]
    s=(t or "").strip()
    # JSON payloads that contain XML strings OR base64-gzip strings
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            payload = json.loads(s)
            def rec(o):
                if isinstance(o, dict):
                    for _, v in o.items():
                        if isinstance(v, str):
                            vs=v.strip()
                            if vs.startswith("<") or vs.startswith("<?xml"):
                                outs.append(vs)
                            else:
                                # base64 in JSON fields → try to decode to text then mine for XML
                                b = safe_b64decode(vs)
                                if b:
                                    if len(b)>2 and b[:2]==b"\x1f\x8b":
                                        try:
                                            t2=gzip.decompress(b).decode("utf-8-sig","ignore").strip()
                                            if t2: outs.extend(extract_xmls_from_text(t2))
                                        except Exception:
                                            pass
                                    else:
                                        try:
                                            t2=b.decode("utf-8-sig","ignore").strip()
                                            if t2: outs.extend(extract_xmls_from_text(t2))
                                        except Exception:
                                            pass
                        else:
                            rec(v)
                elif isinstance(o, list):
                    for it in o: rec(it)
            rec(payload)
        except Exception:
            pass
    # full XML or relaxed XML-ish block
    if s.startswith("<") or s.startswith("<?xml"):
        outs.append(s)
    else:
        m=re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
        if m: outs.append(m.group(0))
    # unique
    seen=set(); uniq=[]
    for x in outs:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def pretty_xml(x):
    try:
        return minidom.parseString(x).toprettyxml(indent="  ")
    except Exception:
        return x

def compile_pat(term, regex=False, case_sensitive=False):
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(term, flags) if regex else re.compile(re.escape(term), flags)

def hl(text, pat):
    esc = html.escape(text or "")
    spans=[(m.start(), m.end()) for m in pat.finditer(esc)]
    if not spans: return f"<pre>{esc[:2000]}</pre>"
    out=[]; p=0
    for s,e in spans:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>"); p=e
    out.append(esc[p:])
    return f"<pre style='white-space:pre-wrap;word-break:break-word'>{''.join(out)[:20000]}</pre>"

# ---------------- Peek one ----------------
if peek:
    try:
        if not (bucket and ak and sk and peek_key.strip()):
            st.error("Bucket, keys, and exact object key are required."); st.stop()
        s3, *_ = get_client(ak, sk, bucket)
        obj = s3.get_object(Bucket=bucket, Key=peek_key.strip())
        raw = obj["Body"].read()
        tries = decode_candidates(raw)
        st.write("Decode kinds:", [k for k,_ in tries] or ["(none)"])
        for kind, t in tries[:3]:
            st.write(f"**{kind} preview:**")
            st.code(t[:2000])
            embeds = embedded_payloads_from_text(t)
            if embeds:
                st.info(f"Embedded payloads found in {kind}: {len(embeds)} (showing first 1k chars)")
                st.code(embeds[0][:1000])
            xmls=[]
            for t2 in [t] + embeds:
                xmls.extend(extract_xmls_from_text(t2))
            if xmls:
                st.success(f"Extracted {len(xmls)} XML candidate(s); pretty-printing first:")
                st.code(pretty_xml(xmls[0])[:4000], language="xml")
    except Exception as e:
        st.error(f"Peek failed: {e}")

# ---------------- Scan ----------------
if run:
    try:
        if not (bucket and prefix and ak and sk and query.strip()):
            st.error("Fill Bucket, Prefix, Access/Secret and Query."); st.stop()
        pf = fix_prefix(prefix)
        s3, region, endpoint = get_client(ak, sk, bucket)
        keys = list_keys(s3, bucket, pf, int(max_keys))
        if not keys:
            st.warning("No objects found under that prefix."); st.stop()

        use_xpath = (search_mode=="XPath (requires lxml)")
        if use_xpath and not LXML_AVAILABLE:
            st.error("lxml not available for XPath."); st.stop()
        pat = None if use_xpath else compile_pat(query, regex=(search_mode=="Regular expression"))

        matches=[]
        prog = st.progress(0)
        for i, key in enumerate(keys):
            hit=False

            # A) Path
            if scope in ("All (Path + Decoded + Embedded + XML)", "Path only"):
                if pat and pat.search(key) or (not pat and not use_xpath and query.lower() in key.lower()):
                    matches.append({"key":key,"where":"path","content":None})
                    hit=True

            if scope=="Path only":
                prog.progress(int((i+1)/len(keys)*100)); continue

            # B) Fetch & decode
            try:
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()
                tries = decode_candidates(raw)
                decoded = [t for _,t in tries] or [raw.decode("utf-8",errors="ignore")]

                if debug:
                    st.write(f"{key} → decode kinds: {[k for k,_ in tries] or ['fallback']}")

                # B1) Decoded text
                if scope in ("All (Path + Decoded + Embedded + XML)", "Decoded+Embedded+XML only"):
                    if not use_xpath:
                        for t in decoded:
                            if pat.search(t):
                                matches.append({"key":key,"where":"decoded","content":t})
                                hit=True; break

                # B2) Embedded base64/base64+gzip inside the decoded text
                if not hit and scope in ("All (Path + Decoded + Embedded + XML)", "Decoded+Embedded+XML only"):
                    if not use_xpath:
                        for t in decoded:
                            embeds = embedded_payloads_from_text(t)
                            if debug and embeds:
                                st.write(f"• embedded payloads: {len(embeds)}")
                            for e in embeds:
                                if pat.search(e):
                                    matches.append({"key":key,"where":"embedded-decoded","content":e})
                                    hit=True; break
                            if hit: break

                # C) XML (from decoded & embedded payloads)
                if not hit and scope in ("All (Path + Decoded + Embedded + XML)", "Decoded+Embedded+XML only", "XML only"):
                    xmls=[]
                    for t in decoded:
                        xmls.extend(extract_xmls_from_text(t))
                        for e in embedded_payloads_from_text(t):
                            xmls.extend(extract_xmls_from_text(e))
                    # dedup
                    seen=set(); xmls=[x for x in xmls if not (x in seen or seen.add(x))]
                    for x in xmls:
                        if use_xpath:
                            try:
                                root = etree.fromstring(x.encode("utf-8"))
                                nsmap = {k if k else 'ns': v for k,v in (getattr(root,"nsmap",{}) or {}).items()}
                                if root.xpath(query, namespaces=nsmap):
                                    matches.append({"key":key,"where":"xml:xpath","content":pretty_xml(x)})
                                    hit=True; break
                            except Exception:
                                continue
                        else:
                            if pat.search(x):
                                matches.append({"key":key,"where":"xml:text","content":pretty_xml(x)})
                                hit=True; break

            except Exception as e:
                if debug: st.write(f"{key}: {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not matches:
            st.error("❌ No matches found in path, decoded text, embedded payloads, or XML.")
            st.stop()

        st.success(f"✅ Found {len(matches)} match(es).")
        st.dataframe([{"Key":m["key"],"Where":m["where"]} for m in matches])

        sel = st.selectbox("Preview which match?", [m["key"] for m in matches])
        chosen = next(m for m in matches if m["key"]==sel)
        content = chosen["content"]
        if content is None:
            st.info("Matched by PATH; no content to preview.")
        else:
            if chosen["where"].startswith("xml"):
                st.subheader("Preview (XML)"); st.code(content[:4000], language="xml")
            else:
                st.subheader("Preview (text)"); st.markdown(hl(content, pat), unsafe_allow_html=True)
        st.download_button("⬇️ Download matched content", (content or "").encode("utf-8"), file_name="match.txt")

    except ClientError as e:
        err=e.response.get("Error",{}); st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Error: {e}")
