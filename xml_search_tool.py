# app.py — Wasabi Multi-Search (Path + Decoded Text + Embedded b64/gzip + XML/XPath)
# Finds XML/text that matches 1 mandatory term + up to 3 optional filters.
# Lets you preview one match, download one match, or download ALL matches as a ZIP.

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

# lxml (optional for XPath)
try:
    from lxml import etree
    LXML_AVAILABLE = True
except Exception:
    LXML_AVAILABLE = False

# ========================= UI =========================
st.set_page_config(page_title="Wasabi Multi-Search XML Finder", layout="wide")
st.title("🔍 Wasabi Multi-Search — Path + Decoded Text + Embedded Payloads + XML/XPath")

c1, c2 = st.columns([1.2, 2])
with c1:
    bucket = st.text_input("Bucket name", "")
with c2:
    ak = st.text_input("Wasabi Access Key", type="password")
sk = st.text_input("Wasabi Secret Key", type="password")

st.subheader("📁 Prefix Scan & Search")
prefix = st.text_input("Prefix to scan (folder path; no leading '/', ends with '/' — I'll add it if missing)", "")

row1 = st.columns(4)
with row1[0]:
    search_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
with row1[1]:
    main_query = st.text_input("🔹 Mandatory Search Term (required)", "")
with row1[2]:
    opt_query1 = st.text_input("Optional Filter 1", "")
with row1[3]:
    opt_query2 = st.text_input("Optional Filter 2", "")
opt_query3 = st.text_input("Optional Filter 3", "")

row2 = st.columns(4)
with row2[0]:
    where_scope = st.selectbox("Where to search", [
        "All (Path + Decoded + Embedded + XML)",
        "Path only",
        "Decoded+Embedded+XML only",
        "XML only",
    ])
with row2[1]:
    max_keys = st.number_input("Max objects to scan", min_value=1, value=500, step=1)
with row2[2]:
    case_sensitive = st.checkbox("Case sensitive", value=False)
with row2[3]:
    debug = st.checkbox("Debug (show decode kinds & embedded hits)")

run_btn = st.button("🚀 Scan Prefix & Find Matches")

st.divider()
st.markdown("### 🧪 Peek one object (optional) — paste exact key to see how it decodes")
peek_key = st.text_input("Exact object key (e.g. RZBPD/.../UpdateRestrictions/abc.txt)", "")
peek_btn = st.button("🔍 Peek this object")

st.divider()

# ========================= Helpers =========================
def fix_prefix(p: str) -> str:
    p = (p or "").replace("\\", "/").strip()
    p = re.sub(r"^/+", "", p)
    p = re.sub(r"/{2,}", "/", p)
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
            if len(out) >= max_items:
                return out
    return out

def safe_b64decode(s: str) -> bytes:
    s = re.sub(r"[^A-Za-z0-9+/=]", "", (s or "").strip().replace("\n", "").replace("\r", ""))
    if not s: return b""
    pad = len(s) % 4
    if pad: s += "=" * (4 - pad)
    try:
        return base64.b64decode(s)
    except Exception:
        return b""

def decode_candidates(raw: bytes):
    """Return list[(kind, text)] from raw bytes: plain, gzip, base64_text, b64+gzip, fallback."""
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
    # base64→(maybe gzip)
    try:
        s = raw.decode("utf-8", errors="ignore")
        b = safe_b64decode(s)
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

# embedded base64 (includes typical H4sIA... gzip and long base64 blobs)
B64_CHUNK = re.compile(r"(H4sIA[A-Za-z0-9+/=]{40,}|[A-Za-z0-9+/]{80,}={0,2})")
def embedded_payloads_from_text(txt: str):
    outs = []
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

def extract_xmls_from_text(txt: str):
    outs = []
    s = (txt or "").strip()
    # JSON with embedded XML or base64 payloads
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
                                b = safe_b64decode(vs)
                                if b:
                                    if len(b) > 2 and b[:2] == b"\x1f\x8b":
                                        try:
                                            t2 = gzip.decompress(b).decode("utf-8-sig", "ignore").strip()
                                            outs.extend(extract_xmls_from_text(t2))
                                        except Exception:
                                            pass
                                    else:
                                        try:
                                            t2 = b.decode("utf-8-sig", "ignore").strip()
                                            outs.extend(extract_xmls_from_text(t2))
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
        m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
        if m: outs.append(m.group(0))
    # unique
    seen = set(); uniq = []
    for x in outs:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def pretty_xml(x: str) -> str:
    try:
        return minidom.parseString(x).toprettyxml(indent="  ")
    except Exception:
        return x

def compile_pat(term: str, regex: bool, case_sensitive: bool):
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(term, flags) if regex else re.compile(re.escape(term), flags)

def hl(text: str, pat: re.Pattern) -> str:
    esc = html.escape(text or "")
    spans = [(m.start(), m.end()) for m in pat.finditer(esc)]
    if not spans: return f"<pre>{esc[:2000]}</pre>"
    out, p = [], 0
    for s, e in spans:
        out.append(esc[p:s]); out.append("<mark>"); out.append(esc[s:e]); out.append("</mark>")
        p = e
    out.append(esc[p:])
    snip = "".join(out)
    if len(snip) > 20000: snip = snip[:20000] + "..."
    return f"<pre style='white-space:pre-wrap;word-break:break-word'>{snip}</pre>"

# ========================= Peek one object =========================
if peek_btn:
    try:
        if not (bucket and ak and sk and peek_key.strip()):
            st.error("Bucket, keys and exact object key are required."); st.stop()
        s3 = get_client(ak, sk, bucket)
        obj = s3.get_object(Bucket=bucket, Key=peek_key.strip())
        raw = obj["Body"].read()
        tries = decode_candidates(raw)
        st.write("Decode kinds:", [k for k, _ in tries] or ["(none)"])
        for kind, t in tries[:3]:
            st.write(f"**{kind} preview:**"); st.code(t[:2000])
            embeds = embedded_payloads_from_text(t)
            if embeds:
                st.info(f"Embedded payloads found: {len(embeds)} (showing first 800 chars)")
                st.code((embeds[0] or "")[:800])
            xmls = []
            for t2 in [t] + embeds:
                xmls.extend(extract_xmls_from_text(t2))
            if xmls:
                st.success(f"Extracted {len(xmls)} XML candidate(s) — pretty first:")
                st.code(pretty_xml(xmls[0])[:4000], language="xml")
    except Exception as e:
        st.error(f"Peek failed: {e}")

# ========================= Scan Prefix =========================
if run_btn:
    try:
        if not (bucket and ak and sk and prefix and main_query.strip()):
            st.error("Please fill bucket, credentials, prefix, and the mandatory term."); st.stop()

        s3 = get_client(ak, sk, bucket)
        pf = fix_prefix(prefix)
        keys = list_keys(s3, bucket, pf, int(max_keys))
        if not keys:
            st.warning("No objects under that prefix."); st.stop()

        use_xpath = (search_mode == "XPath (requires lxml)")
        if use_xpath and not LXML_AVAILABLE:
            st.error("lxml is not available for XPath searches."); st.stop()

        pat_main = None if use_xpath else compile_pat(main_query, regex=(search_mode == "Regular expression"), case_sensitive=case_sensitive)
        optional_terms = [q.strip() for q in (opt_query1, opt_query2, opt_query3) if q.strip()]
        pats_opt = [] if use_xpath else [compile_pat(q, regex=(search_mode == "Regular expression"), case_sensitive=case_sensitive) for q in optional_terms]

        st.info(f"Scanning {len(keys)} objects under `{pf}` …")
        results = []  # each: {"Key": key, "Content": full_text_or_xml}
        prog = st.progress(0)

        for i, key in enumerate(keys):
            try:
                # A) PATH search first
                if where_scope in ("All (Path + Decoded + Embedded + XML)", "Path only") and not use_xpath:
                    if pat_main.search(key):
                        # also ensure optional filters match path if provided
                        if all(p.search(key) for p in pats_opt):
                            results.append({"Key": key, "Content": key})
                            prog.progress(int((i+1)/len(keys)*100))
                            continue

                if where_scope == "Path only":
                    prog.progress(int((i+1)/len(keys)*100))
                    continue

                # B) Fetch object and decode
                obj = s3.get_object(Bucket=bucket, Key=key)
                raw = obj["Body"].read()
                tries = decode_candidates(raw)
                decoded_texts = [t for _, t in tries] or [raw.decode("utf-8", errors="ignore")]

                if debug:
                    st.write(f"{key} → decode kinds: {[k for k,_ in tries] or ['fallback']}")

                # Build a searchable corpus (decoded + embedded payloads + extracted XML)
                corpus_texts = list(decoded_texts)
                embedded_all = []
                for t in decoded_texts:
                    embedded_all.extend(embedded_payloads_from_text(t))
                corpus_texts.extend(embedded_all)

                extracted_xmls = []
                for t in decoded_texts + embedded_all:
                    extracted_xmls.extend(extract_xmls_from_text(t))

                # C) Decide matches
                matched = False
                full_content = ""

                if use_xpath:
                    # XPath must match on at least one extracted XML
                    for x in extracted_xmls:
                        try:
                            root = etree.fromstring(x.encode("utf-8"))
                            nsmap = {k if k else 'ns': v for k, v in (getattr(root, "nsmap", {}) or {}).items()}
                            main_ok = bool(root.xpath(main_query, namespaces=nsmap))
                            # Optional filters for XPath: treat as additional XPath expressions
                            opt_ok = True
                            for oq in optional_terms:
                                try:
                                    if not root.xpath(oq, namespaces=nsmap):
                                        opt_ok = False; break
                                except Exception:
                                    opt_ok = False; break
                            if main_ok and opt_ok:
                                matched = True
                                full_content = pretty_xml(x)
                                break
                        except Exception:
                            continue
                else:
                    # Text/Regex: search across key + all decoded text + embedded payloads + xml strings
                    haystacks = [key] + corpus_texts + extracted_xmls
                    # Mandatory
                    if any(pat_main.search(h) for h in haystacks):
                        # Optional (AND): all must match somewhere in the haystacks
                        opt_ok = all(any(p.search(h) for h in haystacks) for p in pats_opt)
                        if opt_ok:
                            matched = True
                            # Prefer pretty XML for content if available, else a large decoded blob
                            if extracted_xmls:
                                full_content = pretty_xml(extracted_xmls[0])
                            else:
                                full_content = (corpus_texts[0] if corpus_texts else key)

                if matched:
                    results.append({"Key": key, "Content": full_content})

            except Exception as e:
                if debug:
                    st.write(f"{key}: {e}")

            prog.progress(int((i+1)/len(keys)*100))
        prog.empty()

        if not results:
            st.error("❌ No XMLs matched the mandatory term (and optional filters).")
            st.stop()

        # Normalize previews
        table_rows = [{"Key": r["Key"], "Preview": (r["Content"] or "")[:200]} for r in results]
        st.success(f"✅ Found {len(results)} matching XMLs.")
        st.dataframe(table_rows)

        # Preview selector
        sel = st.selectbox("Select XML to preview:", [r["Key"] for r in results])
        chosen = next(r for r in results if r["Key"] == sel)
        st.code((chosen["Content"] or "")[:4000], language="xml")

        # Download selected
        st.download_button(
            "⬇️ Download Selected XML",
            (chosen["Content"] or "").encode("utf-8"),
            file_name=os.path.basename(chosen["Key"]) or "matched.xml",
            mime="text/xml",
        )

        # Download ALL as ZIP
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for r in results:
                fname = os.path.basename(r["Key"]) or "file.xml"
                if not fname.lower().endswith(".xml"):
                    fname += ".xml"
                zf.writestr(fname, r["Content"] or "")
        zip_buf.seek(0)
        st.download_button(
            "📦 Download ALL matched XMLs (ZIP)",
            data=zip_buf,
            file_name="matched_xmls.zip",
            mime="application/zip",
        )

    except ClientError as e:
        err = e.response.get("Error", {})
        st.error(f"S3 error: {err.get('Code')} — {err.get('Message')}")
    except Exception as e:
        st.error(f"Error: {e}")
