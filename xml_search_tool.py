import streamlit as st
import boto3, re, io, zipfile, html, json, codecs
from xml.dom import minidom
from botocore.config import Config

st.set_page_config(page_title="Wasabi XML Search — Multi Filter + Decode + Download All", layout="wide")
st.title("🔍 Wasabi XML Search — Multi Filter + Decode + Download All")

# ---- Sidebar Secrets ----
st.sidebar.header("🔐 Wasabi Credentials")
bucket = st.sidebar.text_input("Bucket name (e.g. rzgnprdws-code-90d)")
access_key = st.sidebar.text_input("Access key", type="password")
secret_key = st.sidebar.text_input("Secret key", type="password")
endpoint_url = st.sidebar.text_input("Endpoint URL (e.g. https://s3.wasabisys.com)", "https://s3.wasabisys.com")

if not bucket or not access_key or not secret_key:
    st.warning("Please fill bucket and keys to continue.")
    st.stop()

# ---- Search UI ----
st.header("Prefix Scan & Search")

prefix = st.text_input(
    "Prefix to scan (folder path, ends with /)",
    help="Full folder path under bucket (no leading slash, must end with /)"
)

mandatory_term = st.text_input("🔹 Mandatory Search Term (required)", "", help="At least one required term")
opt1 = st.text_input("Optional Filter 1", "")
opt2 = st.text_input("Optional Filter 2", "")
opt3 = st.text_input("Optional Filter 3", "")

search_mode = st.selectbox("Search mode", ["Literal text", "Regular expression", "XPath (requires lxml)"])
where_to_search = st.selectbox("Where to search", ["All (Path + Decoded + Embedded XML)", "Decoded + XML only"])
max_objects = st.number_input("Max objects to scan", 1, 2000, 500)
case_sensitive = st.checkbox("Case sensitive", False)

run_button = st.button("🚀 Scan Prefix & Find Matches")

# ---- Deep Decode Helpers ----
def deep_unescape(s: str) -> str:
    """Aggressively decode escaped XML strings"""
    if s is None:
        return ""
    out = s
    for _ in range(3):
        prev = out
        try:
            if (out.startswith('"') and out.endswith('"')) or (out.startswith("'") and out.endswith("'")):
                out = json.loads(out)
            else:
                out = json.loads('"' + out.replace('\\', '\\\\').replace('"', '\\"') + '"')
        except Exception:
            try:
                out = codecs.decode(out, "unicode_escape")
            except Exception:
                pass
        out = html.unescape(out)
        if (out.startswith('"') and out.endswith('"')) or (out.startswith("'") and out.endswith("'")):
            out = out[1:-1]
        if out == prev:
            break
    return out.strip()

def pretty_xml(x: str) -> str:
    if not x:
        return x
    for cand in (x, deep_unescape(x)):
        try:
            return minidom.parseString(cand).toprettyxml(indent="  ")
        except Exception:
            continue
    return deep_unescape(x)

def extract_xmls_from_text(txt: str):
    outs = []
    if not txt:
        return outs
    candidates = [txt]
    u = deep_unescape(txt)
    if u != txt:
        candidates.insert(0, u)
    for c in candidates:
        s = c.strip()
        if s.startswith("<") or s.startswith("<?xml"):
            outs.append(s)
        else:
            m = re.search(r"(<\?xml[\s\S]*?</[^>]+>|<[^>]+>[\s\S]*?</[^>]+>)", s)
            if m:
                outs.append(m.group(0))
    seen = set(); uniq = []
    for x in outs:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq

def embedded_payloads_from_text(t: str):
    matches = re.findall(r"(?:<payload>|\"payload\":\s*\")(.*?)(?:</payload>|\"\,|\")", t, flags=re.DOTALL)
    outs = []
    for m in matches:
        u = deep_unescape(m)
        if u:
            outs.append(u)
    return outs

def decode_candidates(raw_bytes: bytes):
    tries = []
    # try plain
    try:
        txt = raw_bytes.decode("utf-8", errors="ignore").strip()
        if txt:
            tries.append(("plain", txt))
    except Exception:
        pass
    # try base64
    import base64, gzip
    try:
        b64_dec = base64.b64decode(txt)
        tries.append(("b64_text", b64_dec.decode("utf-8", errors="ignore")))
        if b64_dec[:2] == b"\x1f\x8b":
            gz = gzip.decompress(b64_dec).decode("utf-8", errors="ignore")
            tries.append(("b64+gzip", gz))
    except Exception:
        pass
    # try gzip direct
    try:
        gz = gzip.decompress(raw_bytes).decode("utf-8", errors="ignore")
        tries.append(("gzip", gz))
    except Exception:
        pass
    return tries

# ---- Wasabi Client ----
def get_client():
    cfg = Config(signature_version="s3v4", retries={"max_attempts": 3})
    return boto3.client("s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, endpoint_url=endpoint_url, config=cfg)

# ---- Search Logic ----
if run_button:
    if not prefix.endswith("/"):
        prefix += "/"

    client = get_client()
    paginator = client.get_paginator("list_objects_v2")

    results = []
    total_scanned = 0
    filters = [f for f in [opt1.strip(), opt2.strip(), opt3.strip()] if f.strip()]
    required = mandatory_term.strip()
    if not required:
        st.error("Please provide at least one mandatory term.")
        st.stop()

    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if total_scanned >= max_objects:
                break
            key = obj["Key"]
            total_scanned += 1

            # Fetch
            raw = client.get_object(Bucket=bucket, Key=key)["Body"].read()
            tries = decode_candidates(raw)
            decoded = [deep_unescape(t) for _, t in tries]
            embedded = []
            for t in decoded:
                embedded.extend(embedded_payloads_from_text(t))
            embedded = [deep_unescape(t) for t in embedded]
            xmls = []
            for t in decoded + embedded:
                xmls.extend(extract_xmls_from_text(t))

            candidates = []
            if where_to_search.startswith("All"):
                candidates = [key] + decoded + embedded + xmls
            else:
                candidates = decoded + embedded + xmls

            all_text = "\n".join(candidates)
            comp = (lambda a, b: a in b) if case_sensitive else (lambda a, b: a.lower() in b.lower())

            if not comp(required, all_text):
                continue

            # Optional filters: all must match
            if all(comp(f, all_text) for f in filters):
                pretty = ""
                if xmls:
                    pretty = pretty_xml(xmls[0])
                else:
                    pretty = pretty_xml(decoded[0] if decoded else "")
                results.append({"Key": key, "Preview": pretty})

    if not results:
        st.error("❌ No matches found.")
    else:
        st.success(f"✅ Found {len(results)} matches.")
        st.dataframe([{"Key": r["Key"], "Preview": r["Preview"][:200]} for r in results])

        sel = st.selectbox("Select XML to preview:", [r["Key"] for r in results])
        chosen = next(r for r in results if r["Key"] == sel)

        st.download_button(
            "⬇️ Download Selected XML",
            chosen["Preview"].encode("utf-8"),
            file_name=sel.split("/")[-1] or "matched.xml",
            mime="text/xml"
        )

        # ZIP all
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for r in results:
                fname = r["Key"].split("/")[-1] or "file.xml"
                if not fname.lower().endswith(".xml"):
                    fname += ".xml"
                zf.writestr(fname, r["Preview"])
        zip_buf.seek(0)

        st.download_button(
            "📦 Download ALL matched XMLs (ZIP)",
            data=zip_buf,
            file_name="matched_xmls.zip",
            mime="application/zip"
        )

        st.code(chosen["Preview"], language="xml")
