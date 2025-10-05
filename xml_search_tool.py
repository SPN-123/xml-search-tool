import streamlit as st
import boto3
import re
import html
import base64
import gzip
from io import BytesIO

# ------------------------------------------------------------
# PAGE CONFIG
# ------------------------------------------------------------
st.set_page_config(page_title="XML Search Tool", layout="wide")
st.title("🧩 XML Search Tool")

st.markdown("""
Search Wasabi XML files with **robust decode**, **deep unescape**, and **filters**.  
Now includes **Base64 + GZIP decoding** and a **Download Matching XML** feature.
""")

# ------------------------------------------------------------
# SIDEBAR
# ------------------------------------------------------------
st.sidebar.header("🔐 Wasabi Credentials")
access_key  = st.sidebar.text_input("Access Key", type="password")
secret_key  = st.sidebar.text_input("Secret Key", type="password")
region      = st.sidebar.text_input("Region", value="ap-south-1")
bucket_name = st.sidebar.text_input("Bucket Name")

# ------------------------------------------------------------
# INPUTS
# ------------------------------------------------------------
st.subheader("📂 Prefix Scan & Search")

prefix           = st.text_input("Prefix to scan (folder, trailing '/' optional)", "")
mandatory_term   = st.text_input("🔹 Mandatory term (required)")
optional_filter1 = st.text_input("Optional filter 1 (content only)", "")
optional_filter2 = st.text_input("Optional filter 2 (content only)", "")
optional_filter3 = st.text_input("Optional filter 3 (content only)", "")
search_mode      = st.selectbox("Search mode", ["Literal text", "Regex pattern"])
debug            = st.checkbox("Show debug info", value=False)

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------
def deep_unescape(text: str) -> str:
    if not text:
        return ""
    prev = None
    while text != prev:
        prev = text
        text = html.unescape(text)
    return text

def decode_bytes_best_effort(raw: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode(errors="ignore")

def extract_and_decompress_base64_gzip(text: str) -> list[str]:
    results = []
    for m in re.finditer(r"[A-Za-z0-9+/=]{80,}", text):
        chunk = m.group(0)
        try:
            data = base64.b64decode(chunk, validate=True)
        except Exception:
            continue
        if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
            try:
                decompressed = gzip.decompress(data)
                results.append(decode_bytes_best_effort(decompressed))
            except Exception:
                pass
    return results

def get_searchable_content(raw: bytes) -> tuple[str, list[str]]:
    base = deep_unescape(decode_bytes_best_effort(raw))
    extras = extract_and_decompress_base64_gzip(base)
    extras = [deep_unescape(x) for x in extras]
    return base, extras

def literal_ci(hay: str, needle: str) -> bool:
    return needle.lower() in hay.lower()

def regex_ci(hay: str, pattern: str) -> bool:
    try:
        return re.search(pattern, hay, flags=re.IGNORECASE | re.DOTALL) is not None
    except re.error:
        return False

def mandatory_matches(key: str, content_blocks: list[str], term: str, mode: str) -> bool:
    targets = [key] + content_blocks
    if mode == "Literal text":
        return any(literal_ci(t, term) for t in targets)
    return any(regex_ci(t, term) for t in targets)

def optionals_pass(content_blocks: list[str], *filters: str) -> bool:
    joined = "\n".join(content_blocks).lower()
    for f in filters:
        if f and f.lower() not in joined:
            return False
    return True

def fetch_full_decoded_xml(s3, bucket, key):
    """Fetch and return fully readable XML content from Wasabi (decoded if Base64+GZIP)."""
    obj = s3.get_object(Bucket=bucket, Key=key)
    raw = obj["Body"].read()
    base, extras = get_searchable_content(raw)
    if extras:
        return extras[0]
    return base

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket_name, prefix, mandatory_term]):
        st.error("Please fill in all required fields.")
    else:
        st.info("Scanning files in Wasabi... please wait ⏳")
        try:
            s3 = boto3.client(
                "s3",
                endpoint_url="https://s3.wasabisys.com",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            resp = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            files = resp.get("Contents", [])

            if not files:
                st.warning("No files found under this prefix.")
            else:
                results = []
                total = len(files)

                for f in files:
                    key = f["Key"]
                    try:
                        body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
                        base_text, extras = get_searchable_content(body)
                        blocks = [base_text] + extras

                        if mandatory_matches(key, blocks, mandatory_term, search_mode) and \
                           optionals_pass(blocks, optional_filter1, optional_filter2, optional_filter3):
                            results.append(key)
                            if debug:
                                st.text(f"✅ Matched {key}")
                        elif debug:
                            st.text(f"[skip] {key}")

                    except Exception as e:
                        st.warning(f"Error reading {key}: {e}")

                if results:
                    st.success(f"✅ Found {len(results)} matching XML(s).")

                    for key in results:
                        st.code(key)
                        try:
                            xml_text = fetch_full_decoded_xml(s3, bucket_name, key)
                            xml_bytes = xml_text.encode("utf-8")
                            st.download_button(
                                label=f"⬇️ Download {key.split('/')[-1]}",
                                data=xml_bytes,
                                file_name=f"{key.split('/')[-1]}.xml",
                                mime="application/xml"
                            )
                        except Exception as e:
                            st.warning(f"Could not prepare download for {key}: {e}")

                else:
                    st.warning(f"No XML matched your search (scanned {total}).")

        except Exception as e:
            st.error(f"Connection or listing error: {e}")
