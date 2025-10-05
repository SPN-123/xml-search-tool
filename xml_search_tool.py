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
st.set_page_config(page_title="Wasabi XML Finder", layout="wide")
st.title("🕵️ Wasabi XML Finder — robust decode + deep unescape + filters")

st.markdown("""
Search Wasabi XML files with **robust decode**, **deep unescape**, and **filters**.  
Now also **auto-decodes Base64-GZIP blobs** (e.g., lines starting with `nH4sIA...`) so your XML content is searchable.
""")

# ------------------------------------------------------------
# SIDEBAR – Wasabi creds
# ------------------------------------------------------------
st.sidebar.header("🔐 Wasabi Credentials")
access_key  = st.sidebar.text_input("Access Key", type="password")
secret_key  = st.sidebar.text_input("Secret Key", type="password")
region      = st.sidebar.text_input("Region", value="ap-south-1")  # informational
bucket_name = st.sidebar.text_input("Bucket Name")

# ------------------------------------------------------------
# Inputs
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
# Helpers
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
    """
    Find base64 blocks in the text and try to gunzip them.
    Returns a list of decoded strings (may be multiple blocks; we search all).
    """
    results = []
    # greedy-ish: look for long-ish base64 segments (common in your logs)
    for m in re.finditer(r"[A-Za-z0-9+/=]{80,}", text):
        chunk = m.group(0)
        try:
            data = base64.b64decode(chunk, validate=True)
        except Exception:
            continue
        # GZIP magic header
        if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
            try:
                decompressed = gzip.decompress(data)
                results.append(decode_bytes_best_effort(decompressed))
            except Exception:
                # sometimes there's extra padding or partial blocks – ignore if it fails
                pass
    return results

def get_searchable_content(raw: bytes) -> tuple[str, list[str]]:
    """
    Return (primary_text, extras) where:
      - primary_text is the unescaped normal decode of the file
      - extras is a list of decoded texts from any Base64-GZIP blobs found
    """
    base = deep_unescape(decode_bytes_best_effort(raw))
    extras = extract_and_decompress_base64_gzip(base)
    # also deep-unescape extras
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
    # check key and all content blocks (base + any decompressed extras)
    targets = [key] + content_blocks
    if mode == "Literal text":
        return any(literal_ci(t, term) for t in targets)
    return any(regex_ci(t, term) for t in targets)

def optionals_pass(content_blocks: list[str], *filters: str) -> bool:
    # optional filters apply to content only (base + extras)
    joined = "\n".join(content_blocks).lower()
    for f in filters:
        if f and f.lower() not in joined:
            return False
    return True

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket_name, prefix, mandatory_term]):
        st.error("Please fill in Access Key, Secret Key, Bucket, Prefix and Mandatory term.")
    else:
        st.info("Scanning files in Wasabi... please wait ⏳")
        try:
            # Global endpoint is the most reliable across regions
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

                        if debug:
                            st.markdown(f"**🔎 {key}**")
                            st.text(f"  base length: {len(base_text)} | extras: {len(extras)}")
                            if extras:
                                st.text("  decoded GZIP blocks found → will search inside them")

                            preview = base_text[:200].replace("\n", "\\n").replace("\r", "")
                            st.markdown(f"  base preview (first 200):\n```\n{preview}\n```")
                            for i, ex in enumerate(extras[:2], 1):
                                p = ex[:200].replace("\n", "\\n").replace("\r", "")
                                st.markdown(f"  extra[{i}] preview (first 200):\n```\n{p}\n```")

                        if mandatory_matches(key, blocks, mandatory_term, search_mode) and \
                           optionals_pass(blocks, optional_filter1, optional_filter2, optional_filter3):
                            results.append(key)
                        elif debug:
                            st.text(f"[skip] {key} — mandatory or optional filters not matched")

                    except Exception as e:
                        st.warning(f"Error reading {key}: {e}")

                if results:
                    st.success(f"✅ Found {len(results)} matching XMLs.")
                    for r in results:
                        st.code(r)
                else:
                    st.warning(f"No XML matched your search (scanned {total}).")

        except Exception as e:
            st.error(f"Connection or listing error: {e}")
