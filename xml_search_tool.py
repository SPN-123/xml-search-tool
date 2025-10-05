import streamlit as st
import boto3
import re
import html

# ------------------------------------------------------------
# PAGE CONFIG
# ------------------------------------------------------------
st.set_page_config(page_title="Wasabi XML Finder", layout="wide")
st.title("🕵️ Wasabi XML Finder — robust decode + deep unescape + filters")

st.markdown("""
Search Wasabi XML files with **robust decode**, **deep unescape**, and **filters**.  
Use debug mode to preview decoded content and confirm term visibility.
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
def deep_unescape(text):
    """Unescape nested HTML/XML entities."""
    if not text:
        return ""
    prev = None
    while text != prev:
        prev = text
        text = html.unescape(text)
    return text

def decode_xml_content(raw):
    """Decode bytes into readable text (robust fallback)."""
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode(errors="ignore")

def match_text(content, term, mode):
    """Match literal (case-insensitive) or regex pattern."""
    if not term:
        return False
    if mode == "Literal text":
        return term.lower() in content.lower()
    try:
        return re.search(term, content, flags=re.IGNORECASE | re.DOTALL) is not None
    except re.error:
        return False

# ------------------------------------------------------------
# MAIN SEARCH
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

            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            files = response.get("Contents", [])

            if not files:
                st.warning("No files found under this prefix.")
            else:
                results = []
                total = len(files)

                for f in files:
                    key = f["Key"]
                    try:
                        obj = s3.get_object(Bucket=bucket_name, Key=key)
                        raw = obj["Body"].read()
                        text = deep_unescape(decode_xml_content(raw))

                        if debug:
                            preview = text[:300].replace("\n", "\\n").replace("\r", "")
                            st.markdown(f"**🔍 {key} — first 300 chars:**\n```\n{preview}\n```")

                        if match_text(text, mandatory_term, search_mode):
                            filters = [optional_filter1, optional_filter2, optional_filter3]
                            if all(flt.lower() in text.lower() or not flt for flt in filters):
                                results.append(key)
                            elif debug:
                                st.text(f"[skip] {key} — optional filter not matched")
                        elif debug:
                            st.text(f"[skip] {key} — mandatory term not matched")

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
