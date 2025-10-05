import streamlit as st
import boto3
import re
import html

# ---------------------------------------------
# PAGE CONFIG
# ---------------------------------------------
st.set_page_config(page_title="XML Search Tool", layout="wide")

# ✅ ONLY CHANGE — Updated title
st.title("🧩 XML Search Tool")

st.markdown("""
Search Wasabi XML files easily with robust decode, deep unescape, and multiple filters.
""")

# ---------------------------------------------
# SIDEBAR – WASABI CREDENTIALS
# ---------------------------------------------
st.sidebar.header("🔐 Wasabi Credentials")

access_key = st.sidebar.text_input("Access Key", type="password")
secret_key = st.sidebar.text_input("Secret Key", type="password")
region = st.sidebar.text_input("Region", value="ap-south-1")
bucket_name = st.sidebar.text_input("Bucket Name")

# ---------------------------------------------
# SEARCH FILTERS
# ---------------------------------------------
st.subheader("📂 Prefix Scan & Search")

prefix = st.text_input("Prefix to scan (folder, trailing '/' optional)", "")
mandatory_term = st.text_input("🔹 Mandatory term (required)")
optional_filter1 = st.text_input("Optional filter 1 (content only)", "")
optional_filter2 = st.text_input("Optional filter 2 (content only)", "")
optional_filter3 = st.text_input("Optional filter 3 (content only)", "")

search_mode = st.selectbox("Search mode", ["Literal text", "Regex pattern"])

# ---------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------
def deep_unescape(text):
    """Unescape multiple layers of HTML/XML encoding"""
    if not text:
        return text
    prev = None
    while prev != text:
        prev = text
        text = html.unescape(text)
    return text

def decode_content(raw_data):
    """Safely decode binary content"""
    try:
        return raw_data.decode("utf-8")
    except Exception:
        try:
            return raw_data.decode("latin-1")
        except Exception:
            return raw_data.decode(errors="ignore")

def match_text(content, term, mode):
    """Check match with literal or regex mode"""
    if mode == "Literal text":
        return term in content
    else:
        try:
            return re.search(term, content, flags=re.IGNORECASE) is not None
        except re.error:
            return False

# ---------------------------------------------
# MAIN SEARCH
# ---------------------------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket_name, region, prefix, mandatory_term]):
        st.error("Please fill in all required fields before searching.")
    else:
        st.info("Searching files... please wait ⏳")

        try:
            # ✅ Original working endpoint logic
            s3 = boto3.client(
                "s3",
                endpoint_url=f"https://s3.{region}.wasabisys.com",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            # List files under prefix
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            files = response.get("Contents", [])

            if not files:
                st.warning("No files found under the given prefix.")
            else:
                results = []
                for f in files:
                    key = f["Key"]
                    try:
                        obj = s3.get_object(Bucket=bucket_name, Key=key)
                        raw = obj["Body"].read()
                        text = deep_unescape(decode_content(raw))

                        # Check mandatory term
                        if match_text(text, mandatory_term, search_mode):
                            # Check optional filters
                            if all(filt in text or filt == "" for filt in [optional_filter1, optional_filter2, optional_filter3]):
                                results.append(key)
                    except Exception as e:
                        st.warning(f"Error reading {key}: {e}")

                if results:
                    st.success(f"✅ Found {len(results)} matching XMLs:")
                    for r in results:
                        st.code(r)
                else:
                    st.warning("No files matched your search criteria.")

        except Exception as e:
            st.error(f"Connection or listing error: {e}")
