import streamlit as st
import boto3
import xml.etree.ElementTree as ET
import html
import re
from io import BytesIO

# -------------------------------
# Title and Header
# -------------------------------
st.set_page_config(page_title="XML Search Tool", layout="wide")

st.title("XML Search Tool")

st.markdown("""
Use this tool to **search XML files** stored in your Wasabi bucket.
Supports robust decoding, deep unescaping, and keyword filters.
""")

# -------------------------------
# S3 Configuration
# -------------------------------
st.sidebar.header("🔐 Wasabi Credentials")
access_key = st.sidebar.text_input("Access Key", type="password")
secret_key = st.sidebar.text_input("Secret Key", type="password")
region = st.sidebar.text_input("Region", value="ap-south-1")
bucket_name = st.sidebar.text_input("Bucket Name")

# -------------------------------
# Prefix and Search Filters
# -------------------------------
st.subheader("📂 Prefix Scan & Search")

prefix = st.text_input("Prefix to scan (folder, trailing '/' optional)", "")
mandatory_term = st.text_input("🔹 Mandatory term (required)")
optional_filter1 = st.text_input("Optional filter 1 (content only)", "")
optional_filter2 = st.text_input("Optional filter 2 (content only)", "")
optional_filter3 = st.text_input("Optional filter 3 (content only)", "")

search_mode = st.selectbox("Search mode", ["Literal text", "Regex pattern"])

# -------------------------------
# Helper Functions
# -------------------------------
def deep_unescape(text):
    """Unescape multiple levels of HTML/XML entities."""
    if not text:
        return text
    prev = None
    while prev != text:
        prev = text
        text = html.unescape(text)
    return text

def decode_xml_content(content):
    """Try to decode bytes as UTF-8 or fallback safely."""
    try:
        return content.decode("utf-8")
    except Exception:
        try:
            return content.decode("latin-1")
        except Exception:
            return content.decode(errors="ignore")

def match_text(content, term, mode):
    """Check if content contains the search term."""
    if mode == "Literal text":
        return term in content
    elif mode == "Regex pattern":
        return re.search(term, content) is not None
    return False

# -------------------------------
# Search Execution
# -------------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket_name, region, prefix, mandatory_term]):
        st.error("Please fill in all required fields.")
    else:
        st.info("Searching files... please wait ⏳")

        # Connect to Wasabi (S3 compatible)
        s3 = boto3.client(
            "s3",
            endpoint_url=f"https://s3.{region}.wasabisys.com",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        # List all objects under prefix
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        files = response.get("Contents", [])

        results = []

        for f in files:
            key = f["Key"]
            try:
                obj = s3.get_object(Bucket=bucket_name, Key=key)
                raw_data = obj["Body"].read()
                content = deep_unescape(decode_xml_content(raw_data))

                # Match mandatory + optional filters
                if match_text(content, mandatory_term, search_mode):
                    filters = [optional_filter1, optional_filter2, optional_filter3]
                    if all(filt in content or not filt for filt in filters):
                        results.append(key)
            except Exception as e:
                st.warning(f"Error reading {key}: {e}")

        # -------------------------------
        # Show Results
        # -------------------------------
        if results:
            st.success(f"✅ Found {len(results)} matching files.")
            for r in results:
                st.code(r)
        else:
            st.warning("No files matched your criteria.")
