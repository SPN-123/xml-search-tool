import streamlit as st
import boto3
import html
import re
from io import BytesIO, StringIO
from datetime import datetime

# -------------------------------
# Title and Header
# -------------------------------
st.set_page_config(page_title="XML Search Tool", layout="wide")
st.title("XML Search Tool")
st.markdown("""
Use this tool to **search XML files** stored in your Wasabi bucket.
Supports robust decoding, deep unescaping, keyword filters, and **exporting results**.
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
def deep_unescape(text: str) -> str:
    """Unescape multiple levels of HTML/XML entities."""
    if not text:
        return text
    prev = None
    while prev != text:
        prev = text
        text = html.unescape(text)
    return text

def decode_xml_content(raw: bytes) -> str:
    """Try to decode bytes as UTF-8, then latin-1, then best-effort."""
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode(errors="ignore")

def match_text(content: str, term: str, mode: str) -> bool:
    if mode == "Literal text":
        return term in content
    elif mode == "Regex pattern":
        try:
            return re.search(term, content, flags=re.DOTALL) is not None
        except re.error as e:
            st.error(f"Invalid regex: {e}")
            return False
    return False

def list_all_objects(s3, bucket: str, prefix: str):
    """Generator that yields all objects under a prefix (handles pagination)."""
    kwargs = {"Bucket": bucket, "Prefix": prefix}
    while True:
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            yield obj
        if resp.get("IsTruncated"):
            kwargs["ContinuationToken"] = resp.get("NextContinuationToken")
        else:
            break

# -------------------------------
# Search Execution
# -------------------------------
results_meta = []   # to hold dicts: {key, size, last_modified}
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

        try:
            total_scanned = 0
            match_count = 0
            filters = [optional_filter1, optional_filter2, optional_filter3]

            for obj in list_all_objects(s3, bucket_name, prefix):
                key = obj["Key"]
                total_scanned += 1
                try:
                    data = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
                    content = deep_unescape(decode_xml_content(data))

                    if match_text(content, mandatory_term, search_mode):
                        # all non-empty optional filters must be contained in content
                        if all((filt in content) if filt else True for filt in filters):
                            results_meta.append({
                                "key": key,
                                "size": obj.get("Size", 0),
                                "last_modified": obj.get("LastModified")
                            })
                            match_count += 1
                except Exception as e:
                    st.warning(f"Error reading {key}: {e}")

            if results_meta:
                st.success(f"✅ Found {match_count} matching files (scanned {total_scanned}).")
                for r in results_meta[:300]:
                    # show first 300 keys inline to keep UI responsive
                    lm = r["last_modified"]
                    lm_str = lm.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if isinstance(lm, datetime) else str(lm)
                    st.code(f'{r["key"]}    | {r["size"]} bytes | {lm_str}')
                if len(results_meta) > 300:
                    st.info(f"...and {len(results_meta) - 300} more. Use the download buttons below to get the full list.")
            else:
                st.warning("No files matched your criteria.")

        except Exception as e:
            st.error(f"Connection or listing error: {e}")

# -------------------------------
# Downloads
# -------------------------------
if results_meta:
    # TXT (just the keys)
    keys_txt = "\n".join(r["key"] for r in results_meta)
    st.download_button(
        "⬇️ Download matches (.txt)",
        data=keys_txt.encode("utf-8"),
        file_name="xml_search_matches.txt",
        mime="text/plain",
    )

    # CSV (key,size,last_modified)
    csv_buf = StringIO()
    csv_buf.write("key,size,last_modified\n")
    for r in results_meta:
        lm = r["last_modified"]
        lm_str = lm.astimezone().isoformat() if isinstance(lm, datetime) else (lm or "")
        # Escape quotes if any
        key_safe = '"' + r["key"].replace('"', '""') + '"'
        csv_buf.write(f"{key_safe},{r['size']},{lm_str}\n")

    st.download_button(
        "⬇️ Download matches (.csv)",
        data=csv_buf.getvalue().encode("utf-8"),
        file_name="xml_search_matches.csv",
        mime="text/csv",
    )
