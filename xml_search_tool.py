import streamlit as st
import boto3
import botocore
import re
import html

# ---------------------------------------------
# PAGE CONFIG
# ---------------------------------------------
st.set_page_config(page_title="XML Search Tool", layout="wide")

# ✅ TITLE (only UI change you asked for)
st.title("🧩 XML Search Tool")

st.markdown("""
Search Wasabi XML files with robust decode, deep unescape, and multiple filters.
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
# HELPERS
# ---------------------------------------------
def deep_unescape(text: str) -> str:
    if not text:
        return text
    prev = None
    while prev != text:
        prev = text
        text = html.unescape(text)
    return text

def decode_content(raw: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode(errors="ignore")

def match_text(content: str, term: str, mode: str) -> bool:
    if mode == "Literal text":
        return term in content
    try:
        return re.search(term, content, flags=re.IGNORECASE | re.DOTALL) is not None
    except re.error:
        return False

def make_s3_client(access_key, secret_key, region):
    """
    Build an s3 client. Try regional endpoint first,
    then fall back to the global endpoint if the regional one is unreachable.
    """
    session = boto3.session.Session()
    cfg = botocore.config.Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=60)

    # 1) Regional endpoint (what you already had)
    regional = f"https://s3.{region}.wasabisys.com"
    try:
        client = session.client(
            "s3",
            endpoint_url=regional,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=cfg,
        )
        # quick ping (cheap) to ensure endpoint is reachable
        client.list_buckets()
        return client
    except Exception:
        pass

    # 2) Global endpoint (legacy setups often used this)
    global_ep = "https://s3.wasabisys.com"
    client = session.client(
        "s3",
        endpoint_url=global_ep,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=cfg,
    )
    return client

# ---------------------------------------------
# MAIN SEARCH
# ---------------------------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket_name, region, prefix, mandatory_term]):
        st.error("Please fill in all required fields before searching.")
    else:
        st.info("Searching files... please wait ⏳")

        try:
            # ✅ Build S3 client with regional→global fallback
            s3 = make_s3_client(access_key, secret_key, region)

            # List files (single page; your original behavior)
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

                        if match_text(text, mandatory_term, search_mode):
                            # Apply optional filters (non-empty must match)
                            if all((flt in text) if flt else True for flt in [optional_filter1, optional_filter2, optional_filter3]):
                                results.append(key)
                    except Exception as e:
                        st.warning(f"Error reading {key}: {e}")

                if results:
                    st.success(f"✅ Found {len(results)} matching XMLs:")
                    for r in results:
                        st.code(r)
                else:
                    st.warning("No files matched your search criteria.")

        except botocore.exceptions.EndpointConnectionError as e:
            st.error("Could not reach the Wasabi endpoint. If your bucket is in a different region than entered, try the correct region or leave it as-is and the app will fall back automatically.")
        except botocore.exceptions.ClientError as e:
            st.error(f"AWS/Wasabi client error: {e}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")
