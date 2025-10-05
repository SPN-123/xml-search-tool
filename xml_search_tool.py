import streamlit as st
import boto3
import re
import html

# ---------------------------------------------
# PAGE CONFIG
# ---------------------------------------------
st.set_page_config(page_title="Wasabi XML Finder", layout="wide")
st.title("🕵️ Wasabi XML Finder — robust decode + deep unescape + filters")

st.markdown("""
Search Wasabi XML files with strong decoding and multi-layer unescaping.  
**Mandatory term** matches file **path or content** (like the original you used).  
Optional filters are **content-only**.
""")

# ---------------------------------------------
# SIDEBAR – WASABI CREDENTIALS
# ---------------------------------------------
st.sidebar.header("🔐 Wasabi Credentials")
access_key  = st.sidebar.text_input("Access Key", type="password")
secret_key  = st.sidebar.text_input("Secret Key", type="password")
region      = st.sidebar.text_input("Region", value="ap-south-1")  # informational
bucket_name = st.sidebar.text_input("Bucket Name")

# ---------------------------------------------
# SEARCH FILTERS
# ---------------------------------------------
st.subheader("📂 Prefix Scan & Search")
prefix           = st.text_input("Prefix to scan (folder, trailing '/' optional)", "")
mandatory_term   = st.text_input("🔹 Mandatory term (required)")
optional_filter1 = st.text_input("Optional filter 1 (content only)", "")
optional_filter2 = st.text_input("Optional filter 2 (content only)", "")
optional_filter3 = st.text_input("Optional filter 3 (content only)", "")
search_mode      = st.selectbox("Search mode", ["Literal text", "Regex pattern"])
debug            = st.checkbox("Show debug reasons for non-matches", value=False)

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

def decode_content(raw_data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return raw_data.decode(enc)
        except Exception:
            pass
    return raw_data.decode(errors="ignore")

def match_literal(hay: str, needle: str) -> bool:
    return needle.lower() in hay.lower()

def match_regex(hay: str, pattern: str) -> bool:
    try:
        return re.search(pattern, hay, flags=re.IGNORECASE | re.DOTALL) is not None
    except re.error:
        return False

def match_any(hay_list, term, mode) -> bool:
    if mode == "Literal text":
        return any(match_literal(h, term) for h in hay_list)
    else:
        return any(match_regex(h, term) for h in hay_list)

# ---------------------------------------------
# MAIN SEARCH
# ---------------------------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket_name, prefix, mandatory_term]):
        st.error("Please fill in Access Key, Secret Key, Bucket, Prefix and Mandatory term.")
    else:
        st.info("Searching files... please wait ⏳")
        try:
            # Use global endpoint to avoid regional connectivity issues you saw
            s3 = boto3.client(
                "s3",
                endpoint_url="https://s3.wasabisys.com",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            # NOTE: one page listing like your original; if your prefix has >1000 keys, we can add pagination later
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
            files = response.get("Contents", [])

            if not files:
                st.warning("No files found under the given prefix.")
            else:
                total_scanned = 0
                results = []
                filtered_out = 0

                for obj in files:
                    key = obj["Key"]
                    total_scanned += 1
                    try:
                        body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
                        content = deep_unescape(decode_content(body))

                        # ✅ Mandatory term matches KEY (path/filename) OR CONTENT
                        mand_ok = match_any([key, content], mandatory_term, search_mode)

                        if not mand_ok:
                            filtered_out += 1
                            if debug:
                                st.text(f"[skip] {key} — mandatory term not in key/content")
                            continue

                        # Optional filters: content-only
                        opt_ok = True
                        for extra in (optional_filter1, optional_filter2, optional_filter3):
                            if extra:
                                if not match_literal(content, extra):
                                    opt_ok = False
                                    if debug:
                                        st.text(f"[skip] {key} — optional '{extra}' not in content")
                                    break

                        if opt_ok:
                            results.append(key)

                    except Exception as e:
                        st.warning(f"Error reading {key}: {e}")

                if results:
                    st.success(f"✅ Found {len(results)} matching XML files (scanned {total_scanned}).")
                    for r in results:
                        st.code(r)
                else:
                    st.warning(f"No files matched your criteria (scanned {total_scanned}, skipped {filtered_out}).")

        except Exception as e:
            st.error(f"Connection or listing error: {e}")
