import streamlit as st
import boto3
import botocore
import re
import html

# ----------------------------
# Page
# ----------------------------
st.set_page_config(page_title="XML Search Tool", layout="wide")
st.title("🧩 XML Search Tool")
st.caption("Search Wasabi XML files with robust decode, deep unescape, and filters.")

# ----------------------------
# Sidebar – Wasabi creds
# ----------------------------
st.sidebar.header("🔐 Wasabi Credentials")
access_key = st.sidebar.text_input("Access Key", type="password")
secret_key = st.sidebar.text_input("Secret Key", type="password")
region     = st.sidebar.text_input("Region", value="ap-south-1")
bucket     = st.sidebar.text_input("Bucket Name")

# ----------------------------
# Search inputs
# ----------------------------
st.subheader("📂 Prefix Scan & Search")
prefix = st.text_input("Prefix to scan (folder; trailing '/' optional)", "")

mandatory = st.text_input("🔹 Mandatory term (required)")
opt1 = st.text_input("Optional filter 1 (content only)", "")
opt2 = st.text_input("Optional filter 2 (content only)", "")
opt3 = st.text_input("Optional filter 3 (content only)", "")

mode = st.selectbox("Search mode", ["Literal text", "Regex pattern"])
case_sensitive = st.checkbox("Case sensitive search", value=False)

# ----------------------------
# Helpers
# ----------------------------
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

def list_all_objects_paginated(s3, bucket: str, prefix: str):
    """Yield all objects under prefix (handles >1000 keys)."""
    kwargs = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
    while True:
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            yield obj
        if resp.get("IsTruncated"):
            kwargs["ContinuationToken"] = resp.get("NextContinuationToken")
        else:
            break

def content_matches(text: str, term: str, mode: str, case_sensitive: bool) -> bool:
    if not term:
        return False
    if not case_sensitive:
        text_cmp = text.lower()
        term_cmp = term.lower()
    else:
        text_cmp = text
        term_cmp = term

    if mode == "Literal text":
        return term_cmp in text_cmp
    try:
        flags = re.DOTALL if case_sensitive else (re.IGNORECASE | re.DOTALL)
        return re.search(term, text, flags=flags) is not None
    except re.error:
        return False

# ----------------------------
# Search
# ----------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket, region, prefix, mandatory]):
        st.error("Please fill in Access Key, Secret Key, Region, Bucket, Prefix and Mandatory term.")
    else:
        st.info("Searching files... please wait ⏳")

        try:
            s3 = boto3.client(
                "s3",
                endpoint_url=f"https://s3.{region}.wasabisys.com",  # unchanged behavior
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            total_scanned = 0
            results = []

            # iterate all keys under prefix (with pagination)
            for obj in list_all_objects_paginated(s3, bucket, prefix):
                key = obj["Key"]
                total_scanned += 1
                try:
                    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                    text = deep_unescape(decode_content(body))

                    # mandatory must match content
                    if not content_matches(text, mandatory, mode, case_sensitive):
                        continue

                    # non-empty optional filters must also be present in content (literal, same case policy)
                    passed = True
                    for extra in (opt1, opt2, opt3):
                        if extra:
                            if case_sensitive:
                                if extra not in text:
                                    passed = False
                                    break
                            else:
                                if extra.lower() not in text.lower():
                                    passed = False
                                    break

                    if passed:
                        results.append(key)

                except Exception as e:
                    st.warning(f"Error reading {key}: {e}")

            if results:
                st.success(f"✅ Found {len(results)} matching XMLs (scanned {total_scanned}).")
                for r in results[:300]:
                    st.code(r)
                if len(results) > 300:
                    st.info(f"...and {len(results)-300} more keys not shown here.")
            else:
                st.warning("No files matched your search criteria.")

        except botocore.exceptions.EndpointConnectionError:
            st.error("Could not reach the Wasabi endpoint. Please verify the Region and network access.")
        except botocore.exceptions.ClientError as e:
            st.error(f"Wasabi/AWS client error: {e}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")
