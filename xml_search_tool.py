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
region     = st.sidebar.text_input("Region (e.g. ap-south-1)", value="ap-south-1")
bucket     = st.sidebar.text_input("Bucket Name")
custom_ep  = st.sidebar.text_input("Custom Endpoint (optional, e.g. https://s3.wasabisys.com)")

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
    if mode == "Literal text":
        return (term in text) if case_sensitive else (term.lower() in text.lower())
    try:
        flags = re.DOTALL if case_sensitive else (re.IGNORECASE | re.DOTALL)
        return re.search(term, text, flags=flags) is not None
    except re.error:
        return False

def build_client(endpoint_url: str):
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=botocore.config.Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=60),
    )

def make_autodetected_client():
    """
    Try endpoints in this order:
      1) custom endpoint (if provided)
      2) regional endpoint from the 'Region' box
      3) global endpoint
    If the first/second respond with a different bucket region, rebuild a client for that region.
    """
    tried = []

    # 1) custom endpoint
    if custom_ep.strip():
        tried.append(custom_ep.strip())

    # 2) regional endpoint (what you typed)
    tried.append(f"https://s3.{region}.wasabisys.com")

    # 3) global endpoint
    tried.append("https://s3.wasabisys.com")

    last_error = None
    for ep in tried:
        try:
            c = build_client(ep)
            # head the bucket to both check connectivity and get the actual region if different
            c.head_bucket(Bucket=bucket)
            return c  # success on this endpoint
        except botocore.exceptions.ClientError as e:
            # If we get a region hint, use it
            resp = getattr(e, "response", {}) or {}
            hdrs = resp.get("ResponseMetadata", {}).get("HTTPHeaders", {})
            bucket_region = hdrs.get("x-amz-bucket-region")
            if bucket_region:
                # rebuild client pointing to the hinted region
                hinted_ep = f"https://s3.{bucket_region}.wasabisys.com"
                try:
                    c2 = build_client(hinted_ep)
                    c2.head_bucket(Bucket=bucket)
                    return c2
                except Exception as inner:
                    last_error = inner
            else:
                last_error = e
        except botocore.exceptions.EndpointConnectionError as e:
            last_error = e
        except Exception as e:
            last_error = e

    raise last_error if last_error else RuntimeError("Unable to reach any Wasabi endpoint")

# ----------------------------
# Search
# ----------------------------
if st.button("🔍 Start Search"):
    if not all([access_key, secret_key, bucket, prefix, mandatory]):
        st.error("Please fill in Access Key, Secret Key, Bucket, Prefix and Mandatory term.")
    else:
        st.info("Searching files... please wait ⏳")

        try:
            s3 = make_autodetected_client()

            total_scanned = 0
            results = []
            for obj in list_all_objects_paginated(s3, bucket, prefix):
                key = obj["Key"]
                total_scanned += 1
                try:
                    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                    text = deep_unescape(decode_content(body))

                    if not content_matches(text, mandatory, mode, case_sensitive):
                        continue

                    passed = True
                    for extra in (opt1, opt2, opt3):
                        if extra and (extra not in text if case_sensitive else extra.lower() not in text.lower()):
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
            st.error("Could not reach the Wasabi endpoint. Try setting the correct Region or enter the global endpoint in the 'Custom Endpoint' field (https://s3.wasabisys.com).")
        except botocore.exceptions.ClientError as e:
            st.error(f"Wasabi/AWS client error: {e}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")
