import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
import base64, gzip, re, io, json

st.title("🔍 XML Allotment Search Tool")

# Upload files
uploaded_files = st.file_uploader(
    "Upload your XML or Encoded TXT files",
    type=["xml", "txt"],
    accept_multiple_files=True
)

# Search parameters
st.sidebar.header("Search Parameters")
date_from = st.sidebar.text_input("Date From (e.g. 2026-07-06)", "")
room_code = st.sidebar.text_input("RoomType Code (e.g. 216)", "")
total_available = st.sidebar.text_input("TotalAvailable (e.g. 23)", "")

# Choice for JSON payloads
payload_choice = st.sidebar.radio(
    "If JSON with XML inside:",
    options=["Auto", "RqPayload", "RsPayload", "Both"],
    index=0
)

results = []
preview_data = {}
full_xml_data = {}


def decode_if_needed(uploaded_file):
    """Decode XML, JSON-with-XML, or JSON-like-with-single-quotes inside Base64+Gzip files"""
    raw_bytes = uploaded_file.read()
    try:
        # Plain XML
        text = raw_bytes.decode("utf-8", errors="ignore").strip()
        if text.startswith("<?xml"):
            full_xml_data[uploaded_file.name] = [text]
            preview_data[uploaded_file.name] = [text[:2000]]
            return [io.StringIO(text)]

        # Base64 decode + decompress (with BOM-safe decoding)
        decoded = base64.b64decode(text)
        decompressed = gzip.decompress(decoded).decode("utf-8-sig", errors="ignore").strip()

        # Debug preview
        st.subheader(f"🔎 Raw decompressed preview from {uploaded_file.name}")
        st.text_area(f"First 500 chars from {uploaded_file.name}", decompressed[:500], height=150)

        # Case 1: Direct XML
        if decompressed.startswith("<?xml"):
            full_xml_data[uploaded_file.name] = [decompressed]
            preview_data[uploaded_file.name] = [decompressed[:2000]]
            return [io.StringIO(decompressed)]

        # Case 2: Try strict JSON
        try:
            payload = json.loads(decompressed)
        except Exception:
            # Case 3: Fix JSON-like (single quotes → double quotes)
            fixed = decompressed
            fixed = re.sub(r"([{,])\s*'([^']+)'\s*:", r'\1"\2":', fixed)   # keys
            fixed = re.sub(r":\s*'([^']*)'", r':"\1"', fixed)              # string values
            payload = json.loads(fixed)

        st.success(f"✅ {uploaded_file.name}: decoded as JSON/JSON-like")

        extracted, previews, fulls = [], [], []
        keys = []
        if payload_choice == "RqPayload":
            keys = ["RqPayload"]
        elif payload_choice == "RsPayload":
            keys = ["RsPayload"]
        elif payload_choice == "Both":
            keys = ["RqPayload", "RsPayload"]
        else:
            keys = ["RqPayload", "RsPayload"]

        for key in keys:
            if key in payload:
                xml_candidate = payload[key].replace('\\"', '"').replace("\\n", "\n").strip()
                extracted.append(io.StringIO(xml_candidate))
                previews.append(xml_candidate[:2000])
                fulls.append(xml_candidate)
                st.text_area(f"Preview of {key} from {uploaded_file.name}", xml_candidate[:500], height=150)

        if extracted:
            full_xml_data[uploaded_file.name] = fulls
            preview_data[uploaded_file.name] = previews
