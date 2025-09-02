import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
import base64, gzip, re, io, json

st.title("🔍 XML Allotment Search Tool (Debug Mode)")

uploaded_files = st.file_uploader(
    "Upload your XML or Encoded TXT files",
    type=["xml", "txt"],
    accept_multiple_files=True
)

st.sidebar.header("Search Parameters")
date_from = st.sidebar.text_input("Date From (e.g. 2026-07-06)", "")
room_code = st.sidebar.text_input("RoomType Code (e.g. 216)", "")
total_available = st.sidebar.text_input("TotalAvailable (e.g. 23)", "")

payload_choice = st.sidebar.radio(
    "If JSON with XML inside:",
    options=["Auto", "RqPayload", "RsPayload", "Both"],
    index=0
)

results = []
preview_data, full_xml_data = {}, {}

def decode_if_needed(uploaded_file):
    """Decode XML or Base64+Gzip that may contain XML or JSON-with-XML"""
    raw_bytes = uploaded_file.read()
    try:
        text = raw_bytes.decode("utf-8", errors="ignore").strip()
        if text.startswith("<?xml"):
            st.info(f"✅ {uploaded_file.name}: detected plain XML")
            return [io.StringIO(text)]

        # Base64 decode + Gzip decompress
        decoded = base64.b64decode(text)
        decompressed = gzip.decompress(decoded).decode("utf-8", errors="ignore").strip()

        # 🔎 Debug: Show raw decompressed content
        st.subheader(f"🔎 Raw decompressed preview from {uploaded_file.name}")
        st.text_area(f"First 500 chars from {uploaded_file.name}", decompressed[:500], height=150)

        # Case 1: XML
        if decompressed.startswith("<?xml"):
            return [io.StringIO(decompressed)]

        # Case 2: JSON
        try:
            payload = json.loads(decompressed)
            st.success(f"✅ {uploaded_file.name}: detected JSON")

            extracted_xmls = []
            keys = []
            if payload_choice == "RqPayload":
                keys = ["RqPayload"]
            elif payload_choice == "RsPayload":
                keys = ["RsPayload"]
            elif payload_choice == "Both":
                keys = ["RqPayload", "RsPayload"]
            else:  # Auto
                keys = ["RqPayload", "RsPayload"]

            for key in keys:
                if key in payload:
                    xml_candidate = payload[key].replace('\\"', '"').replace("\\n", "\n").strip()
                    extracted_xmls.append(io.StringIO(xml_candidate))
                    st.text_area(f"Preview of {key} from {uploaded_file.name}", xml_candidate[:500], height=150)

            return extracted_xmls if extracted_xmls else []

        except Exception:
            st.error(f"⚠️ {uploaded_file.name}: not valid JSON")

        return []

    except Exception as e:
        st.error(f"⚠️ Could not decode {uploaded_file.name}: {e}")
        return []

def matches(allotment, date_from, room_code, total_available):
    total = allotment.attrib.get("TotalAvailable")
    date_elem = allotment.find(".//{*}Date")
    room_elem = allotment.find(".//{*}RoomType")

    if date_from and (not date_elem or date_from not in date_elem.attrib.get("From", "")):
        return False
    if room_code and (not room_elem or room_elem.attrib.get("Code") != room_code):
        return False
    if total_available and (total != total_available):
        return False
    return True

if st.button("Search"):
    for uploaded_file in uploaded_files:
        file_objs = decode_if_needed(uploaded_file)
        for idx, file_obj in enumerate(file_objs):
            try:
                tree = ET.parse(file_obj)
                root = tree.getroot()
                for allotment in root.findall(".//{*}Allotment"):
                    if matches(allotment, date_from, room_code, total_available):
                        date_elem = allotment.find(".//{*}Date")
                        room_elem = allotment.find(".//{*}RoomType")
                        results.append({
                            "File": f"{uploaded_file.name} (part {idx+1})",
                            "RoomType": room_elem.attrib.get("Code") if room_elem is not None else "",
                            "From": date_elem.attrib.get("From") if date_elem is not None else "",
                            "To": date_elem.attrib.get("To") if date_elem is not None else "",
                            "TotalAvailable": allotment.attrib.get("TotalAvailable")
                        })
            except Exception as e:
                st.error(f"Error parsing {uploaded_file.name}: {e}")

    if results:
        df = pd.DataFrame(results)
        st.dataframe(df)
