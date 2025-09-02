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
            return extracted

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
    if not uploaded_files:
        st.warning("Please upload at least one file.")
    elif not (date_from or room_code or total_available):
        st.warning("Please provide at least one search parameter.")
    else:
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
                    st.error(f"Error parsing {uploaded_file.name} (part {idx+1}): {e}")

        # Show previews + downloads
        if preview_data:
            st.subheader("📄 Preview of Decoded XML")
            for fname, previews in preview_data.items():
                for i, preview in enumerate(previews):
                    st.text_area(f"Preview from {fname} (part {i+1})", preview, height=200)
                    if fname in full_xml_data and i < len(full_xml_data[fname]):
                        st.download_button(
                            f"Download full XML from {fname} (part {i+1})",
                            full_xml_data[fname][i].encode("utf-8"),
                            file_name=f"{fname}_part{i+1}.xml",
                            mime="application/xml"
                        )

        # Show results
        if results:
            df = pd.DataFrame(results)
            st.success("✅ Matching records found!")
            st.dataframe(df)

            # CSV download
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", csv, "results.csv", "text/csv")

            # Excel download
            excel_bytes = io.BytesIO()
            df.to_excel(excel_bytes, index=False, engine="openpyxl")
            st.download_button("Download Excel", excel_bytes.getvalue(), "results.xlsx", "application/vnd.ms-excel")
        else:
            st.warning("❌ No matches found.")
