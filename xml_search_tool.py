import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
import base64, gzip, re, io, json

st.title("🔍 XML Allotment Search Tool")

# Upload files (XML or encoded TXT)
uploaded_files = st.file_uploader(
    "Upload your XML or Encoded TXT files",
    type=["xml", "txt"],
    accept_multiple_files=True
)

# Search parameters (all optional)
st.sidebar.header("Search Parameters")
date_from = st.sidebar.text_input("Date From (e.g. 2026-07-06)", "")
room_code = st.sidebar.text_input("RoomType Code (e.g. 216)", "")
total_available = st.sidebar.text_input("TotalAvailable (e.g. 23)", "")

# Extra option: when file contains JSON with embedded XML
payload_choice = st.sidebar.radio(
    "If JSON with XML inside:",
    options=["Auto", "RqPayload", "RsPayload", "Both"],
    index=0
)

results = []
preview_data = {}   # store preview text
full_xml_data = {}  # store full decoded XML


def decode_if_needed(uploaded_file):
    """Handle raw XML, JSON-with-XML, or Base64+Gzip encoded text files"""
    raw_bytes = uploaded_file.read()

    try:
        # Try plain XML first
        text = raw_bytes.decode("utf-8", errors="ignore").strip()
        if text.startswith("<?xml"):
            full_xml_data[uploaded_file.name] = [text]
            preview_data[uploaded_file.name] = [text[:2000]]
            return [io.StringIO(text)]

        # Remove wrapper lines (### Start/End ###)
        cleaned = re.sub(r"^#+.*?Start.*?#+\s*", "", text, flags=re.DOTALL)
        cleaned = re.sub(r"#+.*?End.*?#+$", "", cleaned, flags=re.DOTALL).strip()
        cleaned = cleaned.replace('\\"', '"').replace("\\n", "").replace("\\", "").strip()

        # Base64 decode + decompress
        decoded = base64.b64decode(cleaned)
        decompressed = gzip.decompress(decoded).decode("utf-8", errors="ignore").strip()

        # ✅ Case 1: Direct XML inside
        if decompressed.startswith("<?xml"):
            full_xml_data[uploaded_file.name] = [decompressed]
            preview_data[uploaded_file.name] = [decompressed[:2000]]
            return [io.StringIO(decompressed)]

        # ✅ Case 2: Try parsing as JSON (more tolerant)
        try:
            payload = json.loads(decompressed)
        except Exception:
            raise ValueError("Decoded content is neither XML nor JSON-with-XML")

        extracted_xmls, previews, fulls = [], [], []

        if payload_choice == "RqPayload":
            xml_candidate = payload.get("RqPayload")
            if xml_candidate:
                xml_candidate = xml_candidate.replace('\\"', '"').replace("\\n", "\n").strip()
                extracted_xmls.append(io.StringIO(xml_candidate))
                fulls.append(xml_candidate)
                previews.append(xml_candidate[:2000])

        elif payload_choice == "RsPayload":
            xml_candidate = payload.get("RsPayload")
            if xml_candidate:
                xml_candidate = xml_candidate.replace('\\"', '"').replace("\\n", "\n").strip()
                extracted_xmls.append(io.StringIO(xml_candidate))
                fulls.append(xml_candidate)
                previews.append(xml_candidate[:2000])

        elif payload_choice == "Both":
            for key in ["RqPayload", "RsPayload"]:
                xml_candidate = payload.get(key)
                if xml_candidate:
                    xml_candidate = xml_candidate.replace('\\"', '"').replace("\\n", "\n").strip()
                    extracted_xmls.append(io.StringIO(xml_candidate))
                    fulls.append(xml_candidate)
                    previews.append(xml_candidate[:2000])

        else:  # Auto
            xml_candidate = payload.get("RqPayload") or payload.get("RsPayload")
            if xml_candidate:
                xml_candidate = xml_candidate.replace('\\"', '"').replace("\\n", "\n").strip()
                extracted_xmls.append(io.StringIO(xml_candidate))
                fulls.append(xml_candidate)
                previews.append(xml_candidate[:2000])

        if extracted_xmls:
            full_xml_data[uploaded_file.name] = fulls
            preview_data[uploaded_file.name] = previews
            return extracted_xmls

        raise ValueError("JSON did not contain valid RqPayload or RsPayload")

    except Exception as e:
        st.error(f"⚠️ Could not decode {uploaded_file.name}: {e}")
        return []


def matches(allotment, date_from, room_code, total_available):
    """Flexible matching: only check fields provided by user"""
    total = allotment.attrib.get("TotalAvailable")
    date_elem = allotment.find(".//{*}Date")  # namespace-safe
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
            if not file_objs:
                continue

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

        # Show previews and downloads
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

        if results:
            df = pd.DataFrame(results)
            st.success("✅ Matching records found!")
            st.dataframe(df)

            # Download as CSV
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", csv, "results.csv", "text/csv")

            # Download as Excel
            excel_bytes = io.BytesIO()
            df.to_excel(excel_bytes, index=False, engine="openpyxl")
            st.download_button("Download Excel", excel_bytes.getvalue(), "results.xlsx", "application/vnd.ms-excel")
        else:
            st.warning("❌ No matches found.")
