import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
import base64, gzip, re, io

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

results = []


def decode_if_needed(uploaded_file):
    """Handle raw XML or Base64+Gzip encoded text files"""
    raw_bytes = uploaded_file.read()

    try:
        # Try plain XML
        text = raw_bytes.decode("utf-8", errors="ignore").strip()
        if text.startswith("<?xml"):
            return io.StringIO(text)

        # Remove wrapper lines (### Start...End ###)
        cleaned = re.sub(r"^#+.*?Start.*?#+\s*", "", text, flags=re.DOTALL)
        cleaned = re.sub(r"#+.*?End.*?#+$", "", cleaned, flags=re.DOTALL).strip()

        # Remove escape characters
        cleaned = cleaned.replace('\\"', '"').replace("\\n", "").replace("\\", "").strip()

        # Base64 decode + decompress
        decoded = base64.b64decode(cleaned)
        decompressed = gzip.decompress(decoded).decode("utf-8", errors="ignore")

        # Keep only valid XML (cut everything before first <?xml)
        start = decompressed.find("<?xml")
        if start != -1:
            decompressed = decompressed[start:]

        # Validate
        if not decompressed.startswith("<?xml"):
            raise ValueError("Decoded content is not valid XML")

        return io.StringIO(decompressed)

    except Exception as e:
        st.error(f"⚠️ Could not decode {uploaded_file.name}: {e}")
        return None


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
            file_obj = decode_if_needed(uploaded_file)
            if not file_obj:
                continue

            try:
                tree = ET.parse(file_obj)
                root = tree.getroot()

                for allotment in root.findall(".//{*}Allotment"):
                    if matches(allotment, date_from, room_code, total_available):
                        date_elem = allotment.find(".//{*}Date")
                        room_elem = allotment.find(".//{*}RoomType")

                        results.append({
                            "File": uploaded_file.name,
                            "RoomType": room_elem.attrib.get("Code") if room_elem is not None else "",
                            "From": date_elem.attrib.get("From") if date_elem is not None else "",
                            "To": date_elem.attrib.get("To") if date_elem is not None else "",
                            "TotalAvailable": allotment.attrib.get("TotalAvailable")
                        })
            except Exception as e:
                st.error(f"Error parsing {uploaded_file.name}: {e}")

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
