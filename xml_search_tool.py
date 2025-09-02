import streamlit as st
import xml.etree.ElementTree as ET
import pandas as pd
import base64, gzip, re, io, json
from xml.dom import minidom

st.title("🔍 XML Allotment & InventoryItem Search Tool")

uploaded_files = st.file_uploader(
    "Upload your XML or Encoded TXT files",
    type=["xml", "txt"],
    accept_multiple_files=True
)

st.sidebar.header("Search Parameters")
date_from = st.sidebar.text_input("Date From (e.g. 2025-10-07)", "")
room_code = st.sidebar.text_input("RoomType/Room Code (e.g. 216)", "")
total_available = st.sidebar.text_input("TotalAvailable (e.g. 23)", "")

payload_choice = st.sidebar.radio(
    "If JSON with XML inside:",
    options=["Auto", "RqPayload", "RsPayload", "Both"],
    index=0
)

results, preview_data, full_xml_data, xml_matches = [], {}, {}, []


def decode_if_needed(uploaded_file):
    """Decode XML, JSON-with-XML, or JSON-like-with-single-quotes inside Base64+Gzip files"""
    raw_bytes = uploaded_file.read()

    # Case 1: plain XML
    try:
        text = raw_bytes.decode("utf-8-sig", errors="ignore").strip()
        if text.startswith("<?xml"):
            full_xml_data[uploaded_file.name] = [text]
            preview_data[uploaded_file.name] = [text[:2000]]
            return [io.StringIO(text)]
    except Exception:
        pass

    # Case 2: Base64 + Gzip
    try:
        decoded = base64.b64decode(raw_bytes)
        decompressed = gzip.decompress(decoded).decode("utf-8-sig", errors="ignore").strip()

        # XML directly?
        if decompressed.startswith("<?xml"):
            full_xml_data[uploaded_file.name] = [decompressed]
            preview_data[uploaded_file.name] = [decompressed[:2000]]
            return [io.StringIO(decompressed)]

        # Try JSON
        try:
            payload = json.loads(decompressed)
        except Exception:
            fixed = re.sub(r"([{,])\s*'([^']+)'\s*:", r'\1"\2":', decompressed)
            fixed = re.sub(r":\s*'([^']*)'", r':"\1"', fixed)
            payload = json.loads(fixed)

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

        if extracted:
            full_xml_data[uploaded_file.name] = fulls
            preview_data[uploaded_file.name] = previews
            return extracted

    except Exception as e:
        st.error(f"⚠️ Could not decode {uploaded_file.name}: {e}")

    return []


def matches_allotment(allotment, date_from, room_code, total_available):
    """Check match for Allotment structure"""
    total = allotment.attrib.get("TotalAvailable")

    # Date check
    if date_from:
        found_match = False
        for date_elem in allotment.findall(".//{*}Date") + allotment.findall(".//{*}date"):
            date_attr = date_elem.attrib.get("From") or date_elem.attrib.get("value") or ""
            if date_attr == date_from:
                found_match = True
                break
        if not found_match:
            return False

    # Room code check
    if room_code:
        room_elem = allotment.find(".//{*}RoomType") or allotment.find(".//{*}room")
        room_attr = room_elem.attrib.get("Code") if room_elem is not None else room_elem.attrib.get("id") if room_elem is not None else ""
        if room_attr != room_code:
            return False

    # TotalAvailable check
    if total_available and total != total_available:
        return False

    return True


def matches_inventory(item, date_from, room_code):
    """Check match for InventoryItem structure"""
    # Date check
    if date_from:
        df = item.find(".//{*}DateFrom")
        dt = item.find(".//{*}DateTo")
        df_val = df.attrib.get("date") if df is not None else ""
        dt_val = dt.attrib.get("date") if dt is not None else ""
        if df_val != date_from and dt_val != date_from:
            return False

    # Room code check
    if room_code:
        room_elem = item.find(".//{*}Room")
        room_val = room_elem.text.strip() if room_elem is not None else ""
        if room_val != room_code:
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

                    # --- Case 1: Allotments ---
                    for allotment in root.findall(".//{*}Allotment"):
                        if matches_allotment(allotment, date_from, room_code, total_available):
                            results.append({
                                "File": f"{uploaded_file.name} (part {idx+1})",
                                "Type": "Allotment",
                                "Date": date_from,
                                "Room": room_code,
                                "TotalAvailable": allotment.attrib.get("TotalAvailable", "")
                            })
                            xml_matches.append(allotment)

                    # --- Case 2: InventoryItems ---
                    for item in root.findall(".//{*}InventoryItem"):
                        if matches_inventory(item, date_from, room_code):
                            df = item.find(".//{*}DateFrom")
                            dt = item.find(".//{*}DateTo")
                            room_elem = item.find(".//{*}Room")
                            results.append({
                                "File": f"{uploaded_file.name} (part {idx+1})",
                                "Type": "InventoryItem",
                                "DateFrom": df.attrib.get("date") if df is not None else "",
                                "DateTo": dt.attrib.get("date") if dt is not None else "",
                                "Room": room_elem.text if room_elem is not None else ""
                            })
                            xml_matches.append(item)

                except Exception as e:
                    st.error(f"Error parsing {uploaded_file.name} (part {idx+1}): {e}")

        # Results
        if results:
            df = pd.DataFrame(results)
            st.success("✅ Matching records found!")
            st.dataframe(df)

            # XML Export
            if xml_matches:
                xml_root = ET.Element("Results")
                for match in xml_matches:
                    xml_root.append(match)

                rough_string = ET.tostring(xml_root, encoding="utf-8")
                reparsed = minidom.parseString(rough_string)
                pretty_xml = reparsed.toprettyxml(indent="  ")

                st.download_button(
                    "⬇️ Download Matching XML",
                    pretty_xml.encode("utf-8"),
                    "results.xml",
                    "application/xml"
                )
        else:
            st.warning("❌ No matches found.")
