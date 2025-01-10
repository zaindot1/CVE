import os
import json
from pymongo import MongoClient

# Base directory where your CVE JSON files are stored
base_directory = "/Users/laeeqagaffar/Downloads/cvelistV5-main/cves"

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Change if you have a different MongoDB URI
db = client['cve_database']  # Replace with your desired database name
collection = db['cve_records_latest']  # Replace with your desired collection name


# Function to extract key information from a CVE JSON file and store it in MongoDB
def extract_and_store_cve_info(file_path):
    with open(file_path, 'r') as json_file:
        cve_data = json.load(json_file)

        # Extract relevant fields
        cve_id = cve_data.get("cveMetadata", {}).get("cveId", "Unknown CVE ID")
        description = cve_data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value",
                                                                                                     "No description available")

        # Extract affected systems (product and vendor info)
        affected_info = cve_data.get("containers", {}).get("cna", {}).get("affected", [])
        affected_systems = []
        for affected in affected_info:
            vendor = affected.get("vendor", "n/a")
            product = affected.get("product", "n/a")
            affected_systems.append(f"Vendor: {vendor}, Product: {product}")

        # Extract severity (if available)
        severity = "No severity information available"  # Placeholder, extend if severity exists

        # Mitigation strategies can be part of the references or descriptions
        mitigation_strategies = "No mitigation strategies available"  # Placeholder

        # Extract source URLs (from references)
        references = cve_data.get("containers", {}).get("cna", {}).get("references", [])
        source_url = references[0].get("url", "No URL available") if references else "No URL available"

        # Prepare the document to insert into MongoDB
        cve_document = {
            "CVE_ID": cve_id,
            "Description": description,
            "Affected_Systems": affected_systems,
            "Severity": severity,
            "Mitigation_Strategies": mitigation_strategies,
            "Source_URL": source_url
        }

        # Insert the document into MongoDB
        collection.insert_one(cve_document)
        print(f"Inserted CVE ID: {cve_id} into MongoDB.")


# Traverse the directory year-wise and process each JSON file
for year_folder in os.listdir(base_directory):
    year_path = os.path.join(base_directory, year_folder)

    # Check if it's a directory (ignore non-directories)
    if os.path.isdir(year_path):
        # Traverse subdirectories inside each year folder
        for subfolder in os.listdir(year_path):
            subfolder_path = os.path.join(year_path, subfolder)

            # Check if it's a directory (ignore non-directories)
            if os.path.isdir(subfolder_path):
                # Process each JSON file in the subfolder
                for file_name in os.listdir(subfolder_path):
                    if file_name.endswith('.json'):
                        file_path = os.path.join(subfolder_path, file_name)
                        print(f"Processing {file_name} in {subfolder_path}")
                        extract_and_store_cve_info(file_path)
