import pandas as pd
from pymongo import MongoClient

# MongoDB connection setup
source_client = MongoClient("mongodb://localhost:27017/") # Replace with your source MongoDB URI
destination_client = MongoClient("mongodb://localhost:27017/") # Replace with your destination MongoDB URI

# Define source and destination collections
source_db = source_client['combined_cve_database']  # Replace with your source database name
source_collection = source_db['cve_api_results_after_2010']  # Replace with your source collection name
destination_db = destination_client['combined_cve_database']  # Replace with your destination database name
destination_collection = destination_db['all_missing_database']  # Replace with your destination collection name


# Load the CVE IDs from the Excel file
xlsx_path = '/Users/laeeqagaffar/Downloads/Remaining Data.xlsx'  # Replace with the path to your Excel file
cve_data = pd.read_excel(xlsx_path)

# Ensure the 'cve_id' column is properly formatted
cve_ids = cve_data['cve_id'].dropna().unique()


# Function to extract relevant information
def extract_relevant_info(document):
    cve_id = document.get("cve_id")
    api_response = document.get("api_response", {})
    vulnerabilities = api_response.get("vulnerabilities", [])

    extracted_data = {
        "cve_id": cve_id,
        "description": None,
        "affected_systems": []
    }

    # Extract description (in English)
    for vuln in vulnerabilities:
        descriptions = vuln.get("cve", {}).get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                extracted_data["description"] = desc.get("value")
                break

    # Extract affected systems
    for vuln in vulnerabilities:
        configurations = vuln.get("cve", {}).get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    if match.get("vulnerable", False):
                        extracted_data["affected_systems"].append(match.get("criteria"))

    return extracted_data


# Fetch records from source collection, extract details, and save to destination collection
for cve_id in cve_ids:
    document = source_collection.find_one({"cve_id": cve_id})

    if document:
        # Extract only the relevant information
        relevant_info = extract_relevant_info(document)

        # Insert extracted info into the destination collection
        destination_collection.insert_one(relevant_info)
        print(f"Inserted {cve_id} details into the destination database.")
    else:
        print(f"No data found for {cve_id}.")

# Close MongoDB connections
source_client.close()
destination_client.close()

print("Data transfer complete.")
