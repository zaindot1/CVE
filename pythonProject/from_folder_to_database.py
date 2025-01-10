import os
import json
from pymongo import MongoClient

# Base directory where your CVE JSON files are stored
base_directory = "/Users/laeeqagaffar/Downloads/cvelistV5-main/cves"

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if using a different MongoDB URI
db = client['security_database']  # Your desired database name
collection = db['cve_records_all']  # Your desired collection name

# Function to store the complete JSON object from a CVE file into MongoDB
def store_cve_json(file_path):
    try:
        with open(file_path, 'r') as json_file:
            cve_data = json.load(json_file)

            # Insert the entire JSON object into MongoDB as-is
            collection.insert_one(cve_data)
            print(f"Inserted CVE ID: {cve_data.get('cveMetadata', {}).get('cveId', 'Unknown CVE ID')} into MongoDB.")

    except json.JSONDecodeError:
        print(f"Error decoding JSON from file: {file_path}")
    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")

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
                        store_cve_json(file_path)
