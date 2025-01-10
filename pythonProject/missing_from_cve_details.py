import time
import pandas as pd
import requests
from pymongo import MongoClient

# MongoDB connection setup
mongo_client = MongoClient("mongodb://localhost:27017/")  # Replace with your MongoDB URI
db = mongo_client['combined_cve_database']  # Replace with your database name
collection = db['cve_details_missing']  # Replace with your collection name

# CVE Details API configuration
api_url = "https://www.cvedetails.com/api/v1/vulnerability/cve-json"
headers = {
    "Authorization": "Bearer 257ef0ac2bfb4ed7de50ac9dc5b00d8f890e4456.eyJzdWIiOjcyMzcsImlhdCI6MTcyODUwMDY3OCwiZXhwIjoxNzM1NjAzMjAwLCJraWQiOjEsImMiOiJ3b2pUVFJqanEwZ2NVRnQ3Qm5tMVpWWnAxV2VCUWxjTDdKRW5jeUhsRVwvOU9ocTdLSHJWTFwvZDd3ZGZGaXF5SGlvMnFPWG14VCJ9"
}

# Load the CVE IDs from the Excel file
xlsx_path = '/Users/laeeqagaffar/Downloads/Remaining Data.xlsx'  # Replace with your Excel file path
cve_data = pd.read_excel(xlsx_path)

# Ensure the 'cve_id' column is properly formatted
cve_ids = cve_data['cve_id'].dropna().unique()

# Function to fetch CVE data from the API
def fetch_cve_data(cve_id):
    try:
        response = requests.get(f"{api_url}?cveId={cve_id}", headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()  # Parse the response as JSON
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {cve_id}: {e}")
        return None

# Fetch each CVE ID's data from the API and save it to MongoDB
for cve_id in cve_ids:
    cve_data = fetch_cve_data(cve_id)

    if cve_data:
        # Insert the API response into the MongoDB collection
        collection.insert_one(cve_data)
        print(f"Inserted data for {cve_id} into MongoDB.")
    else:
        print(f"No data found for {cve_id} or failed to fetch.")

    # Wait for 1 second before the next request to avoid rate limiting
    time.sleep(3)

# Close MongoDB connection
mongo_client.close()

print("Data transfer complete.")
