import requests
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['combined_cve_database']  # Your existing database name
cve_collection = db['all_cve_records']  # Collection with all CVE records
result_collection = db['cve_api_results']  # New collection to store API results

# NVD API base URL
nvd_api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="

# Function to fetch CVE details from NVD API
def fetch_cve_details(cve_id):
    url = f"{nvd_api_base_url}{cve_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: API request failed for {cve_id} with status code {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error: Exception occurred while fetching {cve_id}: {e}")
        return None

# Function to process CVE IDs and store results
def process_cve_ids():
    # Get all CVE IDs from the 'all_cve_records' collection
    cve_ids = cve_collection.distinct("cve.id")  # Adjust the path if CVE ID is stored differently
    print(f"Found {len(cve_ids)} CVE IDs in the collection.")

    for cve_id in cve_ids:
        print(f"Fetching details for {cve_id}...")
        cve_details = fetch_cve_details(cve_id)

        if cve_details:
            # Save the result in the new collection
            result_collection.insert_one({
                "cve_id": cve_id,
                "api_response": cve_details
            })
            print(f"Stored results for {cve_id}.")
        else:
            print(f"No details found for {cve_id}.")

# Execute the process
if __name__ == "__main__":
    process_cve_ids()

print("Process complete.")
