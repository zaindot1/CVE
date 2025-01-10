import requests
import csv
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['security_database']  # Existing database name
collection = db['cve_records_nvd']  # Collection to store fetched CVE data

# Insider-related keywords (First pass)
insider_keywords = [
    "insider threat",
    "malicious insider",
    "internal fraud",
    "insider misuse",
    "privilege escalation",
    "employee fraud",
    "insider attack",
    "internal attack",
    "insider access",
    "unauthorized access",
    "internal user"
]

# Financial-related keywords (Second pass)
financial_keywords = [
    "banking",
    "payment gateway",
    "SWIFT transaction",
    "credit card fraud",
    "financial institution",
    "ATM fraud",
    "currency manipulation",
    "payment system",
    "financial transaction",
    "bank fraud",
    "money laundering",
    "payment fraud",
    "transaction fraud"
]


# Function to fetch CVEs from NVD API based on keyword
def fetch_cves_from_nvd(keyword):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data from NVD API for keyword: {keyword}. Status code: {response.status_code}")
        return None


# Function to store full CVE data structure into MongoDB
def store_cves_in_db(cve_data):
    if not cve_data:
        print("No data to store.")
        return

    # Extract the relevant CVE data from the response
    cve_items = cve_data.get("vulnerabilities", [])

    for item in cve_items:
        cve_id = item.get("cve", {}).get("id", "Unknown ID")

        # Insert the full CVE JSON structure into MongoDB
        collection.update_one(
            {"CVE_ID": cve_id},  # Match by CVE_ID to avoid duplicates
            {
                "$set": item  # Store the entire CVE item (full structure)
            },
            upsert=True  # Insert if it doesn't exist
        )
        print(f"Stored full CVE structure: {cve_id}")


# Function to write CVE data to CSV files
def write_to_csv(cve_data, csv_writer):
    if not cve_data:
        print("No data to write.")
        return

    # Extract the relevant CVE data from the response
    cve_items = cve_data.get("vulnerabilities", [])

    for item in cve_items:
        cve_id = item.get("cve", {}).get("id", "Unknown ID")
        description = item.get("cve", {}).get("descriptions", [{}])[0].get("value", "No description available")

        # Write to CSV
        csv_writer.writerow([cve_id, description])


# Main function to run the process for both insider and financial keywords
def main():
    # Create CSV files
    with open('insider_results.csv', mode='w', newline='', encoding='utf-8') as insider_file, \
            open('financial_results.csv', mode='w', newline='', encoding='utf-8') as financial_file:

        # Define CSV writers
        insider_writer = csv.writer(insider_file)
        financial_writer = csv.writer(financial_file)

        # Write headers to both CSV files
        insider_writer.writerow(['CVE ID', 'Description'])
        financial_writer.writerow(['CVE ID', 'Description'])

        # Loop through insider-related keywords
        for keyword in insider_keywords:
            print(f"Fetching data for insider keyword: {keyword}")

            # Fetch CVEs from NVD API
            cve_data = fetch_cves_from_nvd(keyword)

            # Write the fetched CVEs to the insider CSV
            write_to_csv(cve_data, insider_writer)

            # Store the fetched CVEs (with full JSON structure) in MongoDB
            store_cves_in_db(cve_data)

        # Loop through financial-related keywords
        for keyword in financial_keywords:
            print(f"Fetching data for financial keyword: {keyword}")

            # Fetch CVEs from NVD API
            cve_data = fetch_cves_from_nvd(keyword)

            # Write the fetched CVEs to the financial CSV
            write_to_csv(cve_data, financial_writer)

            # Store the fetched CVEs (with full JSON structure) in MongoDB
            store_cves_in_db(cve_data)


if __name__ == "__main__":
    main()
