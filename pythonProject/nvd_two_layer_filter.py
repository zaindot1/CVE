import requests
import csv
import re
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['cve_database']  # Existing database name
collection = db['cve_records_nvd_2_layer']  # Collection to store fetched CVE data

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

# Financial-related keywords (Second pass, filtering from insider matches)
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

# Compile financial keywords into a regex pattern for filtering
financial_pattern = re.compile("|".join(financial_keywords), re.IGNORECASE)


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


# Function to filter CVEs for financial-related keywords
def filter_financial_from_insider(cve_data):
    filtered_cves = []

    if not cve_data:
        print("No data to filter.")
        return filtered_cves

    # Extract the relevant CVE data from the response
    cve_items = cve_data.get("vulnerabilities", [])

    for item in cve_items:
        # Check if the description or other fields contain financial-related keywords
        description = item.get("cve", {}).get("descriptions", [{}])[0].get("value", "")

        if financial_pattern.search(description):
            filtered_cves.append(item)

    return filtered_cves


# Main function to run the process for insider keywords and filter financials
def main():
    # Create CSV files
    with open('insider_results_nvd.csv', mode='w', newline='', encoding='utf-8') as insider_file, \
            open('financial_filtered_results_nvd.csv', mode='w', newline='', encoding='utf-8') as financial_file:

        # Define CSV writers
        insider_writer = csv.writer(insider_file)
        financial_writer = csv.writer(financial_file)

        # Write headers to both CSV files
        insider_writer.writerow(['CVE ID', 'Description'])
        financial_writer.writerow(['CVE ID', 'Description'])

        all_insider_data = []

        # Loop through insider-related keywords
        for keyword in insider_keywords:
            print(f"Fetching data for insider keyword: {keyword}")

            # Fetch CVEs from NVD API
            cve_data = fetch_cves_from_nvd(keyword)

            if cve_data:
                # Collect all insider CVEs to filter them later
                all_insider_data.extend(cve_data.get("vulnerabilities", []))

                # Write the fetched insider CVEs to the insider CSV
                write_to_csv(cve_data, insider_writer)

                # Store the fetched insider CVEs (with full JSON structure) in MongoDB
                store_cves_in_db(cve_data)

        # Filter insider results for financial-related keywords
        print("Filtering financial-related CVEs from insider matches...")
        filtered_cves = filter_financial_from_insider({"vulnerabilities": all_insider_data})

        # Write filtered financial-related CVEs to the financial CSV
        if filtered_cves:
            write_to_csv({"vulnerabilities": filtered_cves}, financial_writer)

            # Store the filtered financial CVEs (with full JSON structure) in MongoDB
            store_cves_in_db({"vulnerabilities": filtered_cves})


if __name__ == "__main__":
    main()
