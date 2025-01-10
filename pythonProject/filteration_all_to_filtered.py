import re
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if you're using a different connection string
db = client['security_database']  # Existing database name
source_collection = db['cve_records_all']  # Existing collection with all CVEs
target_collection = db['filtered_cve_records']  # New collection to store matching CVEs


# Define the insider and financial-related keywords
keywords = [
    "insider threat", "malicious insider", "internal fraud", "insider misuse",
    "privilege escalation", "employee fraud", "insider attack", "internal attack",
    "insider access", "unauthorized access", "internal user",
    "banking", "payment gateway", "SWIFT transaction", "credit card fraud",
    "financial institution", "ATM fraud", "currency manipulation",
    "payment system", "financial transaction", "bank fraud", "money laundering",
    "payment fraud", "transaction fraud"
]

# Create a regex pattern to match any of the keywords (case-insensitive)
keyword_pattern = re.compile("|".join(re.escape(keyword) for keyword in keywords), re.IGNORECASE)

# Find and copy matching CVEs to the new collection
for cve in source_collection.find():
    # Extract the description from the nested structure
    descriptions = cve.get("containers", {}).get("cna", {}).get("descriptions", [])
    description_text = next((desc.get("value", "") for desc in descriptions if desc.get("lang", "") == "en"), "")

    # Check if any of the keywords are found in the CVE description
    if keyword_pattern.search(description_text):
        # Insert the matching CVE into the new collection
        target_collection.insert_one(cve)
        print(f"Copied CVE: {cve.get('cveMetadata', {}).get('cveId', 'Unknown CVE ID')}")

print("Process complete. Matching CVEs have been copied to the 'filtered_cve_records' collection.")