import re
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if you're using a different connection string
db = client['cve_database']  # Existing database name
source_collection = db['cve_records']  # Existing collection with all CVEs
target_collection = db['filtered_cve_records']  # New collection to store matching CVEs

# Define the keywords to match
keywords = [
    "insider threat", "insider attack", "insider vulnerability", "insider fraud",
    "insider misuse", "insider data breach", "internal threat", "insider sabotage",
    "malicious insider", "banking insider threat", "financial insider attack",
    "payment system insider vulnerability", "online banking insider attack",
    "financial data breach by insider", "mobile banking insider attack",
    "digital wallet insider threat", "cash management insider threat",
    "bank account insider fraud", "SWIFT payment insider attack",
    "loan processing insider vulnerability", "financial transaction insider threat",
    "wealth management insider vulnerability", "fraudulent account creation",
    "asset management insider attack", "credit management insider vulnerability",
    "fraudulent transactions by insider", "financial reporting insider threat",
    "funds transfer insider vulnerability", "cardholder data insider breach",
    "credit card fraud by insider", "debit card data theft by insider",
    "unauthorized access to cardholder data", "payment card industry insider threat",
    "cardholder verification insider attack", "insider privilege escalation",
    "insider credential theft", "data exfiltration by insider", "lateral movement by insider",
    "insider credential access", "insider data manipulation", "privilege abuse",
    "unauthorized access", "internal credential misuse"
]

# Create a regex pattern to match any of the keywords (case-insensitive)
keyword_pattern = re.compile("|".join(keywords), re.IGNORECASE)

# Find and copy matching CVEs to the new collection
for cve in source_collection.find():
    description = cve.get("Description", "")

    # Check if any of the keywords are found in the CVE description
    if keyword_pattern.search(description):
        # Insert the matching CVE into the new collection
        target_collection.insert_one(cve)
        print(f"Copied CVE: {cve['CVE_ID']}")

print("Process complete. Matching CVEs have been copied to the 'filtered_cve_records' collection.")
