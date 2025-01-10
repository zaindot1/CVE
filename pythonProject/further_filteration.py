import re
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['cve_database']  # Existing database name
source_collection = db['cve_records']  # Existing collection with all CVEs
target_collection = db['refined_filtered_cve_records']  # New collection to store matching CVEs

# Broad insider-related keywords (Layer 1)
insider_keywords = [
    "insider", "attack", "fraud", "misuse", "breach"
]

# Broad financial and banking-related keywords (Layer 2)
financial_keywords = [
    "bank", "financial", "payment", "credit", "account", "SWIFT", "currency"
]

# Create regex patterns to match both layers (case-insensitive)
insider_pattern = re.compile("|".join(insider_keywords), re.IGNORECASE)
financial_pattern = re.compile("|".join(financial_keywords), re.IGNORECASE)


# Function to check if the description or other fields match the keywords
def match_fields(cve):
    description = cve.get("Description", "")
    affected_systems = " ".join(cve.get("Affected_Systems", []))  # Join list into a string
    severity = cve.get("Severity", "")
    mitigation_strategies = cve.get("Mitigation_Strategies", "")

    # Concatenate relevant fields for searching
    searchable_text = f"{description} {affected_systems} {severity} {mitigation_strategies}"

    # Check for both insider-related and financial-related keywords in the combined text
    insider_match = insider_pattern.search(searchable_text)
    financial_match = financial_pattern.search(searchable_text)

    return insider_match, financial_match, searchable_text


# Tracking if any records are inserted
records_inserted = 0

# Find and copy matching CVEs to the new collection
for cve in source_collection.find():
    insider_match, financial_match, searchable_text = match_fields(cve)

    # Print debug info for CVEs that are inspected
    print(
        f"CVE ID: {cve.get('CVE_ID', 'Unknown ID')}, Insider match: {bool(insider_match)}, Financial match: {bool(financial_match)}")

    # If both patterns match, insert the CVE into the target collection
    if insider_match and financial_match:
        target_collection.update_one(
            {"CVE_ID": cve['CVE_ID']},  # Match by CVE_ID to avoid duplicates
            {"$set": cve},  # Update if it exists, otherwise insert
            upsert=True  # Insert if it doesn't exist
        )
        records_inserted += 1
        print(f"Copied CVE: {cve['CVE_ID']}")

# Summary of the process
if records_inserted > 0:
    print(
        f"Process complete. {records_inserted} matching CVEs have been copied to the 'refined_filtered_cve_records' collection.")
else:
    print("No matching CVEs were found based on the provided criteria.")
