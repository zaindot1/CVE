import re
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['cve_database']  # Existing database name
source_collection = db['cve_records']  # Existing collection with all CVEs
target_collection = db['folder_scrapper']  # New collection to store matching CVEs

# Insider-related keywords (First pass)
insider_keywords = [
    "insider threat", "malicious insider", "internal fraud", "insider misuse",
    "privilege escalation", "employee fraud", "insider attack", "internal attack",
    "insider access", "unauthorized access", "internal user"
]

# Financial-related keywords (Second pass, after insider match)
financial_keywords = [
    "banking", "payment gateway", "SWIFT transaction", "credit card fraud",
    "financial institution", "ATM fraud", "currency manipulation",
    "payment system", "financial transaction", "bank fraud", "money laundering",
    "payment fraud", "transaction fraud"
]

# Create regex patterns to match both layers (case-insensitive)
insider_pattern = re.compile("|".join(insider_keywords), re.IGNORECASE)
financial_pattern = re.compile("|".join(financial_keywords), re.IGNORECASE)


# Function to check if the description or other fields match the keywords
def match_fields(cve, pattern):
    description = cve.get("Description", "")
    affected_systems = " ".join(cve.get("Affected_Systems", []))  # Join list into a string
    severity = cve.get("Severity", "")
    mitigation_strategies = cve.get("Mitigation_Strategies", "")

    # Concatenate relevant fields for searching
    searchable_text = f"{description} {affected_systems} {severity} {mitigation_strategies}"

    # Check if the given pattern (either insider or financial) matches
    match = pattern.search(searchable_text)

    return match, searchable_text


# Tracking if any records are inserted
records_inserted = 0

# First pass: Filter for insider-related matches
for cve in source_collection.find():
    insider_match, searchable_text = match_fields(cve, insider_pattern)

    # If an insider match is found, proceed to check for financial-related keywords
    if insider_match:
        print(f"Insider match found for CVE ID: {cve.get('CVE_ID', 'Unknown ID')}")

        # Second pass: Check for financial-related match from the insider matches
        financial_match, _ = match_fields(cve, financial_pattern)

        if financial_match:
            # If both insider and financial matches are found, insert the CVE into the target collection
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
