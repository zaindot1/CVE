import re
import csv
from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['cve_database']  # Existing database name
source_collection = db['cve_records']  # Existing collection with all CVEs

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
    searchable_text = description
    match = pattern.search(searchable_text)
    return match, searchable_text


# Create CSV writers for the three output files
with open('insider_results.csv', mode='w', newline='') as insider_file, \
        open('financial_results.csv', mode='w', newline='') as financial_file, \
        open('insider_then_financial_results.csv', mode='w', newline='') as insider_financial_file:
    # Define CSV writers
    insider_writer = csv.writer(insider_file)
    financial_writer = csv.writer(financial_file)
    insider_financial_writer = csv.writer(insider_financial_file)

    # Write headers to the CSV files
    insider_writer.writerow(['CVE ID', 'Description'])
    financial_writer.writerow(['CVE ID', 'Description'])
    insider_financial_writer.writerow(['CVE ID', 'Description'])

    # Tracking for the third CSV (insider -> financial)
    records_inserted = 0

    # Loop through CVEs to apply the filters
    for cve in source_collection.find():
        cve_id = cve.get("CVE_ID", "Unknown ID")
        description = cve.get("Description", "")

        # First pass: Filter for insider-related matches
        insider_match, searchable_text = match_fields(cve, insider_pattern)

        # If an insider match is found, write to insider CSV
        if insider_match:
            insider_writer.writerow([cve_id, description])

            # Second pass: Check for financial-related match from the insider matches
            financial_match, _ = match_fields(cve, financial_pattern)

            # If a financial match is found after the insider match, write to both financial and insider-financial CSVs
            if financial_match:
                financial_writer.writerow([cve_id, description])
                insider_financial_writer.writerow([cve_id, description])
                records_inserted += 1
            else:
                # If no financial match, write to insider CSV only
                financial_writer.writerow([cve_id, description])

    # Summary of the process for the third CSV
    if records_inserted > 0:
        print(
            f"Process complete. {records_inserted} matching CVEs have been copied to 'insider_then_financial_results.csv'.")
    else:
        print("No matching CVEs were found based on the insider then financial criteria.")
