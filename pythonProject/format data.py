from pymongo import MongoClient
from datetime import datetime
import re

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['combined_cve_database']  # Your existing database name
source_collection = db['cve_api_results_after_2010']  # Collection with API results
target_collection = db['simplified_cve_data']  # New collection to store simplified results

# Define the insider and financial keywords
insider_keywords = [
    "insider threat", "malicious insider", "internal fraud", "insider misuse",
    "privilege escalation", "employee fraud", "insider attack", "internal attack",
    "insider access", "unauthorized access", "internal user"
]

financial_keywords = [
    "banking", "payment gateway", "SWIFT transaction", "credit card fraud",
    "financial institution", "ATM fraud", "currency manipulation",
    "payment system", "financial transaction", "bank fraud", "money laundering",
    "payment fraud", "transaction fraud"
]

# Compile regex for keyword matching
insider_keywords_regex = re.compile("|".join(insider_keywords), re.IGNORECASE)
financial_keywords_regex = re.compile("|".join(financial_keywords), re.IGNORECASE)


# Function to simplify and extract only important fields from the CVE data
def simplify_document(doc):
    vulnerabilities = doc.get('api_response', {}).get('vulnerabilities', [])
    if not vulnerabilities:
        return None

    cve_info = vulnerabilities[0].get('cve', {})
    descriptions = cve_info.get('descriptions', [])
    metrics = cve_info.get('metrics', {}).get('cvssMetricV2', [])
    references = cve_info.get('references', [])
    affected_systems = cve_info.get('configurations', [])

    description_text = descriptions[0].get('value',
                                           'No description available') if descriptions else 'No description available'

    # Check for keywords in the description
    related_keywords = []
    included = "No"  # Default as No

    if insider_keywords_regex.search(description_text):
        related_keywords.extend(insider_keywords_regex.findall(description_text))
        included = "Yes"

    if financial_keywords_regex.search(description_text):
        related_keywords.extend(financial_keywords_regex.findall(description_text))
        included = "Yes"

    # Simplified document with only important fields
    simplified_doc = {
        "cve_id": cve_info.get('id', 'Unknown'),
        "description": description_text,
        "affected_systems": [f"Vendor: {item.get('vendor', 'n/a')}, Product: {item.get('product', 'n/a')}"
                             for item in affected_systems[0].get('nodes', [{}])[0].get('cpeMatch', [])],
        "score_and_severity": metrics[0].get('cvssData', {}).get('baseScore', 'N/A') if metrics else 'N/A',
        "mitigation_strategies": "No specific mitigation mentioned",
        # Placeholder, if you have data for this you can extract it
        "source_url": references[0].get('url', 'No URL available') if references else 'No URL available',
        "related_keywords": list(set(related_keywords)),  # Remove duplicate keywords
        "included": included,
        "vulnerability_lifecycle_stage": "Unknown",  # Placeholder for MITRE ATT&CK framework if applicable
    }

    return simplified_doc


# Process and store the simplified data
def process_and_simplify_data():
    documents = source_collection.find()  # Fetch all documents

    for doc in documents:
        simplified_doc = simplify_document(doc)
        if simplified_doc:
            target_collection.insert_one(simplified_doc)  # Insert simplified document into the new collection
            print(f"Simplified and stored CVE: {simplified_doc['cve_id']}")


# Execute the simplification process
if __name__ == "__main__":
    process_and_simplify_data()

print("Data simplification complete.")
