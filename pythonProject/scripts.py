from pymongo import MongoClient
from datetime import datetime

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['combined_cve_database']  # Your existing database name
source_collection = db['cve_api_results']  # Collection with API results
target_collection = db['cve_api_results_after_2010']  # New collection to store results

# Date to compare (January 1, 2010)
cutoff_date = datetime(2010, 1, 1)

# Query to find all documents where the "published" date is after 2010
query = {
    "api_response.vulnerabilities.cve.published": {
        "$gt": cutoff_date.isoformat()  # Expecting the date in ISO string format
    }
}

# Find and move the matching documents
documents_to_move = source_collection.find(query)

# Insert each document into the new collection and remove it from the old one
for doc in documents_to_move:
    target_collection.insert_one(doc)  # Copy the document to the new collection
    source_collection.delete_one({"_id": doc["_id"]})  # Remove it from the original collection

print("Data migration complete.")
