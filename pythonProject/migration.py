from pymongo import MongoClient

# MongoDB connection setup
source_client = MongoClient("mongodb://localhost:27017/")  # Adjust if using a different connection string
source_db = source_client['security_database']

# Source collections
cve_records_nvd = source_db['cve_records_nvd']
filtered_cve_records = source_db['filtered_cve_records']
cve_data = source_db['cve_records']

# New MongoDB database for all combined records
target_client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
target_db = target_client['combined_cve_database']
target_collection = target_db['all_cve_records']

# Helper function to reformat and copy the data into the target collection
def reformat_and_copy(doc, target_collection):
    # Check the structure and reformat to match 'cve_records_nvd'
    reformatted_doc = {
        'cve': {
            'id': doc.get('cve', {}).get('id') or doc.get('cveMetadata', {}).get('cveId') or doc.get('cveId', None),
            'sourceIdentifier': doc.get('cve', {}).get('sourceIdentifier', 'unknown'),
            'published': doc.get('cve', {}).get('published', None),
            'lastModified': doc.get('cve', {}).get('lastModified', None),
            'vulnStatus': doc.get('cve', {}).get('vulnStatus', None),
            'descriptions': doc.get('containers', {}).get('cna', {}).get('descriptions', []),
            'metrics': doc.get('metrics', {}),  # Using the existing metrics data if available
            'weaknesses': doc.get('weaknesses', []),
            'configurations': doc.get('configurations', []),
            'references': doc.get('references', []),
        }
    }

    # Insert the document if it's not already in the target collection
    if reformatted_doc['cve']['id'] and not target_collection.find_one({'cve.id': reformatted_doc['cve']['id']}):
        target_collection.insert_one(reformatted_doc)
        print(f"Inserted CVE: {reformatted_doc['cve']['id']}")
    else:
        print(f"Duplicate CVE: {reformatted_doc['cve']['id']} - Skipped")

# Copy data from 'cve_records_nvd' to the new database (already in the right format)
print("Copying data from 'cve_records_nvd'...")
for doc in cve_records_nvd.find():
    reformat_and_copy(doc, target_collection)

# Reformat and copy data from 'filtered_cve_records'
print("Copying data from 'filtered_cve_records'...")
for doc in filtered_cve_records.find():
    reformat_and_copy(doc, target_collection)

# Reformat and copy data from 'cve_data'
print("Copying data from 'cve_records'...")
for doc in cve_data.find():
    reformat_and_copy(doc, target_collection)

print("Data migration complete.")
