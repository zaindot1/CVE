from pymongo import MongoClient

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if using a different connection string
db = client['security_database']

# Collections
collection_1 = db['cve_data']  # First collection
collection_2 = db['cve_records_nvd']  # Second collection
collection_3 = db['filtered_cve_records']  # Third collection
collection_4 = db['cve_records_all']  # Third collection

# Fetch all CVE IDs from each collection with debugging output
cve_ids_1 = set()
cve_ids_2 = set()
cve_ids_3 = set()
cve_ids_4 = set()

for doc in collection_1.find({}, {'cveId': 1}):
    cve_id = doc.get('cveId')
    if cve_id:
        cve_ids_1.add(cve_id)
print(f"Total CVE IDs in collection 1: {len(cve_ids_1)}")

for doc in collection_2.find({}, {'cve.id': 1}):
    cve_id = doc.get('cve', {}).get('id')
    if cve_id:
        cve_ids_2.add(cve_id)
print(f"Total CVE IDs in collection 2: {len(cve_ids_2)}")

for doc in collection_3.find({}, {'cveMetadata.cveId': 1}):
    cve_id = doc.get('cveMetadata', {}).get('cveId')
    if cve_id:
        cve_ids_3.add(cve_id)
print(f"Total CVE IDs in collection 3: {len(cve_ids_3)}")

for doc in collection_4.find({}, {'cveMetadata.cveId': 1}):
    cve_id = doc.get('cveMetadata', {}).get('cveId')
    if cve_id:
        cve_ids_4.add(cve_id)
print(f"Total CVE IDs in collection 4: {len(cve_ids_4)}")

# Find common CVE IDs across all three collections
common_cve_ids = cve_ids_1.intersection(cve_ids_4, cve_ids_2)

# Output the common CVE IDs
print(f"Common CVE IDs ({len(common_cve_ids)} found):")
for cve_id in common_cve_ids:
    print(cve_id)

#collection_1 = db['cve_data']  # First collection
#collection_2 = db['cve_records_nvd']  # Second collection
#collection_3 = db['filtered_cve_records']  # Third collection
#collection_4 = db['cve_records_all']  # Third collection

print("ID 1 -> CVE details")
print("ID 2 -> CVE NVD")
print("ID 3 -> CVE org")
print("ID 4 -> CVE org all")

print(len(common_cve_ids))
print(f"Common CVE IDs 1 and 2 ({len(cve_ids_1.intersection(cve_ids_2))} found)")
print(f"Common CVE IDs 1 and 3 ({len(cve_ids_1.intersection(cve_ids_3))} found)")
print(f"Common CVE IDs 1 and 4 ({len(cve_ids_1.intersection(cve_ids_4))} found)")

print(f"Common CVE IDs 2 and 3 ({len(cve_ids_2.intersection(cve_ids_3))} found)")
print(f"Common CVE IDs 2 and 4 ({len(cve_ids_2.intersection(cve_ids_4))} found)")

print(f"Common CVE IDs 3 and 4 ({len(cve_ids_3.intersection(cve_ids_4))} found)")

print(f"Uncommon CVE IDs 1 and 2 ({len(cve_ids_1.difference(cve_ids_2))} found)")
print(f"Uncommon CVE IDs 2 and 1 ({len(cve_ids_2.difference(cve_ids_1))} found)")
print(f"Uncommon CVE IDs 1 and 3 ({len(cve_ids_1.difference(cve_ids_3))} found)")
print(f"Uncommon CVE IDs 3 and 1 ({len(cve_ids_3.difference(cve_ids_1))} found)")
print(f"Uncommon CVE IDs 1 and 4 ({len(cve_ids_1.difference(cve_ids_4))} found)")
print(f"Uncommon CVE IDs 4 and 1 ({len(cve_ids_4.difference(cve_ids_1))} found)")

print(f"Uncommon CVE IDs 2 and 3 ({len(cve_ids_2.difference(cve_ids_3))} found)")
print(f"Uncommon CVE IDs 3 and 2 ({len(cve_ids_3.difference(cve_ids_2))} found)")
print(f"Uncommon CVE IDs 2 and 4 ({len(cve_ids_2.difference(cve_ids_4))} found)")
print(f"Uncommon CVE IDs 4 and 2 ({len(cve_ids_4.difference(cve_ids_2))} found)")

print(f"Uncommon CVE IDs 3 and 4 ({len(cve_ids_3.difference(cve_ids_4))} found)")
print(f"Uncommon CVE IDs 4 and 3 ({len(cve_ids_4.difference(cve_ids_3))} found)")