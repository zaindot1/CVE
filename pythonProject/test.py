from pymongo import MongoClient

# Connect to the local MongoDB instance running on default port 27017
client = MongoClient("mongodb://localhost:27017/")

# Specify the database
db = client['test_database']

# Specify the collection
collection = db['test_collection']

# Insert a test document
test_document = {"name": "John Doe", "age": 30, "city": "San Francisco"}
collection.insert_one(test_document)

# Retrieve and print the document
retrieved_document = collection.find_one({"name": "John Doe"})
print(retrieved_document)
