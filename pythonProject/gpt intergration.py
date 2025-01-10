import os
import requests
import csv
from pymongo import MongoClient

# Get the OpenAI API key from the environment variable
api_key = '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'


# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")  # Adjust if needed
db = client['combined_cve_database']  # Your existing database name
source_collection = db['cve_api_results_after_2010']  # Collection with simplified CVE data
target_collection = db['gpt_cve_details_latest']  # New collection to store GPT-4o results


# Function to get details of a CVE using OpenAI API
def get_cve_details(cve_id):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    # Prepare the system and user message in the specified format
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant providing details about CVEs in a structured format."
            },
            {
                "role": "user",
                "content": f"Provide details for the CVE {cve_id} in the following format: \n1 - CVE ID\n2 - Description\n3 - Affected Systems\n4 - Score and Severity\n5 - Mitigation Strategies\n6 - Source URL\n7 - Related Keywords\n8 - Included/Excluded\n9 - Rationale\n10 - Vulnerability Lifecycle Stage."
            }
        ]
    }

    # Send the request to the API
    response = requests.post(url, headers=headers, json=payload)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        return data['choices'][0]['message']['content']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None


# Function to parse the GPT response into a structured format
def parse_gpt_response(gpt_response):
    if not gpt_response:
        return None

    # Print the GPT response to verify its structure
    print("GPT Response:")
    print(gpt_response)

    # Initialize the fields
    cve_data = {
        "CVE_ID": "",
        "Description": "",
        "Affected_Systems": "",
        "Score_and_Severity": "",
        "Mitigation_Strategies": "",
        "Source_URL": "",
        "Related_Keywords": "",
        "Included_Excluded": "",
        "Rationale": "",
        "Vulnerability_Lifecycle_Stage": ""
    }

    # Split the response by lines and map them into the correct fields
    mapping = {
        "1 - CVE ID": "CVE_ID",
        "2 - Description": "Description",
        "3 - Affected Systems": "Affected_Systems",
        "4 - Score and Severity": "Score_and_Severity",
        "5 - Mitigation Strategies": "Mitigation_Strategies",
        "6 - Source URL": "Source_URL",
        "7 - Related Keywords": "Related_Keywords",
        "8 - Included/Excluded": "Included_Excluded",
        "9 - Rationale": "Rationale",
        "10 - Vulnerability Lifecycle Stage": "Vulnerability_Lifecycle_Stage"
    }

    current_key = None
    for line in gpt_response.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Check if the line starts with one of the mapping keys
        for key, field in mapping.items():
            if line.startswith(key):
                current_key = field
                # Get the data after the colon or key
                cve_data[current_key] = line.split(key)[-1].strip()
                break
        else:
            # If current key is set, append data to the current field
            if current_key:
                cve_data[current_key] += f" {line.strip()}"

    return cve_data


# Loop over each CVE ID in the collection and fetch its details
def fetch_and_store_cve_details():
    cve_documents = source_collection.find({}, {"cve_id": 1})  # Fetch all CVE IDs
    for doc in cve_documents:
        cve_id = doc.get('cve_id')
        if cve_id:
            print(f"Fetching details for {cve_id}...")
            gpt_response = get_cve_details(cve_id)

            if gpt_response:
                parsed_data = parse_gpt_response(gpt_response)
                if parsed_data:
                    parsed_data["cve_id"] = cve_id  # Keep the original cve_id field

                    # Save the parsed details into MongoDB
                    target_collection.insert_one(parsed_data)
                    print(f"Stored structured details for {cve_id}.\n")
                else:
                    print(f"Could not parse details for {cve_id}. Skipping.")
            else:
                print(f"GPT response was empty for {cve_id}. Skipping.")


# Execute the process
fetch_and_store_cve_details()

print("CVE details fetching and storing complete.")