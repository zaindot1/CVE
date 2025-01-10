import os
import requests
from pymongo import MongoClient

# OpenAI API key (replace with actual key)
api_key = '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'

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")
db = client['combined_cve_database']
source_collection = db['cve_api_results_after_2010']
target_collection = db['gpt_cve_details_latest']
target_collection_latest = db['gpt_cve_details_latest_updated']
error_collection = db['gpt_cve_errors']
raw_response_collection = db['gpt_raw_responses']  # New collection to store raw responses

# Function to get details of a CVE using OpenAI API, asking for insider and finance relevance
def get_cve_details(cve_id):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant providing details about CVEs in a structured format."
            },
            {
                "role": "user",
                "content": f"""Provide details for the CVE {cve_id} in the following format:
                1 - CVE ID
                2 - Description
                3 - Affected Systems
                4 - Score and Severity
                5 - Mitigation Strategies
                6 - Source URL
                7 - Related Keywords
                8 - Included/Excluded
                9 - Rationale
                10 - Vulnerability Lifecycle Stage
                11 - Is it related to insider threats, financial sector (yes or no)
                12 - If no, then why not
                """
            }
        ]
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()
        raw_response = data['choices'][0]['message']['content']
        print(raw_response)
        return raw_response
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def parse_gpt_response(gpt_response):
    if not gpt_response:
        return None

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
        "Vulnerability_Lifecycle_Stage": "",
        "Insider_Finance_Relevance": "",
        "No_Relevance_Reason": ""
    }

    # Mapping for the fields we want to capture
    mapping = {
        "CVE ID": "CVE_ID",
        "Description": "Description",
        "Affected Systems": "Affected_Systems",
        "Score and Severity": "Score_and_Severity",
        "Mitigation Strategies": "Mitigation_Strategies",
        "Source URL": "Source_URL",
        "Related Keywords": "Related_Keywords",
        "Included/Excluded": "Included_Excluded",
        "Rationale": "Rationale",
        "Vulnerability Lifecycle Stage": "Vulnerability_Lifecycle_Stage",
        "Is it related to insider threats, financial sector": "Insider_Finance_Relevance",
        "If no, then why not": "No_Relevance_Reason"
    }

    current_key = None
    for line in gpt_response.split("\n"):
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Remove any ** markers or special formatting
        line = line.replace("**", "")

        # Check if the line starts with one of the mapping keys
        for key, field in mapping.items():
            if key in line:
                current_key = field
                # Extract the content after the first colon or hyphen and strip any trailing spaces
                if ":" in line:
                    cve_data[current_key] = line.split(":", 1)[-1].strip()
                elif "-" in line:
                    cve_data[current_key] = line.split("-", 1)[-1].strip()
                break
        else:
            # Continue appending data for the current key if we are inside a multi-line field
            if current_key and line:
                cve_data[current_key] += f" {line.strip()}"

    # Ensure that empty fields are None
    for key, value in cve_data.items():
        if not value:
            cve_data[key] = None

    return cve_data


# Function to fetch and store CVE details
def fetch_and_store_cve_details():
    cve_documents = source_collection.find({}, {"cve_id": 1})  # Fetch all CVE IDs

    for doc in cve_documents:
        cve_id = doc.get('cve_id')
        if cve_id:
            print(f"Fetching details for {cve_id}...")
            gpt_response = get_cve_details(cve_id)

            if gpt_response:
                parsed_data = parse_gpt_response(gpt_response)

                # Store raw response in raw_response_collection
                raw_response_collection.insert_one({"cve_id": cve_id, "raw_response": gpt_response})

                if parsed_data:
                    parsed_data["cve_id"] = cve_id  # Keep the original cve_id field

                    # Save parsed data to target collection
                    target_collection_latest.insert_one(parsed_data)
                    print(f"Stored structured details for {cve_id}.\n")
                else:
                    print(f"Could not parse details for {cve_id}. Storing raw response.")
                    error_collection.insert_one({"cve_id": cve_id, "raw_response": gpt_response})
            else:
                print(f"GPT response was empty for {cve_id}. Skipping.")


# Execute the process
fetch_and_store_cve_details()

print("CVE details fetching and storing complete.")
