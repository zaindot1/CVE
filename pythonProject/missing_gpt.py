import pandas as pd
from openai import OpenAI
from pymongo import MongoClient
import json

# Initialize OpenAI client with your API key
client = OpenAI(api_key = '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')
  # Replace with your OpenAI API key
# MongoDB connection setup (adjust the URI and database as necessary)
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client['combined_cve_database']
target_collection = db['missing_cve_gpt_latest']
error_collection = db['gpt_cve_errors']

# Path to your local CSV file
file_path = '/Users/laeeqagaffar/Documents/missing_cve.csv'

# Load the CSV file into a DataFrame
df = pd.read_csv(file_path)


# Function to query ChatGPT and get CVE details
def get_cve_details(cve_id):
    try:
        # This is the original query you provided. We're keeping it intact.
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": [
                        {
                            "text": "you are a cyber security expert",
                            "type": "text"
                        }
                    ]
                }
            ],
            temperature=1,
            max_tokens=1071,
            top_p=1,
            frequency_penalty=0,
            presence_penalty=0,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "cve_analysis",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "required": [
                            "parameters"
                        ],
                        "properties": {
                            "parameters": {
                                "type": "object",
                                "required": [
                                    "cve_id",
                                    "description",
                                    "affected_systems",
                                    "score_and_severity",
                                    "mitigation_strategies",
                                    "source_url",
                                    "related_keywords",
                                    "included_excluded",
                                    "rationale",
                                    "vulnerability_lifecycle_stage",
                                    "insider_threats_financial_sector",
                                    "if_no_reason",
                                    "insider_threats_or_financial_sector"
                                ],
                                "properties": {
                                    "cve_id": {
                                        "type": "string",
                                        "description": "The exact CVE identifier."
                                    },
                                    "rationale": {
                                        "type": "string",
                                        "description": "Explain the significance or reason for inclusion or exclusion."
                                    },
                                    "source_url": {
                                        "type": "string",
                                        "description": "A reliable URL where the CVE details can be verified."
                                    },
                                    "description": {
                                        "type": "string",
                                        "description": "Summary of the details and impact of the vulnerability."
                                    },
                                    "if_no_reason": {
                                        "type": "string",
                                        "description": "Provide reasoning if not related to insider threats or the financial sector."
                                    },
                                    "affected_systems": {
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                            "description": "An affected system or platform."
                                        },
                                        "description": "List of operating systems, software versions, or platforms impacted by the CVE."
                                    },
                                    "related_keywords": {
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                            "description": "A related keyword."
                                        },
                                        "description": "List of relevant keywords related to the CVE."
                                    },
                                    "included_excluded": {
                                        "type": "string",
                                        "description": "Specify any inclusion or exclusion criteria, if applicable."
                                    },
                                    "score_and_severity": {
                                        "type": "object",
                                        "required": [
                                            "cvss_score",
                                            "severity_level"
                                        ],
                                        "properties": {
                                            "cvss_score": {
                                                "type": "number",
                                                "description": "The CVSS score of the vulnerability."
                                            },
                                            "severity_level": {
                                                "type": "string",
                                                "description": "The assigned severity level."
                                            }
                                        },
                                        "additionalProperties": False
                                    },
                                    "mitigation_strategies": {
                                        "type": "string",
                                        "description": "Recommendations or updates for mitigating the vulnerability."
                                    },
                                    "vulnerability_lifecycle_stage": {
                                        "type": "string",
                                        "description": "Current lifecycle stage such as discovery, patch released, or closed."
                                    },
                                    "insider_threats_financial_sector": {
                                        "enum": [
                                            "Yes",
                                            "No"
                                        ],
                                        "type": "string",
                                        "description": "Determine if the CVE is related to insider threats and the financial sector."
                                    },
                                    "insider_threats_or_financial_sector": {
                                        "enum": [
                                            "insider",
                                            "financial"
                                        ],
                                        "type": "string",
                                        "description": "Determine if the CVE is related to insider threats or the financial sector."
                                    }
                                },
                                "additionalProperties": False
                            }
                        },
                        "additionalProperties": False
                    }
                }
            }
        )

        # Since the response is coming back as a Python object, extract the actual 'content'
        print(response)
        message_content = response.choices[0].message.content
        print(message_content)
        # The content is a JSON-like string, so we need to parse it as JSON
        parsed_content = json.loads(message_content)
        print(parsed_content)

        return parsed_content  # Return the parsed dictionary

    except Exception as e:
        print(f"Error fetching details for CVE {cve_id}: {str(e)}")
        return None


# Iterate over the rows in the DataFrame, querying the OpenAI API with each CVE ID
for index, row in df.iterrows():
    cve_id = row['cve_id']  # Extract the CVE ID
    if pd.notna(cve_id):
        print(f"Fetching details for CVE ID: {cve_id}")
        gpt_response = get_cve_details(cve_id)

        if gpt_response:
            try:
                # Save response to MongoDB
                target_collection.insert_one({"cve_id": cve_id, **gpt_response})  # Save the parsed response
                print(f"Stored structured details for {cve_id}.")
            except Exception as e:
                print(f"Failed to store details for {cve_id}. Error: {str(e)}")
                error_collection.insert_one({"cve_id": cve_id, "error": str(e)})
        else:
            print(f"No response for CVE {cve_id}")

print("Process completed.")
