import requests
import pymongo
import time

# MongoDB setup
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['security_database']
cve_collection = db['cve_data']

# Insider and financial keywords
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


# Function to fetch CVE data by keyword and page
def fetch_cve_by_keyword(keyword, page_number, api_key):
    url = "https://www.cvedetails.com/api/v1/vulnerability/fts"
    params = {
        'q': f'"{keyword}"',
        'pageNumber': page_number,
        'resultsPerPage': 100,
        'orderBy': 'relevance',
        'sort': 'DESC'
    }
    headers = {
        'Authorization': f'Bearer {api_key}',
        'accept': '*/*'
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                print(f"JSON parsing error for keyword '{keyword}'.")
                return None
        else:
            print(f"Failed to fetch data for keyword '{keyword}'.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed for keyword '{keyword}': {e}")
        return None


# Function to store data in MongoDB
def store_in_mongodb(data):
    if data:
        cve_collection.insert_many(data)
    else:
        print("No data to store.")


# Function to search and store CVEs based on keywords, iterating through all pages
def search_and_store_cves(api_key):
    for keyword in insider_keywords + financial_keywords:
        page_number = 1
        while True:
            print(f"Searching for CVEs with keyword: {keyword}, page: {page_number}")
            data = fetch_cve_by_keyword(keyword, page_number, api_key)

            if data and 'results' in data and data['results']:
                store_in_mongodb(data['results'])
                page_number += 1
            else:
                print(f"No more CVEs found for keyword: {keyword} on page: {page_number}")
                break

            # Sleep to avoid hitting the API rate limit for each page
            time.sleep(2)

        # Sleep for one minute before processing the next keyword
        print(f"Waiting for 1 minute before moving to the next keyword...")
        time.sleep(60)



# Example usage
api_key = '257ef0ac2bfb4ed7de50ac9dc5b00d8f890e4456.eyJzdWIiOjcyMzcsImlhdCI6MTcyODUwMDY3OCwiZXhwIjoxNzM1NjAzMjAwLCJraWQiOjEsImMiOiJ3b2pUVFJqanEwZ2NVRnQ3Qm5tMVpWWnAxV2VCUWxjTDdKRW5jeUhsRVwvOU9ocTdLSHJWTFwvZDd3ZGZGaXF5SGlvMnFPWG14VCJ9'  # Replace with your actual API key
search_and_store_cves(api_key)
