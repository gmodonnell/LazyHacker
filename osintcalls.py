"""
Any OSINT functions that also call an API because I want
all the money wasters in a separate file.
"""

from getpass import getpass
from colorama import Fore, Style
import requests
import json
import csv
from parseutils import dedupe_csv
from datetime import datetime
import hmac
import hashlib
import base64

# Queries Dehashed V2 API for Credentials
# Cleans data and throws it in a CSV
def dehashedV2Query(domain):
    # Gather user credentials
    dh_api = getpass("Dehashed API Key: ")
    print(f"{Fore.CYAN}Querying Dehashed for {domain}{Style.RESET_ALL}")

    # Prepare Request
    url = "https://api.dehashed.com/v2/search"
    headers = {
        "Content-Type": "application/json",
        "Dehashed-Api-Key": dh_api
    }
    payload = {
        "query": f"domain:{domain}",
        "page": 1,
        "size": 10000,
        "wildcard": False,
        "regex": False,
        "de_dupe": True
    }

    # Make POST request
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload
        )

        # Check if request was successful
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Status code: {e.response.status_code}")
            print(f"Response: {e.response.text[:500]}...")
        return

    # Parse response
    try:
        data = response.json()
    except json.JSONDecodeError:
        print("Failed to parse API response as JSON")
        print(f"Response: {response.text[:500]}...")
        return

    # Debug response structure
    print(f"API Response Keys: {list(data.keys())}")

    # Handle different possible response structures
    entries = []
    if 'data' in data and isinstance(data['data'], list):
        entries = data['data']
    elif 'entries' in data and isinstance(data['entries'], list):
        entries = data['entries']
    elif 'results' in data and isinstance(data['results'], list):
        entries = data['results']
    else:
        print("Unexpected API response structure. Full response:")
        print(json.dumps(data, indent=2)[:500] + "...")
        return

    total_entries = len(entries)
    print(f"{total_entries} records to parse. Starting Now...")

    # Process and filter entries
    valid_entries = []
    for index, item in enumerate(entries):
        print(f"\r{index}/{total_entries}", end="")

        email = item.get('email', '')
        password = item.get('password', '')
        hashed_password = item.get('hashed_password', '')
        database_name = item.get('database_name', '')

        if (password or hashed_password) and email and database_name:
            valid_entries.append([email, password, hashed_password, database_name])

    print(f"\nFound {len(valid_entries)} valid entries")

    # Save to CSV
    with open('dehashedResults.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(valid_entries)

    # Sort and remove duplicates
    dedupe_csv('dehashedResults.csv', 'dehashedDeduped.csv')
    print(f"Results saved to dehashedDeduped.csv")

# Queries DarkOwl V1 API for historic data
# related to domain.
# INPUT: Domain (str)
# OUTPUT: Shitload of JSON
def darkowlQuery(domain):
    print(f"Querying DarkOwl for Records Associated with {domain}")
    privkey = getpass("Input DarkOwl Private Key: ")
    pubkey = getpass("Input DarkOwl Public Key: ")
    url = "https://api.darkowl.com/api/v1/entity/email-domain"
    path = f"/api/v1/entity/email-domain?domain={domain}"
    headers = makeDarkOwlHeaders(path, privkey, pubkey)

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f'Error: Status Code {response.status_code}')
            print(response.content)
        return response.json
    except requests.exceptions.RequestException as e:
        print(f"Error Connecting to API: {e}")

# Checks DarkOwl API Balance
# TODO: Integrate this fxn with darkowlQuery fxn to
# skip the query if the API balance is under 500 calls.
def apiBalanceCheck(privkey, pubkey):
    print("Checking DarkOwl API Balance...")
    path = '/api/v1/usage'
    try:
        headers = makeDarkOwlHeaders(path, privkey, pubkey)
        response = requests.get(f'https://api.darkowl.com{path}', headers=headers)
        if response.status_code != 200:
            print(f"Error Checking Usage: Status Code {response.status_code}")
            print(response.content)
            return None
        usage = response.json()
        return usage
    except requests.exceptions.RequestException as e:
        print(f"Error Connecting to Usage API: {e}")
        return None

# Generates Auth Headers for DarkOwl
def makeDarkOwlHeaders(path, privkey, pubkey):
    date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    str2hash = f'GET{path}{date}'
    bkey = bytes(privkey, encoding='UTF-8')
    bpayload = bytes(str2hash, encoding='UTF-8')
    hmac1 = hmac.new(bkey, bpayload, hashlib.sha1).digest()
    b64encoded = base64.b64encode(hmac1).decode('UTF-8')
    auth = f'OWL {pubkey}:{b64encoded}'
    return {
        'Authorization': auth,
        'X-VISION-DATE': date,
        'Accept': 'application/json'
    }

# TODO: Write this function
# Maybe put it in parseutils?
def parseDarkOwl():
    pass

# Wappalyzer -> NVD Call
class webScanner:
    # Subjects a list of urls to wappalyzer
    # In: List of urls (1 per line)
    # Out: csv of webapp, component, component, etc
    def wappalyze(list):
        pass

    # Calls the NVD Database