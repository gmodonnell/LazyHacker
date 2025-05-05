import datetime
import dns.exception
import dns.resolver
import requests
import getpass
import csv
from colorama import init, Fore, Style

# Attempts to resolve and return DMARC record
# given domain. Will print the DMARC to stdout
def resolveDMARC(domain):
    fqdn = f"_dmarc.{domain}"
    try:
        dmarc = dns.resolver.resolve(fqdn, "TXT")
        for rdata in dmarc:
            for string in rdata.strings:
                print(string.decode('utf-8'))
    except dns.resolver.NXDOMAIN:
        print(f"{Fore.RED}Domain {fqdn} does not exist{Style.RESET_ALL}")
    except dns.resolver.NoAnswer:
        print(f"{Fore.RED}No DMARC record found for {fqdn}{Style.RESET_ALL}")
    except Exception:
        print(f"{Fore.RED}Error: {Exception}{Style.RESET_ALL}")

# Checks for a DKIM record given a domain and selector
# returns the DKIM record if one is found
def checkDKIMSelector(domain, selector):
    try:
        fqdn = f"{selector}._domainkey.{domain}"
        dkim = dns.resolver.resolve(fqdn, "TXT")
        for rdata in dkim:
            return ''.join(str(txt) for txt in rdata.strings)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None

# Attempts to find a DKIM record using
# checkDKIMSelector and common selectors
def findDKIMRecord(domain):
    selectors = ["default", "google", "k1", "k2", "selector1", "selector2", "dkim", "mail",
        "email", "smtp", "20161025", "20150623", "20150623", "mandrill",
        "key1", "key2", "everlytic", "s1", "s2", "mxvault", "dk", "20230503",
        "20230224", "20220803", "sendgrid", "sig1", "litesrv", "ctct1", "ctct2", "zendesk1",
        "zendesk2", "mxvault", "spop1024", 'dk', 'a1', 'aweber_key_a', 'aweber_key_b', 'aweber_key_c',
        "cm", "clab1", "dkim1024", "e2ma-k1", "e2ma-k2", "e2ma-k3", "sable", "hs1", "hs2",
        "kl", "kl2", "mailjet", "mailpoet1", "mailpoet2", "m101", "m102", "ecm1", "nce2048",
        "smtp"]

    print(f"Attempting to find DKIM record for {domain} with {len(selectors)} selectors...")

    # Bool for DKIM existence
    found = False

    for selector in selectors:
        #print(f"Trying {selector}")
        result = checkDKIMSelector(domain, selector)

        if result:
            print(f"{Fore.GREEN}✓ DKIM record found for {selector}._domainkey.{domain}{Style.RESET_ALL}")
            print(f"Record: {result}")
            print("=" * 70)
            found = True

    if not found:
        print(f"{Fore.RED}No DKIM records found for {domain} with any of the common selectors{Style.RESET_ALL}")

# Queries Dehashed V2 API for Credentials
# Cleans data and throws it in a CSV
def dehashedV2Query(domain):
    # Gather user credentials
    dh_user = input("Dehashed Username: ")
    dh_api = getpass.getpass("Dehashed API Key: ")
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

def dedupe_csv(infile, outfile):
    # Read all entries
    seen = set()
    unique_entries = []

    with open(infile, 'r', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            # Clean each value by removing [''] notation
            cleaned_row = []
            for value in row:
                # Remove [''] notation if present
                if value.startswith("['") and value.endswith("']"):
                    value = value[2:-2]  # Remove ['']
                cleaned_row.append(value)

            # Create key tuple for deduplication
            if len(cleaned_row) >= 3:
                key = (cleaned_row[0], cleaned_row[1], cleaned_row[2])
                if key not in seen:
                    seen.add(key)
                    unique_entries.append(cleaned_row)

    # Sort by email
    unique_entries.sort(key=lambda x: x[0])

    # Write deduplicated and cleaned entries
    with open(outfile, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(unique_entries)


if __name__ == "__main__":
    domain = input("Type domain: ")
    resolveDMARC(domain)
    findDKIMRecord(domain)
    dehashedV2Query(domain)