"""
OSINT entry point. This file will guide you through scraping
for credentials, usernames, DNS config, available URLs etc.
"""

import csv
import getpass
from colorama import Fore, Style
import requests
import json
from parsing.clerk import dedupe_csv
import dns.resolver
import hmac
import hashlib
import subprocess
import base64
from datetime import datetime, timedelta
import parsing.clerk as clerk

# OsintApi Class handles all the calls related to
# DarkOwl, Dehashed and other OSINT API Services
# which specifically REQUIRE KEYS
class OsintApi:
    
    # Makes headers for darkowl query
    # I refuse to explain this.
    # Needs the path from / for api endpoint requested
    def darkowlheaders(path):
        public = getpass.getpass("Please input your DarkOwl Public Key:")
        private = getpass.getpass("Please input your DarkOwl Private Key:")
        print(f"{Fore.YELLOW}generating headers...{Fore.RESET}")
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        string_to_hash = f'GET{path}{date}'
        bkey = bytes(private, encoding='UTF-8')
        bpayload = bytes(string_to_hash, encoding='UTF-8')
        hmac_sha1 = hmac.new(bkey, bpayload, hashlib.sha1).digest()
        b64encoded = base64.b64encode(hmac_sha1).decode('UTF-8')
        auth = f'OWL {public}:{b64encoded}'
        return {
            'Authorization': auth,
            'X-VISION-DATE': date,
            'Accept': 'application/json'
        }

    # Query DarkOwl API for information related to a domain
    # In: Domain (str)
    # Out: json data related to password dump
    # Out: False if no data or errors.
    # TODO: Potentially refactor this so it isn't as bulky
    def darkowlquery(domain):
        host = 'api.darkowl.com'
        email_endpoint = '/api/v1/entity/email-domain'
        path = f'{email_endpoint}?domain={domain}'
        url = f'https://{host}{path}'
        headers = OsintApi.darkowlheaders(path)
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print(f'Error: status code {response.status_code}')
                print(response.content)
                return False
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error connecting to the API:{Fore.RESET} {e}")
            return False

    # The main darkowl function that I am using
    # to hold everything together because I 
    # actually have no idea how to write code
    def darkowlpull(domain):
        dodata = OsintApi.darkowlquery(domain)
        clerk.darkowlcsv(dodata)

    # Query Dehashed V2 API for information related to a domain
    # In: Domain (str)
    # Out: csv data related to password dump.
    def dehashedV2Query(domain):
        # Gather user credentials
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

# DNSAudit Class examines the DNS, pulls down MX records
# and checks for misconfigurations
class DNSAudit:
    # Pulls dmarc record and either returns it or screams
    # IN: Domain Name (str)
    # OUT: dmarc record or False if none found.
    def dmarcPull(domain):
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{domain}','TXT')
            for data in dmarc:
                print(f"{Fore.GREEN}DMARC Record found for _dmarc.{domain}{Fore.RESET}")
                print(data)
            return dmarc
        except Exception as e:
            print(f"{Fore.RED}NO DMARC RECORD FOUND FOR _dmarc.{domain}, {type(e).__name__}.{Fore.RESET}")
            return False
    
    # Takes domain, tries to pull spf record
    # IN: Domain Name (str)
    # OUT: spf record or False if multiple.
    def spfPull(domain):
        records = dns.resolver.resolve(domain,'TXT')
        spf = []
        for record in records:
            # Convert spf TXT object to string
            spftext = record.to_text().strip('"')
            if 'spf' in spftext.lower():
                print(f"{Fore.YELLOW}Potential spf record found{Fore.RESET}")
                print(spftext)
                spf.append(spftext)
        if len(spf) > 1:
            print(f"{Fore.RED}MULTIPLE SPF RECORDS FOUND. See above output{Fore.RESET}")
            return False
        else:
            return spf

    # Checks for a DKIM record given a domain and selector
    # IN: Domain Name (str), selector (str)
    # OUT: DKIM record string or None if not found
    def checkDKIMSelector(domain, selector):
        try:
            fqdn = f"{selector}._domainkey.{domain}"
            dkim = dns.resolver.resolve(fqdn, "TXT")
            for rdata in dkim:
                return ''.join(str(txt) for txt in rdata.strings)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            return None

    # Attempts to find a DKIM record using checkDKIMSelector and common selectors
    # IN: Domain Name (str)
    # OUT: Prints found DKIM records, returns bool indicating if any were found
    def findDKIMRecord(domain):
        selectors = ["default", "google", "k1", "k2", "selector1", "selector2", "dkim", "mail",
            "email", "smtp", "20161025", "20150623", "mandrill",
            "key1", "key2", "everlytic", "s1", "s2", "mxvault", "dk", "20230503",
            "20230224", "20220803", "sendgrid", "sig1", "litesrv", "ctct1", "ctct2", "zendesk1",
            "zendesk2", "mxvault", "spop1024", 'dk', 'a1', 'aweber_key_a', 'aweber_key_b', 'aweber_key_c',
            "cm", "clab1", "dkim1024", "e2ma-k1", "e2ma-k2", "e2ma-k3", "sable", "hs1", "hs2",
            "kl", "kl2", "mailjet", "mailpoet1", "mailpoet2", "m101", "m102", "ecm1", "nce2048",
            "smtp"]

        print(f"{Fore.YELLOW}Attempting to find DKIM record for {domain} with {len(selectors)} selectors...{Fore.RESET}")

        # Bool for DKIM existence
        found = False

        for selector in selectors:
            result = DNSAudit.checkDKIMSelector(domain, selector)

            if result:
                print(f"{Fore.GREEN}✓ DKIM record found for {selector}._domainkey.{domain}{Fore.RESET}")
                print(f"Record: {result}")
                print("=" * 70)
                found = True

        if not found:
            print(f"{Fore.RED}No DKIM records found for {domain} with any of the common selectors{Fore.RESET}")

        return found

# Checks for Similar URLs and then turns them into a CSV
# for reporting
class URLAudit:
    # Uses the urlcrazy tool to do this
    def callURLCrazy(domain):
        cmd = ['urlcrazy','-n','-f','csv','-o','urlcrazy.csv',domain]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            clerk.urlcsv("urlcrazy.csv")
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
        except FileNotFoundError:
            return False, "urlcrazy not found"
        

# This is going to automate all username scraping.
class nameScraper:
    # Run li2u
    # try to match darkowl/dehashed format to 
    # recovered names to generate more comprehensive name list.
    # TODO: Implement SSH forwarding so you can get a GUI login.
    pass

# Cute menu to tie this all together.
def flow():
    # Hardcoded names for cred pull files.
    dehashedfile = 'dehashed.csv'
    darkowlfile =  'darkowl.csv'
    domain = input("Type the target domain: ")
    print(f"{Fore.YELLOW}Targeting Domain: {Fore.RESET}{domain}")
    print(f"{Fore.GREEN}Starting li2u...{Fore.RESET}")
    # TODO: Fix darkowlpull
    # OsintApi.darkowlpull(domain)
    # OsintApi.dehashedV2Query(domain)
    # Concat username file and generate cred report
    clerk.credconcat(dehashedfile, darkowlfile)
    clerk.credprep(dehashedfile, darkowlfile)
    # Audit DNS and URL Permutations
    DNSAudit.dmarcPull(domain)
    DNSAudit.spfPull(domain)
    URLAudit.callURLCrazy(domain)
    pass