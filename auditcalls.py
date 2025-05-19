"""
File for all auditing functions called by the main interface.
This includes SSL scanning, MX config checkers and anything
that is abstracted to another tool.
"""
from colorama import Fore, Style
import dns.exception
import dns.resolver


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
