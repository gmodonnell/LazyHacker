import datetime
import dns.exception
import dns.resolver
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
    selectors = ["default", "google", "k1", "selector1", "selector2", "dkim", "mail",
        "email", "smtp", "20161025", "20150623", "20150623", "mandrill",
        "key1", "key2", "everlytic", "s1", "s2", "mxvault", "dk", "20230503",
        "20230224", "20220803", "sendgrid"]

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




if __name__ == "__main__":
    domain = input("Type domain: ")
    resolveDMARC(domain)
    findDKIMRecord(domain)