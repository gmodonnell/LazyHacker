"""
Functions that handle the parsing and cleaning of data either to be passed
between tools or from files/stdout into the writeup.

Lines 9-78 are the appendix.ps1 parser converted to Python via AI
so please double check it for accuracy and optimization.

Lines 83-End are CERTAINLY BROKEN version of the hoster.sh code
converted to Python via AI. The MUST BE FIXED and optimized.
"""

import sys
import re
import csv
import pandas as pd

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

# Parses a DarkOwl Query and Returns Dict of Data
def parseDarkOwl(results):
    allData = []
    for result in results:
        email = result.get('email', '')
        username = email.split('@')[0] if '@' in email else email
        record = {
            'email': email,
            'username': username,
            'password': result.get('password', ''),
            'type': result.get('type', ''),
            'leak': result.get('leak', ''),
            'last_seen': result.get('crawlDate', ''),
        }
        allData.append(record)
    return allData

# Takes DarkOwl Data from parseDarkOwl
# Writes it to CSV
def writeDarkowl(data):
    if not data:
        print("DarkOwl Data File is Empty")
        return False

    try:
        columns = ['email', 'username', 'password', 'type', 'leak', 'last_seen']
        df = pd.DataFrame(data)
        df = df[columns]  # enforce column order
        df.to_csv('DarkOwl.csv', index=False)
        print(f"Results saved to DarkOwl.csv")
        return True
    except Exception as e:
        print(f"Error saving to CSV: {e}")
        return False


"""
Everything BELOW THIS COMMENT IS RETARDED AI SLOP SHIT
and is definitely broken.
"""

def parse_service(service_string):
    """Parse the service string to extract the service name."""
    match = re.search(r'//(.+?)//', service_string)
    if match:
        return match.group(1).strip()
    return service_string

def process_file(filepath):
    """Process the nmap output file and extract IP, port, and service information."""
    results = []

    with open(filepath, 'r') as file:
        content = file.read()

    lines = content.split('\n')

    for line in lines:
        if 'Ports:' in line:
            # Extract IP address
            ip_match = re.search(r'Host:\s*(\S+)\s', line)
            if ip_match:
                ip = ip_match.group(1)

                # Extract ports information
                ports_info = re.sub(r'.*Ports:\s*', '', line)

                # Split ports information
                ports = ports_info.split(',')

                for port in ports:
                    match = re.search(r'(\d+)/open/tcp//(.+)', port)
                    if match:
                        port_number = match.group(1)
                        service = parse_service(match.group(2))

                        # Add to results
                        results.append({
                            'IP': ip,
                            'Port': port_number,
                            'Service': service
                        })

    return results

def export_to_csv(results, output_path='nmap_results.csv'):
    """Export results to a CSV file."""
    if results:
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['IP', 'Port', 'Service']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                writer.writerow(result)

        print(f"CSV file has been created at: {output_path}")
    else:
        print("No results to export.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python nmap_parser.py <filepath>")
        sys.exit(1)

    filepath = sys.argv[1]
    results = process_file(filepath)
    export_to_csv(results)



def query_whois(ip):
    """Query WHOIS information for an IP address using Python's socket library"""
    # Determine which WHOIS server to use based on IP
    whois_server = 'whois.arin.net'  # Default to ARIN for most IPs

    # Create a socket connection to the WHOIS server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois_server, 43))

    # Send the query
    s.send((ip + '\r\n').encode())

    # Receive the response
    response = b''
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data

    s.close()

    # Decode the response
    result = response.decode('utf-8', errors='ignore')

    # Check if we need to query a different WHOIS server
    for line in result.splitlines():
        if "ReferralServer:" in line:
            match = re.search(r'whois://([^:]+)', line)
            if match:
                referral_server = match.group(1)
                # Recursive query to the referred server
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((referral_server, 43))
                    s.send((ip + '\r\n').encode())

                    response = b''
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data

                    s.close()
                    result += response.decode('utf-8', errors='ignore')
                except:
                    pass  # Continue with original result if referral fails

    return result

def extract_field(whois_text, field_name):
    """Extract the first occurrence of a field from whois output"""
    for line in whois_text.splitlines():
        if line.strip().startswith(field_name):
            return line.strip()
    return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    sys.exit(process_ips_file(input_file))