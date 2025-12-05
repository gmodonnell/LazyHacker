#!/usr/env/bin/python
"""
The clerk file handles all parsing of logs and
tool output. The functions here are all 
correlated to functions in either the enumeration
or exploitation modules. While intended to 
be run in a certain order, the modules are kept 
individually accessible in case they need to be
run or tested in isolation
"""

import csv
from colorama import Fore
import pandas as pd
import json
from art.art import clerk

# Handles all funcs for parsing nmap output.
# Various formats are handled, as well as
#   categories of outfile
class NmapParser:
    # Greps live hosts from an gnmap file
    def grepLive(gnmapfile, outfile):
        with open(gnmapfile, 'r') as f, open(outfile, 'w') as out:
            for line in f:
                    if 'Status: Up' in line:
                        host = line.split()[1]
                        out.write(host + '\n')

    # Pulls open ports from a gnmap file.
    # Mimics old bash grepcut mess from scanningutils.py:27
    def grepOpenPorts(gnmapfile, outfile):
        with open(gnmapfile) as f:
            openports = {
                int(port)
                # grep "/open/"
                for line in f if '/open/' in line
                # cut -d " " -f 4- | tr "," "\n"
                for entry in ' '.join(line.split()[3:].split(','))
                # cut -d "/" -f 1
                if (port := entry.strip().split('/')[0].isdigit())
            }

        # Sort numerically and write to file
        with open(outfile, 'w') as out:
            for port in sorted(openports):
                out.write(f"{port}\n")

# Dedupes a CSV
# I forgot to write comments during original
# push so I actually don't know what data this is
# good for.                 
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

# Darkowl CSV Generator
# In: Darkowl Dump (json)
# Out: CSV for Reporting (csv)
# Out: True if parse is successful (bool)
# Out: False if no data to parse (bool)
def darkowlcsv(results):
    # Write all darkdowl data to array,
    # keeping only relevant information.
    alldata = []
    for result in results:
        print(result)
        record = {
            'email': result.get('email',''),
            'password': result.get('password',''),
            'leak': result.get('leak',''),
            'last_seen': result.get('crawlDate','')
        }
        alldata.append(record)
    if not alldata:
        print(f"{Fore.RED}No data found to fill csv...{Fore.RESET}")
        return False
    # Take alldata and turn into df, then csv
    # TODO: make this quicker, remove pd import
    #       implement csv.DictReader instead.
    try:
        columns = ['email','password','leak','last_seen']
        df = pd.DataFrame(alldata)
        df = df[columns]
        df.to_csv("DOPull.csv", index=False)
        print(f"{Fore.GREEN}DarkOwl Pull Successful{Fore.RESET}")
        return True
    except Exception as e:
        print(f"Error saving to CSV: {e}")
        return False
    
# URLCrazy CSV Generator
# IN: URLCrazy output filename (STR)
# OUT: CSV for Reportng (CSV)
# Out: True if parse is successful (bool)
# Out: False if no data to parse (bool)
def urlcsv(results):
    with open(results, "r") as r:
        urls = csv.reader(r)
        with open("urlreport.csv", "w", newline='') as f:
            output = csv.writer(f)
        # Transfers only URLs which resolve DNS
        for row in urls:
            # URLs which return completely empty DNS output get skipped
            if any(row[i] == "" for i in range(4,10)):
                pass
            else:
                # If DNS information is located, write the typo type,
                # domain and tld as 3 columns for reporting.
                parts = row[1].split('.', 1)
                output.writerow([row[0],parts[0],parts[1]])

# Credential concat into wordlist of names
# IN: Dehashed credential csv (csv)
# IN: darkown credential csv (csv)
# OUT: Namelist "names.txt" for validation/spraying (txt)
def credconcat(file1, file2):
    # Open output file for writing
    with open("names.txt", "w") as out:
        # DeHashed Names
        with open(file1, "r") as f1:
            csv1 = csv.reader(f1)
            for row in csv1:
                if row:
                    out.write(row[0] + '\n')
        # DarkOwl Names
        with open(file2, "r") as f2:
            csv2 = csv.reader(f2)
            for row in csv2:
                if row:
                    out.write(row[0] + '\n')
    # Dedupe the file
    with open("names.txt", "r") as f:
        lines = f.readlines()
    # Dedupe
    seen = set()
    unique_lines = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)
    # Write deduped content back to file
    with open("names.txt", "w") as out:
        out.writelines(unique_lines)

# Credential prep into report-ready csv
# IN: Dehashed credential csv (csv)
# IN: Darkowl Credential csv (CSV)
# OUT: csv file "breach.csv" in format user,pass,db (CSV)
def credprep(file1, file2):
    with open("breach.csv", "w", newline='') as b:
        writer = csv.writer(b)

        # Process Dehashed CSV (file1)
        with open(file1, "r") as f1:
            dhcsv = csv.reader(f1)
            for row in dhcsv:
                # Pull cleartext cred or weakest hash
                col2 = row[1] if row[1] else row[2].split(',')[0].split(':')[0].strip()
                writer.writerow([row[0], col2, row[3]])

        # Process DarkOwl CSV (file2)
        with open(file2, "r") as f2:
            docsv = csv.reader(f2)
            for row in docsv:
                # Write columns 1, 3, and 5
                writer.writerow([row[0], row[2], row[4]]) 
                
def flow():
    import sys
    import os
    clerk()
    print(
        f"""
        {Fore.YELLOW}=== Town Hall: Parsing ==={Fore.RESET}
        What would you like to parse?
        1. Nmap Scan (Extract Live Hosts)
        2. Nmap Scan (Extract Open Ports)
        3. Dehashed Results (Deduplicate)
        4. DarkOwl Results (JSON to CSV)
        5. URLCrazy Results (Filter DNS-resolved)
        6. Credential Files (Concatenate & Dedupe)
        7. Credential Files (Prep for Reporting)
        """
    )
    choice = input(f"{Fore.CYAN}Select Option [1-7]: {Fore.RESET}")

    match choice:
        case "1":
            print(f"{Fore.GREEN}Parsing Nmap for Live Hosts...{Fore.RESET}")
            gnmapfile = input(f"{Fore.CYAN}Gnmap file path: {Fore.RESET}")
            outfile = input(f"{Fore.CYAN}Output file (default: live_hosts.txt): {Fore.RESET}") or "live_hosts.txt"

            if not os.path.exists(gnmapfile):
                print(f"{Fore.RED}✗ File not found: {gnmapfile}{Fore.RESET}")
                return

            try:
                NmapParser.grepLive(gnmapfile, outfile)
                print(f"{Fore.GREEN}✓ Live hosts extracted to {outfile}{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Parse failed: {e}{Fore.RESET}")

        case "2":
            print(f"{Fore.GREEN}Parsing Nmap for Open Ports...{Fore.RESET}")
            gnmapfile = input(f"{Fore.CYAN}Gnmap file path: {Fore.RESET}")
            outfile = input(f"{Fore.CYAN}Output file (default: open_ports.txt): {Fore.RESET}") or "open_ports.txt"

            if not os.path.exists(gnmapfile):
                print(f"{Fore.RED}✗ File not found: {gnmapfile}{Fore.RESET}")
                return

            try:
                NmapParser.grepOpenPorts(gnmapfile, outfile)
                print(f"{Fore.GREEN}✓ Open ports extracted to {outfile}{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Parse failed: {e}{Fore.RESET}")

        case "3":
            print(f"{Fore.GREEN}Deduplicating Dehashed Results...{Fore.RESET}")
            infile = input(f"{Fore.CYAN}Input CSV file (default: dehashedResults.csv): {Fore.RESET}") or "dehashedResults.csv"
            outfile = input(f"{Fore.CYAN}Output file (default: dehashedDeduped.csv): {Fore.RESET}") or "dehashedDeduped.csv"

            if not os.path.exists(infile):
                print(f"{Fore.RED}✗ File not found: {infile}{Fore.RESET}")
                return

            try:
                dedupe_csv(infile, outfile)
                print(f"{Fore.GREEN}✓ Deduplicated results saved to {outfile}{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Dedupe failed: {e}{Fore.RESET}")

        case "4":
            print(f"{Fore.GREEN}Converting DarkOwl JSON to CSV...{Fore.RESET}")
            jsonfile = input(f"{Fore.CYAN}DarkOwl JSON file path: {Fore.RESET}")

            if not os.path.exists(jsonfile):
                print(f"{Fore.RED}✗ File not found: {jsonfile}{Fore.RESET}")
                return

            try:
                with open(jsonfile, 'r') as f:
                    results = json.load(f)

                success = darkowlcsv(results)
                if success:
                    print(f"{Fore.GREEN}✓ DarkOwl results saved to DOPull.csv{Fore.RESET}")
                else:
                    print(f"{Fore.RED}✗ No data to parse{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Parse failed: {e}{Fore.RESET}")

        case "5":
            print(f"{Fore.GREEN}Filtering URLCrazy Results...{Fore.RESET}")
            infile = input(f"{Fore.CYAN}URLCrazy CSV file (default: urlcrazy.csv): {Fore.RESET}") or "urlcrazy.csv"

            if not os.path.exists(infile):
                print(f"{Fore.RED}✗ File not found: {infile}{Fore.RESET}")
                return

            try:
                urlcsv(infile)
                print(f"{Fore.GREEN}✓ Filtered URLs saved to urlreport.csv{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Parse failed: {e}{Fore.RESET}")

        case "6":
            print(f"{Fore.GREEN}Concatenating Credential Files...{Fore.RESET}")
            file1 = input(f"{Fore.CYAN}Dehashed CSV (default: dehashedDeduped.csv): {Fore.RESET}") or "dehashedDeduped.csv"
            file2 = input(f"{Fore.CYAN}DarkOwl CSV (default: DOPull.csv): {Fore.RESET}") or "DOPull.csv"

            missing_files = []
            if not os.path.exists(file1):
                missing_files.append(file1)
            if not os.path.exists(file2):
                missing_files.append(file2)

            if missing_files:
                print(f"{Fore.YELLOW}⚠ Warning: Missing files: {', '.join(missing_files)}{Fore.RESET}")
                print(f"{Fore.YELLOW}Will process available files only...{Fore.RESET}")

            try:
                credconcat(file1, file2)
                print(f"{Fore.GREEN}✓ Concatenated usernames saved to names.txt{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Concat failed: {e}{Fore.RESET}")

        case "7":
            print(f"{Fore.GREEN}Preparing Credentials for Reporting...{Fore.RESET}")
            file1 = input(f"{Fore.CYAN}Dehashed CSV (default: dehashedDeduped.csv): {Fore.RESET}") or "dehashedDeduped.csv"
            file2 = input(f"{Fore.CYAN}DarkOwl CSV (default: DOPull.csv): {Fore.RESET}") or "DOPull.csv"

            missing_files = []
            if not os.path.exists(file1):
                missing_files.append(file1)
            if not os.path.exists(file2):
                missing_files.append(file2)

            if missing_files:
                print(f"{Fore.YELLOW}⚠ Warning: Missing files: {', '.join(missing_files)}{Fore.RESET}")
                print(f"{Fore.YELLOW}Will process available files only...{Fore.RESET}")

            try:
                credprep(file1, file2)
                print(f"{Fore.GREEN}✓ Credential report saved to breach.csv{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}✗ Prep failed: {e}{Fore.RESET}")

        case "Q"|"q":
            sys.exit()

        case _:
            print(f"{Fore.RED}Only digits 1-7 accepted...{Fore.RESET}")
    