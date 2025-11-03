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
from colorama import Fore, Style
import pandas as pd
import json

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
    def grepOpenPorts(gnmapfile, outfile):
         with open(gnmapfile, 'r') as f:
            content = f.read()
            openports = set()
            for line in content.splitlines():
                 if '/open/' in line:
                      pass

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
    
