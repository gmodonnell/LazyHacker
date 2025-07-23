"""
Functions that handle the parsing and cleaning of data either to be passed
between tools or from files/stdout into the writeup.

Lines 9-78 are the appendix.ps1 parser converted to Python via AI
so please double check it for accuracy and optimization.

Lines 83-End are CERTAINLY BROKEN version of the hoster.sh code
converted to Python via AI. The MUST BE FIXED and optimized.
"""

import sys
from collections import defaultdict
import re
import os
import csv
import shutil
from pathlib import Path
from typing import Dict, Set, List, Tuple, NamedTuple
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import functools
from colorama import Fore, Style

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

class PortInfo(NamedTuple):
    # Structured Port Information
    host: str
    port: int
    status: str
    protocol: str
    service: str
    version: str

class NmapParser:
    # All Nmap Parsing Related Functions. The infile and outdir are changed here
    def __init__(self, infile: str = "nmap_scan.gnmap", outdir: str = "scanparse"):
        self.infile = Path(infile)
        self.outdir = Path(outdir)
        self.csvfile = self.outdir / "parsed_nmap.csv"

        # Precomipling the Regex
        self.ippattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        self.portpattern = re.compile(r'(\d+)/(open|closed)/(\w+)//([^/]*)/([^/]*)/([^/]*)')

        # Colors and Port Service Mappings Omitted

        # Cached Data
        self._portdata: List[PortInfo] = []
        self._parsed = False

    @functools.lru_cache(maxsize=1000)
    def _ipsortkey(self, ip: str) -> Tuple[int, int, int, int]:
        # Cached IP Sorting Key
        try:
            return tuple(map(int, ip.split('.')))
        except:
            return (0,0,0,0)

    def _parsegnmapline(self, line: str) -> List[PortInfo]:
        # Parses a single gnmap line
        if not ('/open/' in line or '/closed/' in line):
            return []
        ip_match = self.ippattern.search(line)
        if not ip_match:
            return []
        host = ip_match.group(1)
        ports = []

        for match in self.portpattern.finditer(line):
            portnum = int(match.group(1))
            status = match.group(2)
            protocol = match.group(3)
            owner = match.group(4) or ""
            service = match.group(5) or ""
            version = match.group(6) or ""
            ports.append(PortInfo(host, portnum, status, protocol, service, version))
        return ports

    def  _loadAndParse(self):
        # Loads and Parses gnmap file
        if self._parsed:
            return

        print(f"{Fore.YELLOW}[>] Parsing GNMAP File{Fore.RESET}")

        with open(self.infile, 'r') as f:
            lines = f.readlines()

        # Parse All Lines
        allPorts = []
        for line in lines:
            allPorts.extend(self._parsegnmapline(line))

        self._portdata = sorted(allPorts, key=lambda x: self._ipsortkey(x.host))
        self._parsed = True

    # Check Temp File Cleanup Functionality
    def output_setup(self):
        # Sets Up Output Directory
        self.outdir.mkdir(exist_ok=True)

        temp_files = ["temp.csv", "webtemp2", "sshtemp", "ssltemp2", "reportemp"]
        for temp_file in temp_files:
            (self.outdir / temp_file).unlink(missing_ok=True)

    def makecsv(self):
        # Creates CSV File
        print(f"{Fore.YELLOW}[>] Creating CSV File{Fore.RESET}")
        with open(self.csvfile, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["HOST", "PORT", "STATUS",  "PROTOCOL", "SERVICE", "VERSION"])
            for portinfo in self._portdata:
                writer.writerow([
                    portinfo.host, portinfo.port, portinfo.status,
                    portinfo.protocol, portinfo.service, portinfo.version
                ])
        print(f"{Fore.GREEN}    - parsed_nmap.csv{Fore.RESET}")

    def _getopenports(self) -> List[PortInfo]:
        # Get only open ports
        return [p for p in self._portdata if p.status == 'open']

    def summary(self):
        # Create Summary File
        print(f"{Fore.YELLOW}[>] Creating Summary{Fore.RESET}")

        open_ports = self._getopenports()

        with open(self.outdir / "summary.txt", 'w') as f:
            f.write("+=========================================================================================+\n")
            f.write(f"{'| HOST':<18} {'| PORT / PROTOCOL':<16} {' | SERVICE':<52} {'|':<2}\n")

            last_host = ""
            for port_info in open_ports:
                if port_info.host != last_host:
                    f.write("+=========================================================================================+\n")

                version_str = f"- {port_info.version}" if port_info.version else ""
                service_ver = f"{port_info.service} {version_str}"

                f.write(f"| {port_info.host:<17} | {port_info.port} / {port_info.protocol:<11} | {service_ver:<50} |\n")
                last_host = port_info.host

            f.write("+=========================================================================================+\n")

        print(f"{Fore.GREEN}    - summary.txt{Fore.RESET}")

    def writetxt(self, filename: str, data: Set[str], description: str):
        # Write txt file of sorted data
        if data:
            sortedData = sorted(data, key=lambda x: self._ipsortkey(x.split(':')[0]) if ':' in x else self._ipsortkey(x))
            with open(self.outdir / filename, 'w') as f:
                f.write('\n'.join(sortedData))
            print(f"{Fore.GREEN}    - {filename}{Fore.RESET}")
        else:
            print(f"{Fore.RED}  - no {description}{Fore.RESET}")

    def ipport(self):
        # Create IP:PORT File
        print(f"{Fore.YELLOW}[>] Creating IP:PORT File{Fore.RESET}")
        ip_ports = {f"{p.host}:{p.port}" for p in self._getopenports()}
        sortedIPPorts = sorted(ip_ports, key=lambda x: (self._ipsortkey(x.split(':')[0]), int(x.split(':')[1])))
        if ip_ports:
            with open(self.outdir / "ipport.txt", 'w') as f:
                f.write('\n'.join(sortedIPPorts))
            print(f"{Fore.GREEN}    - ipport.txt{Fore.RESET}")

    def hoststatus(self):
        # Create up/down File
        print(f"{Fore.YELLOW}[>] Creating Up/Down File{Fore.RESET}")
        upHosts = set()
        downHosts = set()

        with open(self.infile, 'r') as f:
            for line in f:
                ipmatch = self.ippattern.search(line)
                if ipmatch:
                    host = ipmatch.group(1)
                    if 'Status: Up' in line or '/open/' in line:
                        upHosts.add(host)
                    elif 'Status: Down' in line:
                        downHosts.add(host)
        self.writetxt("up.txt", upHosts, "up hosts")
        self.writetxt("down.txt", downHosts, "down hosts")

    def portFiles(self):
        # Create all Port-Specific Files
        print(f"{Fore.YELLOW}[>] Creating Port Files{Fore.RESET}")
        openports =  self._getopenports()

        # Collect all Port data
        unique_ports = {str(p.port) for p in openports}
        tcp_ports = {str(p.port) for p in openports if p.protocol == 'tcp'}
        udp_ports = {str(p.port) for p in openports if p.protocol == 'udp'}

        # Write Port Files
        files_data = [
            ("unique.txt", unique_ports, "unique ports"),
            ("tcp.txt", tcp_ports, "tcp ports"),
            ("udp.txt", udp_ports, "udp_ports")
        ]

        for filename, data, desc in files_data:
            if data:
                sortedPorts = sorted(data, key=int)
                with open(self.outdir / filename, 'w') as f:
                    f.write(','.join(sortedPorts))
                print(f"{Fore.GREEN}    - {filename}{Fore.RESET}")
            else:
                print(f"{Fore.RED}  - no {desc}{Fore.RESET}")

    def serviceFiles(self):
        # Create Service-Specific Files
        print(f"{Fore.YELLOW}[>] Creating Service Files{Fore.RESET}")
        openPorts = self._getopenports()
        services = {
            'smb':set(),
            'web':set(),
            'ssl':set(),
            'ssh':set()
        }
        for p in openPorts:
            # SMB
            if p.port == 445:
                services['smb'].add(f"smb://{p.host}")
            # WEB
            if p.port in [80, 8080] or p.service == 'http':
                services['web'].add(f"http://{p.host}:{p.port}/")
            elif p.port in [443, 8443] or 'ssl' in p.service.lower():
                services['web'].add(f"https://{p.host}:{p.port}/")
            elif 'web' in p.version.lower():
                services['web'].add(f"http://{p.host}:{p.port}/")
            # SSL
            if p.port == 443 or any(term in p.service.lower() + p.version.lower() for term in ['ssl', 'tls']):
                services['ssl'].add(f"{p.host}:{p.port}")
            # SSH
            if p.port == 22 or 'ssh' in p.service.lower() + p.version.lower():
                services['ssh'].add(f"{p.host}:{p.port}")

        for service, data in services.items():
            self.writetxt(f"{service}.txt", data, f"{service} services")

    def nmapParse(self):
        # Main Parsing Function
        if not self.infile.exists():
            raise FileNotFoundError(f"{Fore.RED}Input File {self.infile} Not Found{Fore.RESET}")
        # Prep Environment
        self.output_setup()
        self._loadAndParse()
        # Execute All Parsing Functions
        self.makecsv()
        self.summary()
        self.ipport()
        self.hoststatus()
        self.portFiles()
        self.serviceFiles()

        print(f"{Fore.GREEN}[>] Parsing Complete! Results in '{self.outdir}'{Fore.RESET}")

def appendixGen():
    nmap_data = []
    try:
        with open('parsed_nmap.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    nmap_data.append((row[0], row[1]))
    except FileNotFoundError:
        print(f"Warning: parsed_nmap.csv not found")
        nmap_data = []
    sortedNmap = sorted(set(nmap_data))

    shodan_data = []
    try:
        with open('../shodanHosts.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    shodan_data.append((row[0], row[1]))
    except FileNotFoundError:
        print("Warning: ../shodanHosts.csv not found")
        shodan_data = []

    combinedData = shodan_data + sortedNmap

    host_dict = defaultdict(list)
    for host,port in combinedData:
        if host and port:
            host_dict[host].append(port)

    with open('appendix.csv', 'w') as f:
        for host, ports in host_dict.items():
            ports_str = ','.join(ports)
            f.write(f"{host}:{ports_str}\n")
    print("Generated appendix.csv")

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Optimized nmap gnmap parser")
    parser.add_argument("-i", "--input", default="nmap_scan.gnmap", help="Input gnmap file")
    parser.add_argument("-o", "--output", default="scanparse", help="Output directory")

    args = parser.parse_args()

    try:
        parser_obj = NmapParser(args.input, args.output)
        parser_obj.nmapParse()
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

# Main fxn for debugging
if __name__ == "__main__":
    exit(main())

