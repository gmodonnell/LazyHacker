"""
All functions that handle port scanning of the scope document.
Basically a big nmap/masscan wrapper.
"""

import os
import sys
from colorama import Fore, Style
import subprocess
from parseutils import NmapParser, appendixGen

# Progressively scans scoped endpoints
def phasedScan():
    print(f"{Fore.GREEN}Commencing Phased Scanning...{Fore.RESET}")
    print(f"{Fore.YELLOW}Phase 1: Initial Connect Scan...{Fore.RESET}")
    os.system("nmap -sn -oG connect_scan.gnmap -iL scope --excludefile exclude")
    # Extract Live Hosts
    os.system("grep 'Status: Up' connect_scan.gnmap | cut -d ' ' -f 2 > live_hosts.txt")

    print(f"{Fore.YELLOW}Phase 2: Port Scan On Live Hosts...{Fore.RESET}")
    # Port Scan
    os.system("nmap -sS -sU -p T:1-65535,U:1-1000 --open -oG port_scan.gnmap -iL live_hosts.txt")
    # Extract Open Ports
    os.system('grep "/open/" port_scan.gnmap | cut -d " " -f 4- | tr "," "\n" | cut -d "/" -f 1 | sort -nu > open_ports.txt')
    # Remove Leading Spaces
    os.system("sed -i 's/^[[:space:]]*//' open_ports.txt")

    print(f"{Fore.YELLOW}Phase 3: Targeted Script Scan...{Fore.RESET}")
    #Targeted Script Scan
    with open('open_ports.txt', 'r') as f:
        ports = ','.join(line.strip() for line in f if line.strip())
    os.system(f'nmap -sS -sU -sV -sC -p T:{[ports]},U:{ports} -oA nmap_scan -iL live_hosts.txt')

# Runs sslscan against ssl targets
def auditSSL():
    try:
        if not os.path.exists('ssl.txt'):
            print(f"{Fore.RED}WARNING: ssl.txt not found, skipping sslscan{Fore.RESET}")
            return
        cmd = ['sslscan', '--xml=ssl.xml', '--targets=ssl.txt']
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"{Fore.GREEN}SSLSCAN Completed Successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}SSL scan failed with return code {result.returncode}{Fore.RESET}")
            if result.stderr:
                print(f"Error: {result.stderr}")
    except FileNotFoundError:
        print("Error: sslscan command not found. Please install sslscan.")
    except Exception as e:
        print(f"Error running sslscan: {e}")

# Runs ssh-audit against ssh targets
def auditSSH():
    try:
        if not os.path.exists('ssh.txt'):
            print(f"{Fore.RED}WARNING: ssl.txt not found, skipping SSH AUDIT{Fore.RESET}")
            return
        cmd = ['ssh-audit', '--targets=ssh.txt', '-v']
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("SSH Audit Completed Successfully")
            print(result.stdout)
        else:
            print(f"SSH Audit Failed with return code {result.returncode}")
            if result.stderr:
                print(f"Error: {result.stderr}")
    except FileNotFoundError:
        print("Error: ssh-audit command not found. Please install ssh-audit")
    except Exception as e:
        print(f"Error running ssh-audit: {e}")

# Combination function of everything
# Enables oneshotting the whole joint
def auditScan():
    if not os.path.exists('scope'):
        print(f"{Fore.RED}ERROR: scopefile not found... ABORTING{Fore.RESET}")
        sys.exit(1)
    phasedScan()
    parserobj = NmapParser()
    parserobj.nmapParse()
    try:
        os.chdir('scanparse')
        print(f"{Fore.YELLOW}Entering directory: {os.getcwd()}{Fore.RESET}")
        print(f"{Fore.GREEN}Generating Host Discovery Appendix...{Fore.RESET}")
        appendixGen()
        print(f"{Fore.YELLOW}Running SSLSCAN...{Fore.RESET}")
        auditSSL()
        print(f"{Fore.YELLOW}Running SSH-AUDIT...{Fore.RESET}")
        auditSSH()
    except FileNotFoundError as e:
        print(f"{Fore.RED}ERROR: scanparse or required file not found - {e}{Fore.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}ERROR: {e}{Fore.RESET}")