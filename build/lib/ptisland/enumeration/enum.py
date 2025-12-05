#!/usr/env/bin/python
"""
Enumeration script handles the scanning and OSINT
function calls. Output files are generated but not
parsed. 

This file is intended to build out functions which
you can call piecemeal via the ptisland menu. If you
want a comprehensive test, run the full test (5) from
ptisland main menu.
"""

from colorama import Fore
import ptisland.parsing.clerk as clerk
import subprocess
from ptisland.art.art import mountain

# Scanning Class handles port scanning objects
class Scanning:
    # Performs an nmap connect scan against the scope
    # IN: scope file
    # OUT: Success (bool)
    # OUT: .gnmap of live hosts (ping responding)
    # TODO: Determine if -sn (ICMP) is the best way to do this
    #       as endpoints have been missed before.
    def connectScan(scope, exclude, outfile):
        cmd = ['nmap','-sn','-oG',outfile,'-iL',scope,'--excludefile',exclude, '--max-retries', '1', '--max-rtt-timeout', '800']
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
        except FileNotFoundError:
            return False, "nmap not found"
    

    # Conducts a Port Scan of TCP 1-65535 and UDP 161,500 (in interest of time)
    # IN: scopefile of desired hosts to scan (from connectScan)
    # OUT: gnmap of open ports on target systems
    # Currently does not have exclude support
    def portScan(livescope, outfile):
        # UDP ports restricted to 161 and 500 in the interest of time
        cmd = ['nmap','-sS','-sU','-p','T:1-65535,U:161,500','--open','-oG', outfile, '-iL', livescope]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True, result.stdout
        except FileNotFoundError:
            return False, "nmap not found"
        except subprocess.CalledProcessError as e:
            return False, e.stderr

    # Performs an nmap scan against all discovered ports
    # IN: scope (typically from portScan)
    # IN: ports (from clerk.grepOpenPorts())
    # OUT: TWO arrays, TCP and UDP ports in format int,int,int
    # TODO: Figure out why I commented this would output 2 arrays of ports.
    # TODO: ensure generating this output is POSSIBLE and
    #       MORE ACCURATE than simply mimicking the old implementation.
    def scriptScan(live_hosts, ports):
        # nmap -sS -sU -sV -p $ports -oA nmap_scan -iL live_hosts.txt
        cmd = []
        subprocess.run(cmd)

# WebEnum class handles functions which are
# responsible for subdomain enumeration and
# webapp tech drawdown (whatweb)
class WebEnum:
    pass

# Rhns the Enumeration Flow
# TODO: Take out the hardcoded scope and exclude names
#           `- This may not be necessary
def flow():
    import sys
    mountain()
    print(
        f"""
        {Fore.YELLOW}=== Lookout Peak: Enumeration ==={Fore.RESET}
        What type of scan would you like to run?
        1. Full Scan (Connect -> Port -> Script)
        2. Quick Scan (Connect -> Port)
        3. Connect Scan
        4. Port Scan (Requires Live Hosts File)
        """
    )
    choice = input(f"{Fore.CYAN}Select Option [1-4]: {Fore.RESET}")
    match choice:
        case "1":
            print(f"{Fore.GREEN}Running Full Scan...{Fore.RESET}")
            print(f"{Fore.YELLOW}[1/3] Performing connect scan...{Fore.RESET}")
            success, output = Scanning.connectScan('scope', 'exclude', 'connect_scan.gnmap')
            if success:
                print(f"{Fore.GREEN}Connect Scan Complete{Fore.RESET}")
                clerk.NmapParser.grepLive('connect_scan.gnmap', 'live_hosts.txt')
            else:
                print(f"{Fore.RED}Connect Scan Failed: {output}{Fore.RESET}")
                return
            
            # Port Scan Begins Here
            print(f"{Fore.YELLOW}[2/3] Performing Port Scan...{Fore.RESET}")
            success, output = Scanning.portScan('live_hosts.txt','port_scan.gnmap')
            if success:
                print(f"{Fore.GREEN}Port Scan Complete{Fore.RESET}")
            else:
                print(f"{Fore.RED}✗ Port Scan Failed: {output}{Fore.RESET}")
                return
            
            # Service Scan Begins Here
            print(f"{Fore.YELLOW}[3/3] Performing Service Scan...{Fore.RESET}")
            # TODO: Implement Scanning.scriptScan here.
        
        case "2":
            print(f"{Fore.GREEN}Running Quick Scan...{Fore.RESET}")
            print(f"{Fore.YELLOW}[1/2] Performing connect scan...{Fore.RESET}")
            success, output = Scanning.connectScan('scope', 'exclude', 'connect_scan.gnmap')
            if success:
                print(f"{Fore.GREEN}Connect Scan Complete{Fore.RESET}")
                clerk.NmapParser.grepLive('connect_scan.gnmap', 'live_hosts.txt')
            else:
                print(f"{Fore.RED}Connect Scan Failed: {output}{Fore.RESET}")
                return
            
            # Port Scan Begins Here
            print(f"{Fore.YELLOW}[2/2] Performing Port Scan...{Fore.RESET}")
            success, output = Scanning.portScan('live_hosts.txt','port_scan.gnmap')
            if success:
                print(f"{Fore.GREEN}Port Scan Complete{Fore.RESET}")
            else:
                print(f"{Fore.RED}✗ Port Scan Failed: {output}{Fore.RESET}")
                return
            
        case "3":
            print(f"{Fore.GREEN}Running Connect Scan...{Fore.RESET}")
            print(f"{Fore.YELLOW}[1/1] Performing connect scan...{Fore.RESET}")
            success, output = Scanning.connectScan('scope', 'exclude', 'connect_scan.gnmap')
            if success:
                print(f"{Fore.GREEN}Connect Scan Complete{Fore.RESET}")
                clerk.NmapParser.grepLive('connect_scan.gnmap', 'live_hosts.txt')
            else:
                print(f"{Fore.RED}Connect Scan Failed: {output}{Fore.RESET}")
                return
        
        case "4":
            livefile = input(f"{Fore.CYAN}Live Hosts Filepath: {Fore.RESET}")
            success, output = Scanning.portScan(livefile, 'port_scan.gnmap')
            if success:
                print(f"{Fore.GREEN}Port Scan Complete{Fore.RESET}")
            else:
                print(f"{Fore.RED}✗ Port Scan Failed: {output}{Fore.RESET}")
                return
        
        case "Q"|"q":
            sys.exit()
        
        case _:
            print(f"{Fore.RED}Only Digits 1-4 or 'Q' Accepted...{Fore.RESET}")