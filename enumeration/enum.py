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

import subprocess

# Scanning Class handles port scanning objects
class Scanning:
    # Performs an nmap connect scan against the scope
    # IN: scope file
    # OUT: .gnmap of live hosts (ping responding)
    def connectScan(scope, exclude, outfile):
        """
        usage:
        success, output = connectscan(scope, exclude, outfile)
        """
        cmd = ['nmap','-sn','-oG',outfile,'-iL',scope,'--excludefile',exclude]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
        except FileNotFoundError:
            return False, "nmap not found"
    

    # Conducts a Port Scan of TCP 1-65535 and UDP 1-1000
    # IN: scopefile of desired hosts to scan
    # OUT: gnmap of open ports on target systems
    # Currently does not have exclude support
    def portScan(livescope, outfile):
        cmd = ['nmap','-sS','-sU','-p','T:1-65535,U:1-1000','--open','-oG', outfile, '-iL', livescope]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True, result.stdout
        except FileNotFoundError:
            return False, "nmap not found"
        except subprocess.CalledProcessError as e:
            return False, e.stderr

    # Performs an nmap scan against all ports (T1-65535,U1-1000)
    # IN: scope (typically known live hosts)
    # OUT: TWO arrays, TCP and UDP ports in format int,int,int
    # TODO: ensure generating this output is POSSIBLE and
    #       MORE ACCURATE than simply mimicking the old implementation.
    def portScan(live_hosts):
        cmd = []
        subprocess.run(cmd)

# WebEnum class handles functions which are
# responsible for subdomain enumeration and
# webapp tech drawdown (whatweb)
class WebEnum:
    pass