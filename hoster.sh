#!/bin/bash

# Check if the input file is provided as an argument
if [ $# -ne 1 ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

input_file="$1"

# Check if the input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' not found."
    exit 1
fi

trim_cidr() {
    local ip_with_cidr="$1"
    echo "${ip_with_cidr%/*}"  # Remove everything after the last "/"
}

while IFS= read -r line; do
    if [[ $line =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        ip_address=$(trim_cidr "$line")
    else
        ip_address="$line"
    fi

    whois_result=$(whois "$ip_address")

    # Extract common information (NetRange, CIDR, Organization)
    net_range=$(echo "$whois_result" | grep -i 'NetRange:' | head -n 1)
    cidr=$(echo "$whois_result" | grep -i 'CIDR:' | head -n 1)
    organization=$(echo "$whois_result" | grep -i 'Organization:' | head -n 1)

    # Extract RIPE-specific information (descr, inetnum)
    if echo "$whois_result" | grep -q '^descr:'; then
        descr=$(echo "$whois_result" | grep -i 'descr:' | head -n 1)
        inetnum=$(echo "$whois_result" | grep -i 'inetnum:' | head -n 1)
    fi

    echo "IP Address: $ip_address"
    echo "$net_range"
    echo "$cidr"
    echo "$organization"
    if [ -n "$descr" ]; then
        echo "$descr"
    fi
    if [ -n "$inetnum" ]; then
        echo "$inetnum"
    fi
    echo "-------------------------"

    # Reset variables for next iteration
    unset descr inetnum

done < "$input_file"
