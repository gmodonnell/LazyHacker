#! /usr/bin/python

import re
from typing import List, Set, Dict
import dns.resolver
from dataclasses import dataclass
from collections import defaultdict
import sys

@dataclass
class LookupStats:
    count: int = 0
    paths: Dict[str, List[str]] = None

    def __post_init__(self):
        if self.paths is None:
            self.paths = defaultdict(list)

class TooManyLookupsError(Exception):
    def __init__(self, path: List[str]):
        self.path = path
        super().__init__(f"Maximum lookups (10) exceeded. Path: {' -> '.join(path)}")

def parse_spf_includes(spf_record: str) -> List[str]:
    # Parse SPF and pull FQDNs
    if not spf_record:
        raise ValueError("There does not appear to be an SPF record at this location")

    pattern = r'(?<=include:)[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b'

    try:
        includes = re.findall(pattern, spf_record)
        return includes if includes else []
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")

def get_spf_record(fqdn: str) -> str:
    # Get SPF record
    try:
        answers = dns.resolver.resolve(fqdn, 'TXT')
        # Combine all strings in the TXT record and decode from bytes
        return ''.join(str(rdata).replace('"', '') for rdata in answers[0].strings)
    except dns.exception.DNSException as e:
        raise ValueError(f"DNS lookup failed for {fqdn}: {str(e)}")

def analyze_spf_tree(
    fqdn: str,
    stats: LookupStats,
    visited: Set[str] = None,
    current_path: List[str] = None
) -> List[str]:
    """
    Recursively analyze SPF record tree, tracking lookups and paths.

    Args:
        fqdn: The FQDN to analyze
        stats: Tracking object for lookup counts and paths
        visited: Set of already visited FQDNs
        current_path: Current path in the SPF tree

    Returns:
        List of all discovered FQDNs
    """
    if visited is None:
        visited = set()
    if current_path is None:
        current_path = []

    current_path.append(fqdn)

    # Check if we've exceeded lookup limit
    stats.count += 1
    if stats.count > 10:
        raise TooManyLookupsError(current_path)

    # Record the path to this node
    path_key = current_path[0]
    stats.paths[path_key] = current_path.copy()

    # Skip if we've seen this FQDN
    if fqdn in visited:
        return []

    visited.add(fqdn)
    discovered_fqdns = []

    try:
        txt_record = get_spf_record(fqdn)
        includes = parse_spf_includes(txt_record)

        for include in includes:
            discovered_fqdns.extend(
                analyze_spf_tree(include, stats, visited, current_path.copy())
            )
            discovered_fqdns.append(include)

    except ValueError as e:
        print(f"Warning: {str(e)}")

    current_path.pop()
    return discovered_fqdns

def main():
    initial_spf = get_spf_record(sys.argv[1])
    stats = LookupStats()

    try:
        initial_includes = parse_spf_includes(initial_spf)
        all_fqdns = set()

        for include in initial_includes:
            try:
                discovered = analyze_spf_tree(include, stats)
                all_fqdns.update(discovered)
                all_fqdns.add(include)
            except TooManyLookupsError as e:
                print(f"Error in branch: {e}")

        print(f"\nTotal lookups performed: {stats.count}")
        print("\nDiscovered FQDNs:")
        for fqdn in sorted(all_fqdns):
            print(f"  {fqdn}")

        print("\nLookup paths:")
        for root, path in stats.paths.items():
            print(f"  {root}: {' -> '.join(path)}")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()