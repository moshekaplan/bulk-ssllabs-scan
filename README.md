# bulk-ssllabs-scan
Python client for scanning many domains with the SSLLabs API

This script takes a file with a list of domains and generates a CSV report.

Usage: `python ssllabsscanner.py -i domains.txt -o domain_checks.csv`

You can also use `--write-intermediate` to store the SSLLabs API's JSON output to a file and `--read-intermediate` to read it back. This allows for rapid development and testing.
