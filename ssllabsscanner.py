#!/usr/bin/env python
# Roughly based on: https://github.com/TrullJ/ssllabs

"""
Given a list of domains, checks them all against the SSL Labs API and generates
a CSV report.

API Docs are available here:
https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v2-deprecated.md

Sample query:
https://api.ssllabs.com/api/v2/analyze?host=www.google.com&all=done

"""

from __future__ import print_function

import csv
import sys
import time
import json
import Queue
import socket
import logging
import argparse
import datetime
import threading

import requests

NUM_THREADS = 8

API = 'https://api.ssllabs.com/api/v2/'

global QUIET_MODE
QUIET_MODE = False


def print_q(*args):
    # Source: https://stackoverflow.com/questions/5574702/how-to-print-to-stderr-in-python
    if not QUIET_MODE:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print (ts, *args)


def requestAPI(path, payload={}):
    '''This is a helper method that takes the path to the relevant
        API call and the user-defined payload and requests the
        data/server test from Qualys SSL Labs.

        Returns JSON formatted data'''

    url = API + path
    response = requests.get(url, params=payload)
    logging.exception('Request to %s failed' % url)

    data = response.json()
    return data


def resultsFromCache(host, publish='off', fromCache='on', all='done'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'fromCache': fromCache,
                'all': all,
                'maxAge': 7*24
              }
    results = requestAPI(path, payload)

    while ('errors' in results) or (results['status'] != 'READY' and results['status'] != 'ERROR'):
        time.sleep(10)
        results = requestAPI(path, payload)

    return results


def ssl_present(endpoint_data):
    protocols = endpoint_data['details']['protocols']
    protocols_supported = {
        "SSL 1.0": "No",
        "SSL 2.0": "No",
        "SSL 3.0": "No",
        "TLS 1.0": "No",
        "TLS 1.1": "No",
        "TLS 1.2": "No",
        "TLS 1.3": "No"
    }
    for protocol in protocols:
        protocol_string = "%s %s" % (protocol['name'], protocol['version'])
        protocols_supported[protocol_string] = "Yes"
    return protocols_supported


def timestamp_to_YYYYMMDD(ts):
    dt = datetime.datetime.fromtimestamp(ts/1000)
    return dt.strftime("%Y%m%d")


def has_error(json_result):
    return json_result['status'] == 'ERROR'


def get_supports_3des(json_endpoint):
    supports_3des = "No"
    for suite in json_endpoint['details']["suites"]["list"]:
        if "3DES" in suite["name"].upper():
            supports_3des = "Yes"
    return supports_3des


def parse_result(json_result):
    """Parses the JSON output from SSLLabs API and returns the list of endpoint data"""
    results = []

    domain = json_result['host']
    nslookup_value = get_hostname(domain)
    if has_error(json_result):
        values = {}
        values['Status'] = "Domain Failed"
        values["Host Status Message"] = json_result.get('statusMessage', "")
        values['Domain'] = domain
        values['Test Date'] = timestamp_to_YYYYMMDD(json_result["testTime"])
        values['NSLOOKUP Result'] = nslookup_value
        results.append(values)
        return results

    poodle_tls_vals = {
        -3: "Timeout",
        -2: "TLS not supported",
        -1: "Test Failed",
         0: "Unknown",
         1: "Not Vulnerable",
         2: "Vulnerable"}

    for endpoint in json_result['endpoints']:
        values = {}
        values["Host Status Message"] = json_result.get('statusMessage', "")
        values["Endpoint Status Message"] = endpoint.get('statusMessage', "")
        values['NSLOOKUP Result'] = nslookup_value
        values['Test Date'] = timestamp_to_YYYYMMDD(json_result["testTime"])
        values['Domain'] = domain
        values['Hostname'] = endpoint.get("serverName", "Not Present")
        values['Host IP Address'] = endpoint["ipAddress"]
        if endpoint['progress'] != 100:
            values['Status'] = "Endpoint Failed"
        else:
            values['Status'] = "Success"
            values['Grade'] = endpoint['grade']
            ssl_versions = ssl_present(endpoint)
            values['SSL 1.0'] = ssl_versions['SSL 1.0']
            values['SSL 2.0'] = ssl_versions['SSL 2.0']
            values['SSL 3.0'] = ssl_versions['SSL 3.0']
            values['TLS 1.0'] = ssl_versions['TLS 1.0']
            values['TLS 1.1'] = ssl_versions['TLS 1.1']
            values['TLS 1.2'] = ssl_versions['TLS 1.2']
            values['TLS 1.3'] = ssl_versions['TLS 1.3']

            values['Has HSTS'] = endpoint['details']['hstsPolicy']['status']
            values['Vuln to BEAST'] = endpoint['details']['vulnBeast']
            values['Vuln to POODLE'] = endpoint['details']['poodle']
            values['Vuln to POODLE TLS'] = poodle_tls_vals[endpoint['details']['poodleTls']]
            values['Supports RC4'] = endpoint['details']['supportsRc4']
            values['Supports 3DES'] = get_supports_3des(endpoint)

            values['Cert Start Date'] = timestamp_to_YYYYMMDD(endpoint['details']['cert']['notBefore'])
            values['Cert Expiration Date'] = timestamp_to_YYYYMMDD(endpoint['details']['cert']['notAfter'])
        results.append(values)
    return results


def check_domain_thread(work_queue, result_queue):
    try:
        while True:
            domain = work_queue.get_nowait()
            domain_json = resultsFromCache(domain)
            result_queue.put_nowait(domain_json)
    except Queue.Empty:
        pass


def get_hostname(ip):
    # Retrieve the hostname for a single IP
    ERROR_RESULT = "UNAVAILABLE"
    try:
        hostname = socket.gethostbyname(ip)
    except:
        return ERROR_RESULT

    if hostname == ip:
        return ERROR_RESULT
    else:
        return hostname


def get_ssl_data_api(domains):
    """Retrieves SSLLabs data from the API"""
    # Spin off some threads to do the heavy lifting
    work_queue = Queue.Queue()
    result_queue = Queue.Queue()
    for domain in domains:
        work_queue.put_nowait(domain)

    if NUM_THREADS == 1:
        check_domain_thread(work_queue, result_queue)
    else:
        threads = []
        for i in range(min(NUM_THREADS, work_queue.qsize())):
            t = threading.Thread(target=check_domain_thread, args=(work_queue, result_queue))
            t.daemon = True
            t.start()
            threads.append(t)
            # Avoid sending too many queries at once
            time.sleep(2)

        prev_remaining = None
        while not work_queue.empty():
            remaining = work_queue.qsize()
            if remaining != prev_remaining:
                print_q("Domains remaining: %s" % (work_queue.qsize()))
                prev_remaining = remaining
            time.sleep(1)
        for t in threads:
            t.join()
    results = []
    while not result_queue.empty():
        result = result_queue.get()
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description='Uses the SSL Labs API v2 to scan a list of domains and stores output in a CSV.',
                                     epilog='Ex: Scan the domains in "domains.txt" and store output in "ssl_checks.csv": \
                                     python %s -i domains.txt -o ssl_checks.csv' % sys.argv[0])
    parser.add_argument('-i', '--infile', required=True, help="Specify file with list of domains")
    parser.add_argument("-o", "--output", required=True, help="File to store CSV output")
    intermediate_group = parser.add_mutually_exclusive_group()
    intermediate_group.add_argument("--write-intermediate", required=False, help="File to store JSON intermediate output")
    intermediate_group.add_argument("--read-intermediate", required=False, help="File to read JSON intermediate output")
    parser.add_argument('--quiet', help="Quiet output", action='store_true', default=False)
    options = parser.parse_args()

    global QUIET_MODE
    QUIET_MODE = options.quiet

    domains = []
    for domain in open(options.infile).read().split():
        domains.append(domain)

    if options.read_intermediate:
        print_q("Reading data from JSON file located at %s" % options.read_intermediate)
        with open(options.read_intermediate, 'rb') as fh:
            json_data = json.loads(fh.read())
    else:
        print_q("Retrieving data from OpenSSL Labs API")
        json_data = get_ssl_data_api(domains)
        print_q("Completed retrieving data from OpenSSL Labs API")
        if options.write_intermediate:
            with open(options.write_intermediate, 'wb') as fh:
                fh.write(json.dumps(json_data))
            print_q("Completed writing the OpenSSL Labs API intermediate output to %s" % options.write_intermediate)

    rows = []
    for domain_json_data in json_data:
        domain_results = parse_result(domain_json_data)
        for row_data in domain_results:
            rows.append(row_data)
    print_q("Completed parsing the OpenSSL Labs data")

    # Write the output
    fieldnames = ["Domain", "Status", "Host Status Message",
                  "Endpoint Status Message", "Hostname", "Host IP Address",
                  "NSLOOKUP Result", "Test Date", "Grade", "SSL 1.0",
                  "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2",
                  "TLS 1.3", "Has HSTS", "Vuln to BEAST", "Vuln to POODLE",
                  "Vuln to POODLE TLS", "Supports RC4", "Supports 3DES",
                  "Cert Start Date", "Cert Expiration Date"]

    with open(options.output, 'wb') as csvfile:
        resultswriter = csv.DictWriter(csvfile, fieldnames=fieldnames)
        resultswriter.writeheader()
        for row in rows:
            resultswriter.writerow(row)
    print_q("Completed writing the output to %s" % options.output)

if __name__ == "__main__":
    main()
