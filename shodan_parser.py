#!/usr/bin/env python3
#
# shodan_parser.py
#
# Parses Shodan JSON output to several CSV files:
#  1. A list of IP addresses and open ports - <output base name>_ports.csv
#  2. A list of vulnerabilities - <output base name>_vulns.csv
#  3. A list of HTTP servers - <output base name>_http.csv
#  4. A list of accessible IP addresses - <output base name>_ips.txt
# 
# Usage:
# shodan_parser.py <shodan file> <output base name>
#

import argparse
import csv
import ipaddress
import json
import os

port_fields = [
    'ip',
    'ip_str',
    'transport',
    'port',
    'product',
    'hostnames',
    'cpe',
    'timestamp'
]

http_fields = [
    'host',
    'title',
    'server',
    'robots',
    'location',
    'waf'
]

vulnerability_fields = [
    'ip_str',
    'transport',
    'port',
    'cve',
    'verified',
    'cvss',
    'summary'
]

def write_csv(file, data, fields):
    with open(file, 'w', newline='', encoding="utf-8") as csv_fd:
        csvwriter = csv.DictWriter(csv_fd, fieldnames=fields, dialect='excel')
        data = [x for x in data if x is not None]  # remove null values
        csvwriter.writeheader()
        for d in data:
            csvwriter.writerow(d)


def main():
    parser = argparse.ArgumentParser("Shodan Parser")
    parser.add_argument("input_file", nargs=1, help="Shodan output source file")
    parser.add_argument("output_base", nargs=1, help="Output file base name")
    args = parser.parse_args()

    input_file = args.input_file[0]
    output_base = args.output_base[0]

    print("[*] input file = {}".format(input_file))
    print("[*] output base name = {}".format(output_base))

    with open(input_file, 'r') as json_fd:
        json_lines = json_fd.readlines()
    
    ports = []
    http = []
    vulns = []
    addresses = set()
    for l in json_lines:
        json_obj = json.loads(l)
        # port information
        port_data_dict = {}
        for f in port_fields:
            try:
                if type(json_obj[f]) != list:
                    port_data_dict[f] = json_obj[f]
                else:
                    values = json_obj[f]
                    port_data_dict[f] = ','.join(values)
            except:
                continue
        ports.append(port_data_dict)
        
        # http information
        http_data_dict = None
        if 'http' in json_obj.keys():
            http_data_dict = {}
            for f in http_fields:
                try:
                    if type(json_obj['http'][f]) != list:
                        http_data_dict[f] = json_obj['http'][f]
                    else:
                        values = json_obj['http'][f]
                        http_data_dict[f] = ','.join(values)
                except:
                    continue
        http.append(http_data_dict)
        
        vuln_data_dict = None
        if 'vulns' in json_obj.keys():
            for v in json_obj['vulns'].keys():
                vuln_data_dict = {}
                try:
                    for f in vulnerability_fields:
                        vuln_data_dict[f] = port_data_dict[f]
                except:
                    pass
                vuln_data_dict['cve'] = v
                vuln_data_dict['verified'] = json_obj['vulns'][v]['verified']
                vuln_data_dict['cvss'] = json_obj['vulns'][v]['cvss']
                vuln_data_dict['summary'] = json_obj['vulns'][v]['summary']
                # print("DEBUG vuln_data_dict = {}".format(vuln_data_dict))
                vulns.append(vuln_data_dict)
        
    # create the list of addresses
    for p in ports:
        addresses.add(p['ip_str'])
    
    # print a summary of what was found
    print("Parsed {} IP addresses, {} port entries, {} http entries, {} vulnerabilities".format(len(list(addresses)), len(ports), len(http), len(vulns)))

    # output
    port_output_file = "{}_ports.csv".format(output_base)
    http_output_file = "{}_http.csv".format(output_base)
    vuln_output_file = "{}_vulns.csv".format(output_base)
    addr_output_file = "{}_ips.txt".format(output_base)

    write_csv(port_output_file, ports, port_fields)
    write_csv(http_output_file, http, http_fields)
    write_csv(vuln_output_file, vulns, vulnerability_fields)

    with open(addr_output_file, 'w') as ip_fd:
        for a in sorted(list(addresses)):
            ip_fd.write(a + "\n")


if __name__ == "__main__":
    main()
