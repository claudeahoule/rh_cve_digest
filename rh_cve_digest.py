#!/usr/bin/env python
"""Print a CSV digest of recent Red Hat security advisories.

Usage:
    rh_cve_digest.py [-c CONFIG] > digest.csv

Config file (JSON, all keys optional):
    {
        "days": 3,
        "exclude_products": ["Red Hat Enterprise Linux 6", "Ansible"],
        "https_proxy": "http://yourproxy.example.com:8000"
    }
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta

import requests

API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'

DEFAULT_DAYS = 1


def load_config(path):
    """Load the JSON config file; return defaults if no path is given."""
    config = {'days': DEFAULT_DAYS, 'exclude_products': [], 'https_proxy': None}
    if not path:
        return config

    try:
        with open(path) as f:
            user_config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print('ERROR: Could not read config file {}: {}'.format(path, e),
              file=sys.stderr)
        sys.exit(1)

    config.update(user_config)

    try:
        config['days'] = int(config['days'])
    except (TypeError, ValueError):
        print('ERROR: "days" in config must be an integer.', file=sys.stderr)
        sys.exit(1)

    if not isinstance(config['exclude_products'], list):
        print('ERROR: "exclude_products" in config must be a list.',
              file=sys.stderr)
        sys.exit(1)

    return config


def get_data(query, proxies, exit_on_error=True):
    full_query = API_HOST + query
    r = requests.get(full_query, proxies=proxies)

    if r.status_code != 200:
        msg = ('ERROR: Invalid request; returned {} for the following '
               'query:\n{}'.format(r.status_code, full_query))
        print(msg, file=sys.stderr)
        if exit_on_error:
            sys.exit(1)
        return None

    data = r.json()
    if not data:
        print('No data returned with the following query:\n{}'.format(full_query),
              file=sys.stderr)
        if exit_on_error:
            sys.exit(0)
        return None

    return data


def is_excluded(product_name, exclusions):
    """Case-insensitive substring match against the exclusion list."""
    name = product_name.lower()
    return any(excl.lower() in name for excl in exclusions)


def get_products(advisory_data):
    """Return the de-duplicated, ordered list of product names for an advisory."""
    products = []
    for product_branch in advisory_data.get('product_tree', {}).get('branches', []):
        sub_branches = product_branch.get('branches', [])
        if not sub_branches:
            continue
        for inner_branch in sub_branches[0].get('branches', []):
            name = inner_branch.get('name')
            if name and name not in products:
                products.append(name)
    return products


def get_cves(advisory_data):
    """Return the CVE IDs listed in the advisory's CSAF vulnerabilities."""
    cves = []
    for vuln in advisory_data.get('vulnerabilities', []):
        cve = vuln.get('cve')
        if cve and cve not in cves:
            cves.append(cve)
    return cves


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-c', '--config', help='Path to JSON config file')
    args = parser.parse_args()

    config = load_config(args.config)
    proxies = {'https': config['https_proxy']} if config['https_proxy'] else {}

    date = datetime.now() - timedelta(days=config['days'])
    params = 'after=' + str(date.date())

    data = get_data('/csaf.json?' + params, proxies)

    writer = csv.writer(sys.stdout)
    writer.writerow(['RHSA', 'severity', 'released_on', 'product', 'CVEs'])

    for advisory in data:
        advisory_data = get_data('/csaf/' + advisory['RHSA'] + '.json',
                                 proxies, exit_on_error=False)
        if not advisory_data:
            continue

        cves = ' '.join(get_cves(advisory_data))

        for product in get_products(advisory_data):
            if is_excluded(product, config['exclude_products']):
                continue
            writer.writerow([advisory['RHSA'], advisory['severity'],
                             advisory['released_on'], product, cves])


if __name__ == '__main__':
    main()
