#!/usr/bin/python3
#
# Get matrix for CI GitHub Actions workflow.
#
# Return a JSON-formatted matrix, a list of distributions where CI workflow
# should run.
#


import json
import requests
import argparse
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get GitHub actions CI matrix')
    parser.add_argument('--action', action='store_true', help='It is run in GitHub actions mode')
    args = parser.parse_args()

    matrix = {
        'intgcheck': ['centos-9', 'debian-latest'],
        'multihost': ['centos-9'],
    }

    print(json.dumps(matrix, indent=2))

    if args.action:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f'matrix={json.dumps(matrix)}')
