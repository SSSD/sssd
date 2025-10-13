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


def get_fedora_matrix():
    # Fedora 41 and up are using 2.10, F39 is going out of support
    return ['fedora-40']


def get_centos_matrix():
    return ['centos-8']


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get GitHub actions CI matrix')
    parser.add_argument('--action', action='store_true', help='It is run in GitHub actions mode')
    args = parser.parse_args()

    centos = sorted(get_centos_matrix())

    matrix = {
        'intgcheck': [*centos],
        'multihost': [*centos],
    }

    print(json.dumps(matrix, indent=2))

    if args.action:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f'matrix={json.dumps(matrix)}')
