#!/usr/bin/python3
#
# Get matrix for CI GitHub Actions workflow.
#
# Return a JSON-formatted matrix, a list of distributions where CI workflow
# should run.
#


import json
import requests
import requests.adapters
import argparse
import os

import urllib3.util


def requests_session():
    s = requests.Session()
    retry = urllib3.util.Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[408, 429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("https://", requests.adapters.HTTPAdapter(max_retries=retry))
    return s


def get_fedora_releases(session, type, exclude=[]):
    r = session.get(f'https://bodhi.fedoraproject.org/releases?state={type}', timeout=(10, 30))
    r.raise_for_status()

    versions = [x['version'] for x in r.json()['releases'] if x['id_prefix'] == 'FEDORA']
    versions = list(set(versions) - set(exclude))
    versions.sort()

    return versions


def get_fedora_matrix():
    session = requests_session()
    fedora_stable = get_fedora_releases(session, 'current')
    fedora_devel = get_fedora_releases(session, 'pending', exclude=['eln'])
    fedora_frozen = get_fedora_releases(session, 'frozen', exclude=['eln'])

    matrix = []
    matrix.extend(['fedora-{0}'.format(x) for x in fedora_stable])
    matrix.extend(['fedora-{0}'.format(x) for x in fedora_devel])
    matrix.extend(['fedora-{0}'.format(x) for x in fedora_frozen])

    return matrix


def get_centos_matrix():
    return ['centos-10']


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
