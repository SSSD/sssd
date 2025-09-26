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


def get_fedora_releases(type, exclude=[]):
    r = requests.get(f'https://bodhi.fedoraproject.org/releases?state={type}')
    r.raise_for_status()

    versions = [x['version'] for x in r.json()['releases'] if x['id_prefix'] == 'FEDORA']
    versions = list(set(versions) - set(exclude))
    versions.sort()

    return versions


def get_fedora_matrix():
    fedora_stable = get_fedora_releases('current')
    fedora_devel = get_fedora_releases('pending', exclude=['eln'])
    fedora_frozen = get_fedora_releases('frozen', exclude=['eln'])

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

    fedora = sorted(get_fedora_matrix())
    centos = sorted(get_centos_matrix())

    matrix = {
        'intgcheck': [*fedora, *centos],
        'multihost': [*fedora, *centos],
    }

    print(json.dumps(matrix, indent=2))

    if args.action:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            f.write(f'matrix={json.dumps(matrix)}')
