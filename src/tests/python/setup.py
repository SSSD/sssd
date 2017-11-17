#!/usr/bin/python
#
# Copyright (C) 2016 sssd-qe contributors.
#
from setuptools import setup

REQUIRES = [
    'paramiko',
    'PyYAML',
    'pytest_multihost',
    'pytest']

with open('README.rst', 'r') as f:
    README = f.read()

setup_args = dict(
    name='sssd.testlib',
    version='0.1-11',
    description='System Services Security Daemon python test suite',
    long_description=README,
    author=u'SSSD QE Team',
    url='http://git.app.eng.bos.redhat.com/git/sssd-qe-tests.git/',
    packages=[
        'sssd',
        'sssd.testlib',
        'sssd.testlib.common',
    ],
    package_data={'': ['LICENSE']},
    install_requires=REQUIRES,
    license='GNU GPL v3.0',
    classifiers=(
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
)
if __name__ == '__main__':
    setup(**setup_args)
