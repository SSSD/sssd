#!/bin/python3

import sys
import argparse
import re

import source_files
import module_request


def add_options():
    parser = argparse.ArgumentParser('sss_analyze')
    parser.add_argument(
            '--source', action='store', type=str, default='files',
            choices=['files', 'journald']
    )
    parser.add_argument(
            '--logdir', action='store', type=str, default='/var/log/sssd/'
    )
    return parser


def load_module(module, parser):
    if module == 'request':
        analyzer = module_request.Analyzer()
    else:
        return
    analyzer.add_options(parser)
    return analyzer


def main():
    parser = add_options()

    module = load_module('request', parser)

    ns = parser.parse_args()
    args = vars(ns)
    path = args['logdir']

    if args['source'] == "journald":
        import source_journald
        reader = source_journald.Reader()
    else:
        reader = source_files.Reader(path)

    module.execute(reader, args)


if __name__ == '__main__':
    main()
