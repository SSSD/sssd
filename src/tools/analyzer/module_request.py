import re
from enum import Enum

import source_files


class Analyzer:
    """ Request tracking module """
    def add_options(self, parser):
        subparser = parser.add_subparsers(dest='subcommand', metavar=None,
                                          required=True)
        request_parser = subparser.add_parser('request', help='Track requests'
                                              ' across SSSD components')
        request_parser.add_argument("--list",
                                    help="List recent client requests",
                                    action="store_true")
        request_parser.add_argument("--cid",
                                    help="Print logs related to the "
                                    "provided Client ID")
        request_parser.add_argument("--pam",
                                    help="Use with --cid to track PAM related "
                                    "requests", action="store_true")
        request_parser.add_argument("--cachereq",
                                    help="Include cache request related logs",
                                    action="store_true")

    # retrieve list of associated REQ_TRACE ids
    def get_linked_ids(self, client_id, source, pattern, regex):
        linked_ids = []
        for line in source:
            re_obj = re.compile(pattern)
            if re_obj.search(line):
                # exclude backtrace logs
                if line.startswith('   *  '):
                    continue
                cr_re = re.compile(regex)
                match = cr_re.search(line)
                if match:
                    found = match.group(0)
                    linked_ids.append(found)
        return linked_ids

    # iterate through source and search for any number of patterns in list
    def print_pattern_match(self, patterns, source):
        for line in source:
            for pattern in patterns:
                re_obj = re.compile(pattern)
                if re_obj.search(line):
                    # exclude backtrace logs
                    if line.startswith('   *  '):
                        continue
                    # files source includes newline
                    if type(source) == source_files.Reader:
                        print(line, end='')
                    else:
                        print(line)

    def execute(self, source, options):
        if options['list']:
            self.list_requests(source, options['pam'])
        elif options['cid']:
            self.track_request(source, options)

    def list_requests(self, source, pam):
        component = source.Component.NSS
        resp = "nss"
        pattern = ['\[cmd']
        if pam:
            component = source.Component.PAM
            resp = "pam"

        print(f"******** Listing {resp} client requests ********")
        source.set_component(component)
        self.print_pattern_match(pattern, source)

    def track_request(self, source, options):
        client_id = options['cid']
        component = source.Component.NSS
        resp = "nss"
        pattern = [f'REQ_TRACE.*\[CID #{client_id}\\]']

        if options['pam']:
            component = source.Component.PAM
            resp = "pam"

        print(f"******** Checking {resp} responder for Client ID"
              "{client_id} *******")
        source.set_component(component)
        if options['cachereq']:
            cr_id_regex = 'CR #[0-9]+'
            cr_ids = self.get_linked_ids(client_id, source,
                                         pattern[0], cr_id_regex)
            [pattern.append(f'{id}\:') for id in cr_ids]

        self.print_pattern_match(pattern, source)

        print(f"********* Checking Backend for Client ID {client_id} ********")
        pattern = [f'REQ_TRACE.*\[sssd.{resp} CID #{client_id}\]']
        source.set_component(source.Component.BE)

        be_id_regex = '\[RID#[0-9]+\]'
        be_ids = self.get_linked_ids(client_id, source,
                                     pattern[0], be_id_regex)
        [pattern.append(f'\\{id}') for id in be_ids]
        self.print_pattern_match(pattern, source)
