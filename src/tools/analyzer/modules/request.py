import re
import logging

from sssd.parser import SubparsersAction
from sssd.parser import Option

logger = logging.getLogger()


class RequestAnalyzer:
    """
    A request analyzer module, handles request tracking logic
    and analysis. Parses input generated from a source Reader.
    """
    module_parser = None
    consumed_logs = []
    list_opts = [
        Option('--verbose', 'Verbose output', bool, '-v'),
        Option('--pam', 'Filter only PAM requests', bool),
    ]

    show_opts = [
        Option('cid', 'Track request with this ID', int),
        Option('--child', 'Include child process logs', bool),
        Option('--merge', 'Merge logs together sorted by timestamp', bool),
        Option('--pam', 'Track only PAM requests', bool),
    ]

    def print_module_help(self, args):
        """
        Print the module parser help output

        Args:
            args (Namespace): argparse parsed arguments
        """
        self.module_parser.print_help()

    def setup_args(self, parser_grp, cli):
        """
        Setup module parser, subcommands, and options

        Args:
            parser_grp (argparse.Action): Parser group to nest
               module and subcommands under
        """
        desc = "Analyze request tracking module"
        self.module_parser = parser_grp.add_parser('request',
                                                   description=desc,
                                                   help='Request tracking')

        subparser = self.module_parser.add_subparsers(title=None,
                                                      dest='subparser',
                                                      action=SubparsersAction,
                                                      metavar='COMMANDS')

        subcmd_grp = subparser.add_parser_group('Operation Modes')
        cli.add_subcommand(subcmd_grp, 'list', 'List recent requests',
                           self.list_requests, self.list_opts)
        cli.add_subcommand(subcmd_grp, 'show', 'Track individual request ID',
                           self.track_request, self.show_opts)

        self.module_parser.set_defaults(func=self.print_module_help)

        return self.module_parser

    def load(self, args):
        """
        Load the appropriate source reader.

        Args:
            args (Namespace): argparse parsed arguments

        Returns:
            Instantiated source object
        """
        if args.source == "journald":
            from sssd.source_journald import Journald
            source = Journald()
        else:
            from sssd.source_files import Files
            source = Files(args.logdir)
        return source

    def matched_line(self, source, patterns):
        """
        Yield lines which match any number of patterns (OR) in
        provided patterns list.

        Args:
            source (Reader): source Reader object
        Yields:
            lines matching the provided pattern(s)
        """
        for line in source:
            for pattern in patterns:
                re_obj = re.compile(pattern)
                if re_obj.search(line):
                    if line.startswith('   *  '):
                        continue
                    yield line

    def get_linked_ids(self, source, pattern, regex):
        """
        Retrieve list of associated REQ_TRACE ids. Filter
        only source lines by pattern, then parse out the
        linked id with the provided regex.

        Args:
            source (Reader): source Reader object
            pattern (list of str): regex pattern(s) used for finding
                 linked ids
            regex (str): regular expression used to extract linked id

        Returns:
            List of linked ids discovered
        """
        linked_ids = []
        for match in self.matched_line(source, pattern):
            id_re = re.compile(regex)
            match = id_re.search(match)
            if match:
                found = match.group(0)
                linked_ids.append(found)
        return linked_ids

    def consume_line(self, line, source, consume):
        """
        Print or consume a line, if merge cli option is provided then consume
        boolean is set to True

        Args:
            line (str): line to process
            source (Reader): source Reader object
            consume (bool): If True, line is added to consume_logs
               list, otherwise print line

        Returns:
            True if line was processed, otherwise False
        """
        found_results = True
        if consume:
            self.consumed_logs.append(line.rstrip(line[-1]))
        else:
            # files source includes newline
            if type(source).__name__ == 'Files':
                print(line, end='')
            else:
                print(line)
        return found_results

    def print_formatted_verbose(self, source, patterns):
        """
        Parse line and print formatted verbose list_requests output

        Args:
            source (Reader): source Reader object
            patterns (list): List of regex patterns to use for
                matching lines
        """
        # Get CID number, and print the basic line first
        for line in self.matched_line(source, patterns):
            cid = self.print_formatted(line)

            # Loop through each line with this CID number to extract and
            # print the verbose data needed
            verbose_patterns = ["(cache_req_send|cache_req_process_input|"
                                "cache_req_search_send)"]
            for cidline in self.matched_line(source, verbose_patterns):
                plugin = ""
                name = ""
                id = ""

                # skip any lines not pertaining to this CID
                if f"CID#{cid}]" not in cidline:
                    continue
                if "refreshed" in cidline:
                    continue
                # CR Plugin name
                if re.search("cache_req_send", cidline):
                    plugin = cidline.split('\'')[1]
                # CR Input name
                elif re.search("cache_req_process_input", cidline):
                    name = cidline.rsplit('[')[-1]
                # CR Input id
                elif re.search("cache_req_search_send", cidline):
                    id = cidline.rsplit()[-1]

                if plugin:
                    print("   - " + plugin)
                if name:
                    print("       - " + name[:-2])
                if (id and ("UID" in cidline or "GID" in cidline)):
                    print("       - " + id)

    def print_formatted(self, line):
        """
        Parse line and print formatted list_requests output

        Args:
            line (str): line to parse
        Returns:
            Client ID from printed line, 0 otherwise
        """
        # exclude backtrace logs
        if line.startswith('   *  '):
            return 0
        if "refreshed" in line:
            return 0
        ts = line.split(")")[0]
        ts = ts[1:]
        fields = line.split("[")
        cid = fields[3][4:-9]
        cmd = fields[4][4:-1]
        uid = fields[5][4:-1]
        if not uid.isnumeric():
            uid = fields[6][4:-1]
        print(f'{ts}: [uid {uid}] CID #{cid}: {cmd}')
        return cid

    def list_requests(self, args):
        """
        List component (default: NSS) responder requests

        Args:
            args (Namespace):  populated argparse namespace
        """
        source = self.load(args)
        component = source.Component.NSS
        resp = "nss"
        # Log messages matching the following regex patterns contain
        # the useful info we need to produce list output
        patterns = [r'\[cmd']
        if args.pam:
            component = source.Component.PAM
            resp = "pam"

        logger.info(f"******** Listing {resp} client requests ********")
        source.set_component(component, False)

        if args.verbose:
            self.print_formatted_verbose(source, patterns)
        else:
            for line in self.matched_line(source, patterns):
                if type(source).__name__ == 'Journald':
                    print(line)
                else:
                    self.print_formatted(line)

    def track_request(self, args):
        """
        Print Logs pertaining to individual SSSD client request

        Args:
            args (Namespace):  populated argparse namespace
        """
        source = self.load(args)
        cid = args.cid
        resp_results = False
        be_results = False
        component = source.Component.NSS
        resp = "nss"
        pattern = [rf'REQ_TRACE.*\[CID #{cid}\]']
        pattern.append(rf"\[CID#{cid}\]")

        if args.pam:
            component = source.Component.PAM
            resp = "pam"

        logger.info(f"******** Checking {resp} responder for Client ID"
                    f" {cid} *******")
        source.set_component(component, args.child)
        for match in self.matched_line(source, pattern):
            resp_results = self.consume_line(match, source, args.merge)

        logger.info(f"********* Checking Backend for Client ID {cid} ********")
        pattern = [rf'REQ_TRACE.*\[sssd.{resp} CID #{cid}\]']
        source.set_component(source.Component.BE, args.child)

        be_id_regex = r'\[RID#[0-9]+\]'
        be_ids = self.get_linked_ids(source, pattern, be_id_regex)

        pattern.clear()
        [pattern.append(f'\\{id}') for id in be_ids]

        for match in self.matched_line(source, pattern):
            be_results = self.consume_line(match, source, args.merge)

        if args.merge:
            # sort by date/timestamp
            sorted_list = sorted(self.consumed_logs,
                                 key=lambda s: s.split(')')[0])
            for entry in sorted_list:
                print(entry)
        if not resp_results and not be_results:
            logger.warn(f"ID {cid} not found in logs!")
