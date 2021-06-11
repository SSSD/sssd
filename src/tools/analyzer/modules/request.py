import re
import copy
import click
import logging

from enum import Enum
from source_files import Files
from source_journald import Journald

logger = logging.getLogger()


@click.group(help="Request module")
def request():
    pass


@request.command()
@click.option("-v", "--verbose", is_flag=True, help="Enables verbose output")
@click.option("--pam", is_flag=True, help="Filter only PAM requests")
@click.pass_obj
def list(ctx, verbose, pam):
    analyzer = RequestAnalyzer()
    source = analyzer.load(ctx)
    analyzer.list_requests(source, verbose, pam)


@request.command()
@click.argument("cid", nargs=1, type=int, required=True)
@click.option("--merge", is_flag=True, help="Merge logs together sorted"
              " by timestamp (requires debug_microseconds = True)")
@click.option("--cachereq", is_flag=True, help="Include cache request "
              "related logs")
@click.option("--pam", is_flag=True, help="Track only PAM requests")
@click.pass_obj
def show(ctx, cid, merge, cachereq, pam):
    analyzer = RequestAnalyzer()
    source = analyzer.load(ctx)
    analyzer.track_request(source, cid, merge, cachereq, pam)


class RequestAnalyzer:
    """
    A request analyzer module, handles request tracking logic
    and analysis. Parses input generated from a source Reader.
    """
    consumed_logs = []
    done = ""

    def load(self, ctx):
        """
        Load the appropriate source reader.

        Args:
            ctx (click.ctx): command line state object

        Returns:
            Instantiated source object
        """
        if ctx.source == "journald":
            import source_journald
            source = Journald()
        else:
            source = Files(ctx.logdir)
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
            if isinstance(source, Files):
                print(line, end='')
            else:
                print(line)
        return found_results

    def print_formatted(self, line, verbose):
        """
        Parse line and print formatted list_requests output

        Args:
            line (str): line to parse
            verbose (bool): If true, enable verbose output
        """
        plugin = ""
        name = ""
        id = ""

        # exclude backtrace logs
        if line.startswith('   *  '):
            return
        fields = line.split("[")
        cr_field = fields[2].split(":")[1]
        cr = cr_field[5:]
        if "refreshed" in line:
            return
        # CR Plugin name
        if re.search("cache_req_send", line):
            plugin = line.split('\'')[1]
        # CR Input name
        elif re.search("cache_req_process_input", line):
            name = line.rsplit('[')[-1]
        # CR Input id
        elif re.search("cache_req_search_send", line):
            id = line.rsplit()[-1]
        # CID and client process name
        else:
            ts = line.split(")")[0]
            ts = ts[1:]
            fields = line.split("[")
            cid = fields[3][5:-1]
            cmd = fields[4][4:-1]
            uid = fields[5][4:-1]
            if not uid.isnumeric():
                uid = fields[6][4:-1]
            print(f'{ts}: [uid {uid}] CID #{cid}: {cmd}')

        if verbose:
            if plugin:
                print("   - " + plugin)
            if name:
                if cr not in self.done:
                    print("       - " + name[:-2])
                    self.done = cr
            if id:
                if cr not in self.done:
                    print("       - " + id)
                    self.done = cr

    def list_requests(self, source, verbose, pam):
        """
        List component (default: NSS) responder requests

        Args:
            line (str): line to process
            source (Reader): source Reader object
            verbose (bool): True if --verbose cli option is provided, enables
                verbose output
            pam (bool): True if --pam cli option is provided, list requests
                in the PAM responder only
        """
        component = source.Component.NSS
        resp = "nss"
        patterns = ['\[cmd']
        patterns.append("(cache_req_send|cache_req_process_input|"
                        "cache_req_search_send)")
        consume = True
        if pam:
            component = source.Component.PAM
            resp = "pam"

        logger.info(f"******** Listing {resp} client requests ********")
        source.set_component(component)
        self.done = ""
        # For each CID
        for line in self.matched_line(source, patterns):
            if isinstance(source, Journald):
                print(line)
            else:
                self.print_formatted(line, verbose)

    def track_request(self, source, cid, merge, cachereq, pam):
        """
        Print Logs pertaining to individual SSSD client request

        Args:
            source (Reader): source Reader object
            cid (int): client ID number to show
            merge (bool): True when --merge is provided, merge logs together
                by timestamp
            pam (bool): True if --pam cli option is provided, track requests
                in the PAM responder
        """
        resp_results = False
        be_results = False
        component = source.Component.NSS
        resp = "nss"
        pattern = [f'REQ_TRACE.*\[CID #{cid}\\]']
        pattern.append(f"\[CID #{cid}\\].*connected")

        if pam:
            component = source.Component.PAM
            resp = "pam"
            pam_data_regex = f'pam_print_data.*\[CID #{cid}\]'

        logger.info(f"******** Checking {resp} responder for Client ID"
                    f" {cid} *******")
        source.set_component(component)
        if cachereq:
            cr_id_regex = 'CR #[0-9]+'
            cr_ids = self.get_linked_ids(source, pattern, cr_id_regex)
            [pattern.append(f'{id}\:') for id in cr_ids]

        for match in self.matched_line(source, pattern):
            resp_results = self.consume_line(match, source, merge)

        logger.info(f"********* Checking Backend for Client ID {cid} ********")
        pattern = [f'REQ_TRACE.*\[sssd.{resp} CID #{cid}\]']
        source.set_component(source.Component.BE)

        be_id_regex = '\[RID#[0-9]+\]'
        be_ids = self.get_linked_ids(source, pattern, be_id_regex)

        pattern.clear()
        [pattern.append(f'\\{id}') for id in be_ids]

        if pam:
            pattern.append(pam_data_regex)
        for match in self.matched_line(source, pattern):
            be_results = self.consume_line(match, source, merge)

        if merge:
            # sort by date/timestamp
            sorted_list = sorted(self.consumed_logs,
                                 key=lambda s: s.split(')')[0])
            for entry in sorted_list:
                print(entry)
        if not resp_results and not be_results:
            logger.warn(f"ID {cid} not found in logs!")
