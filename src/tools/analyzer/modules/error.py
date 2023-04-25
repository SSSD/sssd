from sssd import util
from sssd.parser import SubparsersAction
from sssd import sss_analyze

class ErrorAnalyzer:
    """
    An error analyzer module, list if there is any error reported by sssd_be
    """
    module_parser = None
    print_opts = []

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
        desc = "Analyze error check module"
        self.module_parser = parser_grp.add_parser('error',
                                                   description=desc,
                                                   help='Error checker')

        subparser = self.module_parser.add_subparsers(title=None,
                                                      dest='subparser',
                                                      action=SubparsersAction,
                                                      metavar='COMMANDS')

        subcmd_grp = subparser.add_parser_group('Operation Modes')
        cli.add_subcommand(subcmd_grp, 'list', 'Print error messages found in backend',
                           self.print_error, self.print_opts)

        self.module_parser.set_defaults(func=self.print_module_help)

        return self.module_parser

    def print_error(self, args):
        err = 0
        utl = util.Utils()
        source = utl.load(args)
        component = source.Component.BE
        source.set_component(component, False)
        patterns = ['sdap_async_sys_connect request failed', 'terminated by own WATCHDOG',
            'ldap_sasl_interactive_bind_s failed', 'Communication with KDC timed out', 'SSSD is offline', 'Backend is offline',
            'tsig verify failure', 'ldap_install_tls failed', 's2n exop request failed']
        for line in utl.matched_line(source, patterns):
            err +=1
            print(line)
        if err > 0:
            print("For possible solutions please refer to https://sssd.io/troubleshooting/errors.html")
        return
