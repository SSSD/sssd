import argparse

from sssd.modules import request
from sssd.parser import SubparsersAction


class Analyzer:
    def add_subcommand(self, subcmd_grp, name, help_msg, func, opts):
        """
        Add subcommand to existing subcommand group

        Args:
            name(str): Subcommand name
            help_msg(str): Help message for subcommand
            func(function): Function to call on execution
            opts(list of Object()): List of Option objects to add to subcommand
        """
        # Create parser
        req_parser = subcmd_grp.add_parser(name, help=help_msg)

        # Add subcommand options
        self._add_subcommand_options(req_parser, opts)

        # Execute func() when argument is called
        req_parser.set_defaults(func=func)

    def _add_subcommand_options(self, parser, opts):
        """
        Add subcommand options to subcommand parser

        Args:
            parser(str): Subcommand group parser
            opts(list of Object()): List of Option objects to add to subcommand
        """
        for opt in opts:
            if opt.opt_type is bool:
                if opt.short_opt is None:
                    parser.add_argument(opt.name, help=opt.help_msg,
                                        action='store_true')
                else:
                    parser.add_argument(opt.name, opt.short_opt,
                                        help=opt.help_msg, action='store_true')
            if opt.opt_type is int:
                parser.add_argument(opt.name, help=opt.help_msg,
                                    type=int)

    def load_modules(self, parser, parser_grp):
        """
        Initialize analyzer modules from modules/*

        Args:
            parser (ArgumentParser): Base parser object
            parser_grp (argparse.Action): Parser group that can have
                additional parsers attached.
        """
        # Currently only the 'request' module exists
        req = request.RequestAnalyzer()
        cli = Analyzer()

        req.setup_args(parser_grp, cli)

    def setup_args(self):
        """
        Top-level argument setup function.
        Setup analyzer argument parsers and subcommand parser/options.

        Returns:
            parser (ArgumentParser): Base parser object
        """
        # top level parser
        formatter = argparse.RawTextHelpFormatter
        parser = argparse.ArgumentParser(description='Analyzer tool to assist '
                                         'with SSSD log parsing',
                                         formatter_class=formatter)
        parser.add_argument('--source', default='files', choices=['files',
                            'journald'])
        parser.add_argument('--logdir', default='/var/log/sssd/',
                            help='SSSD Log directory to parse log files from')

        # Modules parser group
        subparser = parser.add_subparsers(title=None,
                                          action=SubparsersAction,
                                          metavar='COMMANDS')
        parser_grp = subparser.add_parser_group('Modules')

        # Load modules, subcommands are added in module.setup_args()
        self.load_modules(parser, parser_grp)

        return parser

    def main(self):
        parser = self.setup_args()
        args = parser.parse_args()

        if not hasattr(args, 'func'):
            parser.print_help()
            return 0

        args.func(args)


def run():
    analyzer = Analyzer()
    analyzer.main()
