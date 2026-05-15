import argparse


# Based on patch from https://bugs.python.org/issue9341
class SubparsersAction(argparse._SubParsersAction):
    """
    Provide a subparser action that can create subparsers with ability of
    grouping arguments.

    It is based on the patch from:

        - https://bugs.python.org/issue9341
    """

    class _PseudoGroup(argparse.Action):
        def __init__(self, container, title):
            super().__init__(option_strings=[], dest=title)
            self.container = container
            self._choices_actions = []

        def add_parser(self, name, **kwargs):
            # add the parser to the main Action, but move the pseudo action
            # in the group's own list
            parser = self.container.add_parser(name, **kwargs)
            choice_action = self.container._choices_actions.pop()
            self._choices_actions.append(choice_action)
            return parser

        def _get_subactions(self):
            return self._choices_actions

        def add_parser_group(self, title):
            # the formatter can handle recursive subgroups
            grp = SubparsersAction._PseudoGroup(self, title)
            self._choices_actions.append(grp)
            return grp

    def add_parser_group(self, title):
        """
        Add new parser group.

        :param title: Title.
        :type title: str
        :return: Parser group that can have additional parsers attached.
        :rtype: ``argparse.Action`` extended with ``add_parser`` method
        """
        grp = self._PseudoGroup(self, title)
        self._choices_actions.append(grp)
        return grp


class Option:
    """
    Group option attributes for command/subcommand options
    """
    def __init__(self, name, help_msg, opt_type, short_opt=None):
        self.name = name
        self.short_opt = short_opt
        self.help_msg = help_msg
        self.opt_type = opt_type
