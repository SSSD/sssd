import re
import logging

from sssd.source_files import Files
from sssd.source_journald import Journald

logger = logging.getLogger()


class Utils:

    def load(self, args):
        """
        Load the appropriate source reader.

        Args:
            args (Namespace): argparse parsed arguments

        Returns:
            Instantiated source object
        """
        if args.source == "journald":
            source = Journald()
        else:
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
