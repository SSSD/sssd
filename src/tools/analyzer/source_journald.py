from systemd import journal

from sssd.source_reader import Reader

_EXE_PREFIX = "/usr/libexec/sssd/"
_NSS_MATCH = _EXE_PREFIX + "sssd_nss"
_PAM_MATCH = _EXE_PREFIX + "sssd_pam"
_BE_MATCH = _EXE_PREFIX + "sssd_be"


class Journald(Reader):
    """
    A class used to represent a Journald Reader
    """
    def __init__(self):
        super().__init__()
        self.reader = journal.Reader()
        self.reader.this_boot()
        self.reader.seek_head()

    def __iter__(self):
        """
        Yields:
            str: The next journal entry message, with timestamp if found
        """
        self.reader.seek_head()
        for entry in self.reader:
            ts = entry['__REALTIME_TIMESTAMP']
            msg = entry['MESSAGE']
            if ts:
                yield f'{ts}: {msg}'
            else:
                yield msg

    def set_component(self, component, child):
        """
        Switch the reader to interact with a certain SSSD component
        NSS, PAM, BE
        """
        self.reader.flush_matches()
        if component == self.Component.NSS:
            self.reader.add_match(_EXE=_NSS_MATCH)
        elif component == self.Component.PAM:
            self.reader.add_match(_EXE=_PAM_MATCH)
        elif component == self.Component.BE:
            self.reader.add_match(_EXE=_BE_MATCH)
