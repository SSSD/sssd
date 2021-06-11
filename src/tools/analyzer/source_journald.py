from systemd import journal

from enum import Enum

_EXE_PREFIX = "/usr/libexec/sssd/"
_NSS_MATCH = _EXE_PREFIX + "sssd_nss"
_PAM_MATCH = _EXE_PREFIX + "sssd_pam"
_BE_MATCH = _EXE_PREFIX + "sssd_be"


class Reader:
    class Component(Enum):
        NSS = 1   # NSS Responder
        PAM = 2   # PAM Responder
        BE = 3    # Backend

    def __init__(self):
        self.reader = journal.Reader()
        self.reader.this_boot()

    def __iter__(self):
        for entry in self.reader:
            yield entry['MESSAGE']

    def set_component(self, component):
        if component == self.Component.NSS:
            self.reader.add_match(_EXE=_NSS_MATCH)
        elif component == self.Component.PAM:
            self.reader.add_match(_EXE=_PAM_MATCH)
        elif component == self.Component.BE:
            self.reader.add_match(_EXE=_BE_MATCH)
