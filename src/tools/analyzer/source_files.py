from enum import Enum
import configparser
from os import listdir
from os.path import isfile, join
import glob


class Reader:
    class Component(Enum):
        NSS = 1   # NSS Responder
        PAM = 2   # PAM Responder
        BE = 3    # Backend

    def __init__(self, path):
        self.log_files = []
        self.path = self.resolve_path(path)
        self.domains = self.get_domain_logfiles()

    def __iter__(self):
        for files in self.log_files:
            try:
                with open(files) as file:
                    for line in file:
                        yield line
            except FileNotFoundError as err:
                print("Could not find domain log file, skipping")
                print(err)
                continue

    def resolve_path(self, path):
        if path.endswith("/"):
            return path
        else:
            return path + "/"

    def get_domain_logfiles(self):
        domain_files = []
        exclude_list = ["ifp", "nss", "pam", "sudo", "autofs",
                        "ssh", "pac", "kcm"]
        file_list = glob.glob(self.path + "sssd_*")
        for file in file_list:
            if not any(s in file for s in exclude_list):
                domain_files.append(file)

        return domain_files

    def set_component(self, component):
        self.log_files = []
        if component == self.Component.NSS:
            self.log_files.append(self.path + "sssd_nss.log")
        elif component == self.Component.PAM:
            self.log_files.append(self.path + "sssd_pam.log")
        elif component == self.Component.BE:
            if not self.domains:
                raise IOError
            # error: No domains found?
            for dom in self.domains:
                self.log_files.append(dom)
