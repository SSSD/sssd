import glob
import logging

from sssd.source_reader import Reader

logger = logging.getLogger()


class Files(Reader):
    """
    A class used to represent a Log Files Reader

    Args:
        path -- the path where SSSD logs are to
           be read (default /var/log/sssd/)
    """

    def __init__(self, path):
        super().__init__()
        self.log_files = []
        self.path = self.resolve_path(path)
        self.domains = self.get_domain_logfiles()

    def __iter__(self):
        """
        Yields:
            str: The next line in the log file
        """
        for files in self.log_files:
            try:
                with open(files) as file:
                    for line in file:
                        yield line
            except Exception as e:
                logger.warning(e)
                continue

    def resolve_path(self, path):
        if path.endswith("/"):
            return path
        else:
            return path + "/"

    def get_domain_logfiles(self, child=False):
        """ Retrieve list of SSSD log files, exclude rotated (.gz) files """
        domain_files = []
        exclude_list = ["ifp", "nss", "pam", "sudo", "autofs",
                        "ssh", "pac", "kcm", ".gz"]
        if child:
            file_list = glob.glob(self.path + "*.log")
        else:
            file_list = glob.glob(self.path + "sssd_*")
        for file in file_list:
            if not any(s in file for s in exclude_list):
                domain_files.append(file)

        return domain_files

    def set_component(self, component, child):
        """
        Switch the reader to interact with a certain SSSD component
        NSS, PAM, BE
        """
        self.log_files = []
        if component == self.Component.NSS:
            self.log_files.append(self.path + "sssd_nss.log")
        elif component == self.Component.PAM:
            self.log_files.append(self.path + "sssd_pam.log")
        elif component == self.Component.BE:
            domains = self.get_domain_logfiles(child)
            if not domains:
                return
            for dom in domains:
                self.log_files.append(dom)
