"""
Module with extensions to the pytest_multihost
"""

import time
import logging
import pytest
import pytest_multihost.config
import pytest_multihost.host
from .exceptions import SSSDException


class QeConfig(pytest_multihost.config.Config):
    """QeConfig subclass of multihost plugin to extend functionality."""

    extra_init_args = {'directory_manager', 'directory_password',
                       'rootdn', 'rootdn_pwd'}

    def __init__(self, **kwargs):
        self.log = self.get_logger(f'{__name__}.{type(self).__name__}')
        pytest_multihost.config.Config.__init__(self, **kwargs)

    def get_domain_class(self):
        """return custom domain class.

        This is needed to fully extend the config for custom
        multihost plugin extensions.

        Args:
            None

        Returns:
            None
        """
        return QeDomain

    def get_logger(self, name):
        """Override get_logger to set logging level.

        Args:
            name (str): Name of the logger

        Returns:
            log (obj): Logger object
        """
        log = logging.getLogger(name)
        log.propagate = False
        if not log.handlers:
            # set log Level
            log.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            # set formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            log.addHandler(handler)
        return log

    def filter(self, descriptions):
        """
        Override default behavior to not filter hosts, so that it can work
        with dynamic topologies.
        """
        return


class QeBaseHost(pytest_multihost.host.BaseHost):
    """QeBaseHost subclass of multihost plugin BaseHost class."""


class QeHost(QeBaseHost):
    """QeHost subclass of multihost plugin host class.

    This extends functionality of the host class for SSSD QE purposes.
    Here we add support functions that will be very widely used across
    tests and must be run on any or all hosts in the environment.
    """

    @property
    def sys_hostname(self):
        """Get system hostname

        Args:
            None

        Returns:
            str: System hostname
        """
        cmd = self.run_command(['hostname'], raiseonerr=False)
        output = cmd.stdout_text.strip()
        if '\n' in output:
            ret = output.split('\n')
            name = (ret[len(ret) - 1])
            return name
        return cmd.stdout_text.strip()

    @property
    def fips(self):
        """ Check if system is fips enabled """
        fips_check_cmd = "fips-mode-setup --is-enabled"
        cmd = self.run_command(fips_check_cmd, raiseonerr=False)
        return bool(cmd.returncode != 0)

    @property
    def distro(self):
        """ Get contents of /etc/redhat-release

            :param None:
            :return str: contents of /etc/redhat-release
        """
        cmd = self.run_command(['cat', '/etc/redhat-release'],
                               raiseonerr=False)
        if cmd.returncode != 0:
            return 'Unknown Distro'
        return cmd.stdout_text.strip()

    def package_mgmt(self, package, action='install'):
        """ Install packages
            : param str package: Package name or list of packages
            : param str action: Install/uninstall/update
            : return str: Return code of the yum remove command
        """
        if 'Fedora' in self.distro or '8.' in self.distro or\
                '9.' in self.distro or '10.' in self.distro:
            pkg_cmd = 'dnf'
        else:
            pkg_cmd = 'yum'
        pkg_install_cmd = f'{pkg_cmd} -y {action} {package}'
        cmd = self.run_command(pkg_install_cmd, raiseonerr=False)
        return bool(cmd.returncode == 0)

    def service_sssd(self, action):
        """ Start/stop/restart sssd service based on RHEL Version
            :param str action: Action to be performed (start/stop/restart)
            :return: str Return code of the systemctl/service command
            :Exception Raises exception
        """
        # For Fedora, Atomic and RHELs 7, 8, 9 this should work.
        service_command = f'systemctl {action} sssd'
        if 'Red Hat Enterprise Linux' in self.distro and ' 6.' in self.distro:
            # RHEL 6 needs service command
            service_command = f"service sssd {action}"
        cmd = self.run_command(service_command, raiseonerr=False)
        if cmd.returncode == 0:
            time.sleep(10)
            return cmd.returncode
        self.run_command('journalctl -xeu sssd.service', raiseonerr=False)
        raise SSSDException(f'Unable to {action} sssd', 1)

    def yum_install(self, package):
        """ Install packages through yum

            :param str package: Name of the package to be installed
            :return str: Returncode of the yum command
            :Exception: None
        """
        cmd = self.run_command(['yum', '-y', 'install', package],
                               raiseonerr=False)
        return cmd.returncode

    def dnf_install(self, package):
        """ Install packages through dnf

            :param str package: Name of the package to be installed
            :return str: Returncode of the dnf command
            :Exception: None
        """
        install = f'dnf install -y --setopt=strict=0 {package}'
        cmd = self.run_command(install, raiseonerr=False)
        return cmd.returncode

    def yum_uninstall(self, package):
        """ Uninstall packages through yum
            :param str package: Name of the package to be uninstalled
            :return str: Return code of the yum remove command
            :Exception: None
        """

        cmd = self.run_command(['yum', '-y', 'remove', package],
                               raiseonerr=False)
        return cmd.returncode

    def dnf_uninstall(self, package):
        """ Uninstall packages through dnf
            :param str package: Name of the package to be uninstalled
            :return str: Return code of the dnf remove command
            :Exception: None
        """

        cmd = self.run_command(['dnf', '-y', 'remove', package],
                               raiseonerr=False)
        return cmd.returncode

    def detect_files_provider(self):
        """
        Detect the SSSD's files provider feature
        :param: None
        :return bool: Returns "True" if "files provider" is supported
        :Exception: None
        """
        check = f'ls "/usr/lib64/sssd/libsss_files.so"'
        cmd = self.run_command(check, raiseonerr=False)
        return cmd.returncode == 0


class QeWinHost(QeBaseHost, pytest_multihost.host.WinHost):
    """ Windows Host class

    Subclass of pytest_multihost.host.WinHost, QeBaseHost
    Functions defined provide extra attributes when using Windows AD

    Attributes:
        domainname (str): Return domainname of the AD machine
        domain_basedn_entry (str): Return AD basedn
        netbiosname (str): Rerurn the netbios name of the machine
        realm (str):  Return AD realm in upper case
        sys_hostname(str): Return full hostname of the machine
     """

    # These are defined as class properties to be overriden on the
    # instance level.
    _domainname = None
    _domain_basedn_entry = None
    _hostname = None
    _netbiosname = None
    _realm = None

    @property
    def domainname(self):
        """ Return Domain name """
        if self._domainname is None:
            cmd = self.run_command(
                ['domainname'], set_env=False, raiseonerr=False)
            self._domainname = cmd.stdout_text.strip()
        return self._domainname

    @property
    def sys_hostname(self):
        """ Return FQDN """
        if self._hostname is None:
            hostname = 'hostname -f'
            cmd = self.run_command(hostname, set_env=False, raiseonerr=False)
            self._hostname = cmd.stdout_text.strip().lower()
        return self._hostname

    @property
    def realm(self):
        """ Return AD Realm """
        if self._realm is None:
            self._realm = self.domainname.upper()
        return self._realm

    @property
    def domain_basedn_entry(self):
        """ Return base DN Entry of the """
        if self._domain_basedn_entry is None:
            domain_list = ['DC=' + string for string in
                           self.domainname.split('.')]
            list1 = map(str, domain_list)
            self._domain_basedn_entry = ','.join(list1)
        return self._domain_basedn_entry

    @property
    def netbiosname(self):
        """ Return netbios name """
        if self._netbiosname is None:
            cmd = "powershell.exe -inputformat none -noprofile "\
                  "'(Get-ADDomain -Current LocalComputer)'.NetBIOSName"
            self._netbiosname = self.run_command(cmd).stdout_text
        return self._netbiosname

    def _get_client_dn_entry(self, client):
        """ Return DN entry of client computer in AD """
        cmd = self.run_command(['dsquery', 'computer', '-name', str(client)],
                               set_env=False, raiseonerr=False)
        output = cmd.stdout_text.strip()
        return output

    def _get_user_dn_entry(self, user):
        """ Return DN entry of client computer in AD """
        cmd = self.run_command(['dsquery', 'user', '-name', user],
                               set_env=False, raiseonerr=False)
        output = cmd.stdout_text.strip()
        return output


class QeDomain(pytest_multihost.config.Domain):
    """ QeDomain subclass of multihost plugin domain class. """
    def __init__(self, config, name, domain_type):
        """
        Subclass of pytest_multihost.config.Domain

        :param obj config: config config
        :param str name: Name
        :param str domain_type:

        :return None:
        """
        # No need to call the super constructor as everything is done here
        # pylint: disable=super-init-not-called
        self.type = str(domain_type)
        self.config = config
        self.name = str(name)
        self.hosts = []

    host_classes = {'default': QeHost, 'windows': QeWinHost}
