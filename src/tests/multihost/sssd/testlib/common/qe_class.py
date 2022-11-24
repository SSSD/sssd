"""
Module with extensions to the pytest_multihost
"""

import time
import logging
import pytest
from pytest_multihost import make_multihost_fixture
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
        if cmd.returncode == 0:
            return True
        return False

    @property
    def distro(self):
        """ Get contents of /etc/redhat-release

            :param None:
            :return str: contents of /etc/redhat-release
        """
        cmd = self.run_command(['cat', '/etc/redhat-release'],
                               raiseonerr=False)
        if cmd.returncode != 0:
            distro = 'Unknown Distro'
        else:
            distro = cmd.stdout_text.strip()
        return distro

    def package_mgmt(self, package, action='install'):
        """ Install packages
            : param str package: Package name or list of packages
            : param str action: Install/uninstall/update
            : return str: Return code of the yum remove command
        """
        if 'Fedora' in self.distro or '8.' in self.distro or\
                '9.' in self.distro:
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
        if '6.' in self.distro.split()[6]:
            # RHEL 6 needs service command
            service_command = f"service sssd {action}"
        cmd = self.run_command(service_command, raiseonerr=False)
        if cmd.returncode == 0:
            time.sleep(10)
            return cmd.returncode
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


class QeWinHost(QeBaseHost, pytest_multihost.host.WinHost):
    """ Windows Host class

    Subclass of pytest_multihost.host.WinHost, QeBaseHost
    Functions defined provide extra attributes when using Windows AD

    Attributes:
        domainname (str): Return domainname of the AD Machine
        realm (str):  Return AD realm in upper case
     """

    @property
    def domainname(self):
        """ Return Domain name """
        cmd = self.run_command(['domainname'], set_env=False, raiseonerr=False)
        return cmd.stdout_text.strip()

    @property
    def sys_hostname(self):
        """ Return FQDN """
        hostname = 'hostname -f'
        cmd = self.run_command(hostname, set_env=False, raiseonerr=False)
        return cmd.stdout_text.strip().lower()

    @property
    def realm(self):
        """ Return AD Realm """
        cmd = self.run_command(['domainname'], set_env=False, raiseonerr=False)
        return cmd.stdout_text.strip().upper()

    @property
    def domain_basedn_entry(self):
        """ Return base DN Entry of the """
        cmd = self.run_command(['domainname'], set_env=False, raiseonerr=False)
        domain_list = ['DC=' + string for string in cmd.stdout_text.strip().
                       split('.')]
        list1 = map(str, domain_list)
        domain_base_dn = ','.join(list1)
        return domain_base_dn

    @property
    def netbiosname(self):
        """ Return netbios name """
        cmd = "powershell.exe -inputformat none -noprofile "\
              "'(Get-ADDomain -Current LocalComputer)'.NetBIOSName"
        return self.run_command(cmd).stdout_text

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


@pytest.fixture(scope="session", autouse=True)
def session_multihost(request):
    # pylint: disable=no-member
    """Multihost plugin fixture for session scope"""
    if pytest.num_ad > 0:
        mhost = make_multihost_fixture(request, descriptions=[
            {
                'type': 'sssd',
                'hosts':
                {
                    'master': pytest.num_masters,
                    'atomic': pytest.num_atomic,
                    'replica': pytest.num_replicas,
                    'client': pytest.num_clients,
                    'other': pytest.num_others,
                }
            },
            {
                'type': 'ad',
                'hosts':
                {
                    'ad': pytest.num_ad,
                },
            },
        ], config_class=QeConfig,)
    else:
        mhost = make_multihost_fixture(request, descriptions=[
            {
                'type': 'sssd',
                'hosts':
                {
                    'master': pytest.num_masters,
                    'atomic': pytest.num_atomic,
                    'replica': pytest.num_replicas,
                    'client': pytest.num_clients,
                    'other': pytest.num_others,
                }
            },
        ], config_class=QeConfig,)
    mhost.domain = mhost.config.domains[0]
    mhost.master = mhost.domain.hosts_by_role('master')
    mhost.atomic = mhost.domain.hosts_by_role('atomic')
    mhost.replica = mhost.domain.hosts_by_role('replica')
    mhost.client = mhost.domain.hosts_by_role('client')
    mhost.others = mhost.domain.hosts_by_role('other')

    if pytest.num_ad > 0:
        mhost.ad = []
        for i in range(1, pytest.num_ad + 1):
            print(i)
            print(mhost.config.domains[i].hosts_by_role('ad'))
            mhost.ad.extend(mhost.config.domains[i].hosts_by_role('ad'))

    yield mhost


# pylint: disable=redefined-outer-name
@pytest.fixture(scope='session', autouse=True)
def create_testdir(session_multihost, request):
    """
    Create test dir on the hosts and backup resolv.conf
    @param session_multihost: Multihost fixture
    @param request: Pytest request
    """
    config_dir_cmd = f"mkdir -p {session_multihost.config.test_dir}"
    env_file_cmd = f"touch {session_multihost.config.test_dir}/env.sh"
    rm_config_cmd = f"rm -rf {session_multihost.config.test_dir}"
    bkup_resolv_conf = 'cp -a /etc/resolv.conf /etc/resolv.conf.orig'
    restore_resolv_conf = 'cp -a /etc/resolv.conf.orig /etc/resolv.conf'

    for machine in session_multihost.atomic + session_multihost.others +\
            session_multihost.replica:
        machine.run_command(config_dir_cmd)
        machine.run_command(env_file_cmd)

    for machine in session_multihost.client + session_multihost.master:
        machine.run_command(config_dir_cmd)
        machine.run_command(env_file_cmd)
        machine.run_command(bkup_resolv_conf)

    def remove_test_dir():
        for machine in session_multihost.client + session_multihost.master:
            machine.run_command(rm_config_cmd)
            machine.run_command(restore_resolv_conf)

        for machine in session_multihost.atomic + session_multihost.others +\
                session_multihost.replica:
            machine.run_command(config_dir_cmd)

    request.addfinalizer(remove_test_dir)
