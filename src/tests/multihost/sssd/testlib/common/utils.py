""" This module defines classes regarding sssd tools,
AD Operations and LDAP Operations"""

# flake8: noqa: W605

from __future__ import print_function
import os
import tempfile
import time
import re
import subprocess
import array
import random
import shlex
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import ldap
import ldif
import pytest
import pymmh3 as mmh3
from ldap import modlist
from .authconfig import RedHatAuthConfig
from .exceptions import PkiLibException
from .exceptions import LdapException
from .exceptions import SSSDException
from .paths import SSSD_DEFAULT_CONF
from .expect import pexpect_ssh
from .exceptions import SSHLoginException

GETENT_PASSWD_ITEMS = (
    'name', 'password', 'uid', 'gid', 'gecos', 'home', 'shell')

GETENT_GROUP_ITEMS = (
    'name', 'password', 'gid', 'users')


class sssdTools(object):
    """ Collection of assorted functions which is used in fixtures

        Attributes:
            Host(obj: `Multihost object type`): Multihost Object
            authbackup(str): Backup directory of authconfig
    """
    def __init__(self, Host, adhost=None):
        self.multihost = Host
        self.authbackup = "/root/authconfig_backup"
        if adhost:
            self.adhost = adhost
            self.adhost_ip = self.adhost.ip
            self.ad_ops = ADOperations(self.adhost)
            self.ad_dns = ADDNS(self.adhost)
            self._ad_conn = None
            self.domainname = self.adhost.domainname
            self.ad_realm = self.adhost.realm
            self.ad_password = self.adhost.ssh_password
            self.ad_hostname = self.adhost.external_hostname
            self.ad_basedn = self.adhost.domain_basedn_entry
            self.admin_user = 'Administrator'

    @property
    def ad_conn(self):
        """AD LDAP connection in lazy initialized property"""
        # Make sure to return None when the host is not AD
        if not hasattr(self, "_ad_conn"):
            return None
        if self._ad_conn:
            return self._ad_conn
        self._ad_conn = self.ad_ops.ad_conn()
        return self._ad_conn

    @property
    def sssd_user(self):
        """Sssd user"""
        if not hasattr(self, "_sssd_user"):
            cmd = self.multihost.run_command(
                'systemctl show sssd --value --property User', raiseonerr=False)
            if cmd.returncode == 0:
                self._sssd_user = cmd.stdout_text.strip()
            else:
                self._sssd_user = 'root'
        return self._sssd_user


    def client_install_pkgs(self):
        """ Install common required packages """
        pkgs = 'adcli realmd samba samba-common-tools krb5-workstation '\
               'oddjob oddjob-mkhomedir ldb-tools samba-winbind '\
               'samba-winbind-clients autofs nfs-utils rsyslog '\
               'cifs-utils openldap-clients tdb-tools '\
               'tcpdump wireshark-cli expect gcc gcc-c++ pam-devel '\
               'libkcapi-hmaccalc strace iproute-tc python3-libsss_nss_idmap'
        sssd_pkgs = 'sssd sssd-tools sssd-proxy sssd-winbind-idmap '\
                    'libsss_autofs sssd-kcm sssd-dbus'
        # Packages that might or might not be available depending on distro
        # are installed in own transactions not to prevent others
        # to be installed. It is due to difference between yum and dnf when dnf
        # does not install anything when one of the packages is missing.
        # It can be changed in dnf config by strict=0, but it would be hard to
        # do here without a massive refactoring.
        standalalone_pkgs = [
            'authselect', 'authconfig', 'firewalld', 'libsss_simpleifp',
            'nss-pam-ldapd', 'krb5-pkinit'
        ]
        for pkg in standalalone_pkgs:
            self.multihost.package_mgmt(pkg, action='install')
        self.multihost.package_mgmt(pkgs, action='install')
        self.multihost.package_mgmt(sssd_pkgs, action='install')

    def server_install_pkgs(self):
        """ Install common required packages on server"""
        pkgs = 'adcli realmd samba samba-common-tools krb5-workstation '\
               'samba-winbind-clients nfs-utils openldap-clients '\
               'krb5-server cifs-utils expect 389-ds-base rsyslog '\
               'oddjob oddjob-mkhomedir'
        sssd_pkgs = 'sssd sssd-tools sssd-proxy sssd-winbind-idmap '\
                    'libsss_autofs sssd-kcm sssd-dbus'
        # See comment in client_install_pkgs
        standalalone_pkgs = ['authselect', 'authconfig', 'libsss_simpleifp']
        distro = self.multihost.distro
        if '8.' in distro:
            enable_idm = 'yum module enable idm:DL1 -y'
            self.multihost.run_command(enable_idm)
        for pkg in standalalone_pkgs:
            self.multihost.package_mgmt(pkg, action='install')
        self.multihost.package_mgmt(pkgs, action='install')
        self.multihost.package_mgmt(sssd_pkgs, action='install')

    def service_ctrl(self, action, target_service):
        """ Start, stop, restart, reload service with systemctl

            :param str action: start/ stop/ restart/ reload
            :param str target_service: target service/daemon
            :return: str Return code of the systemctl command
            :Exception Raises exception
        """
        cmd = self.multihost.run_command(['systemctl', action,
                                          target_service], raiseonerr=False)
        if cmd.returncode == 0:
            time.sleep(10)
            return cmd.returncode
        else:
            raise SSSDException('Unable to %s %s' % (action,
                                                     target_service), 1)

    def update_resolv_conf(self, ip_addr):
        """ Update /etc/resolv.conf with Windows AD IP address

            :param str ip_addr: IP Address to be added in resolv.conf
            :return: None
        """
        self.multihost.log.info("Add ip addr %s in resolv.conf" % ip_addr)
        nameserver = 'nameserver %s\n' % ip_addr
        resolv_conf = self.multihost.get_file_contents('/etc/resolv.conf')
        if isinstance(resolv_conf, bytes):
            contents = resolv_conf.decode('utf-8')
        else:
            contents = resolv_conf
        contents = nameserver + contents.replace(nameserver, '')
        # Chattr will not work on symlink (like from systemd resolved)
        # so we ignore result
        self.multihost.run_command("chattr -i /etc/resolv.conf", raiseonerr=False)
        self.multihost.put_file_contents('/etc/resolv.conf', contents)
        self.multihost.run_command("chattr +i /etc/resolv.conf", raiseonerr=False)
        # Try to change dns settings on a machine with systemd.resolved
        change_stub = f"sed -ie 's/#\?DNS=.*/DNS={ip_addr}/' /etc/systemd/resolved.conf"
        self.multihost.run_command(change_stub, raiseonerr=False)
        self.multihost.run_command(
            "systemctl restart systemd-resolved", raiseonerr=False
        )

    def update_etc_hosts(self, ip_addr, hostname):
        """ Update /etc/hosts with ipaddress and hostname

           :param str ip_addr: IP Address to be added in /etc/hosts
           :param str hostname: hostname to be added in /etc/hosts
           :return None
        """
        hostentry = "%s   %s" % (ip_addr, hostname)
        self.multihost.log.info("Adding %s in /etc/hosts" % hostentry)
        current_contents = self.multihost.get_file_contents('/etc/hosts')
        if isinstance(current_contents, bytes):
            contents = current_contents.decode('utf-8')
        else:
            contents = current_contents
        contents = "\n" + hostentry + contents.replace(hostentry, '')
        self.multihost.put_file_contents('/etc/hosts', contents)

    def firewall_port(self, port, action):
        """ open or block ports via firewalld
            :param int port_num: port number to open or block
            :param str action: action to perform on port, action could be
            'block', 'open', 'allowall', 'delall'
            :port option could take port number or word
            :return: true
            :exceptions: raise sssdexception
        firewall_rules = firewall_rules.decode("utf-8")
        firewall_rules = firewall_rules.stdout_text[:-1]
        """
        cmd = 'systemctl restart firewalld'
        self.multihost.run_command(cmd)
        cmd = 'firewall-cmd --permanent --direct --get-rules ' \
              'ipv4 filter output'
        cmd1 = self.multihost.run_command(cmd)
        firewall_rules = cmd1.stdout_text
        rule_num_index = []
        port_and_rule_num = {}
        for rule in firewall_rules.split('\n'):
            if len(rule) > 13:
                port = rule.split()[5].split('=')[1]
                rule_num = rule.split()[0]
                rule_num_index.append(rule[0])
                port_and_rule_num[port] = rule_num
        if not rule_num_index:
            max_rule_num = 0
        else:
            max_rule_num = int(max(rule_num_index)) + 1
        rule_allow_all = ''
        for rule in firewall_rules.split('\n'):
            if rule.split(' ').count('accept') == 1:
                rule_allow_all = int(rule[0])
        fw_rld = 'firewall-cmd --reload'
        if action.lower() == 'block' and port not in port_and_rule_num:
            fw_block = 'firewall-cmd --permanent --direct --add-rule ipv4 ' \
                       'filter output %s -p tcp -m tcp ' \
                       '--dport=%s -j drop' % (max_rule_num, port)
            try:
                self.multihost.run_command(fw_block, raiseonerr=False)
            except subprocess.CalledProcessError:
                pytest.fail("unable to block %s port" % port)
            else:
                self.multihost.run_command(fw_rld, raiseonerr=False)
        elif action.lower() == 'open' and port in port_and_rule_num:
            fw_open = 'firewall-cmd --permanent --direct --remove-rule ' \
                'ipv4 filter output %s -p tcp -m tcp ' \
                '--dport=%s -j drop' % (port_and_rule_num[port], port)
            try:
                cmd = self.multihost.run_command(fw_open, raiseonerr=False)
            except subprocess.CalledProcessError:
                pytest.fail("unable to open %s port" % port)
            else:
                self.multihost.run_command(fw_rld, raiseonerr=False)
        elif action.lower() == 'allowall' and not rule_allow_all:
            fw_alw_rest = 'firewall-cmd --permanent --direct --add-rule ' \
                          'ipv4 filter output %s -j accept' % (max_rule_num)
            try:
                cmd = self.multihost.run_command(fw_alw_rest, raiseonerr=False)
            except subprocess.CalledProcessError:
                pytest.fail("unable to run cmd")
            else:
                self.multihost.run_command(fw_rld, raiseonerr=False)
        elif action.lower() == 'delall' and isinstance(rule_allow_all, int):
            fw_del_alw = 'firewall-cmd --permanent --direct --remove-rule ' \
                         'ipv4 filter output %s -j accept' % (rule_allow_all)
            try:
                cmd = self.multihost.run_command(fw_del_alw, raiseonerr=False)
            except subprocess.CalledProcessError:
                pytest.fail("unable to run cmd")
            else:
                self.multihost.run_command(fw_rld, raiseonerr=False)
        else:
            print("failed to execute")
            return False

    def config_authconfig(self, hostname, domainname):
        """ Run authconfig to configure Kerberos and SSSD auth on remote host

            :param str hostname: Hostname of server(AD) to
             which client is configured to auth
            :param domainname: domain name of IPA/AD
            :return: None
            :Exceptions: None
        """
        authconfig = RedHatAuthConfig(self.multihost)
        self.multihost.log.info("Take backup of current authconfig")
        authconfig.backup(self.authbackup)
        self.multihost.run_command(['domainname'], raiseonerr=False)
        authconfig.enable("sssd")
        authconfig.enable("sssdauth")
        authconfig.add_parameter("krb5kdc", hostname)
        authconfig.add_parameter("krb5adminserver", hostname)
        authconfig.add_parameter("krb5realm", domainname.upper())
        authconfig.execute()

    def authselect(self):
        """ Run authselect """
        authselect_cmd = 'authselect select sssd with-mkhomedir --force'
        self.multihost.run_command(authselect_cmd)
        start_oddjob = 'systemctl restart oddjobd.service'
        self.multihost.run_command(start_oddjob)

    def systemsssdauth(self, realm, krb_server):
        """ Run authconfig/authselect to enable sssd authentication """
        distro = self.multihost.distro
        if '7.' in distro:
            self.config_authconfig(krb_server, realm)
        else:
            self.authselect()
            self.config_etckrb5(realm, krb_server)
            self.enable_kcm()

    def update_conf(self, conffile, section, parameters, action='add'):
        """ Update configuration files """
        config = ConfigParser.RawConfigParser(delimiters=('='))
        config.optionxform = str
        try:
            config.read(conffile)
        except IOError:
            raise SSSDException("Unable to fetch %s" % conffile)
        if action == 'add' or action == 'update':
            if section not in config.sections():
                config.add_section(section)
            for key, value in parameters.items():
                config.set(section, key, value)
        elif action == 'delete':
            if section not in config.sections():
                raise SSSDException("%s section do not exist" % section)
            else:
                for key, _ in parameters.items():
                    config.remove_option(section, key)
                if not parameters:
                    config.remove_section(section)
        with open(conffile, 'w') as conf:
            config.write(conf)

    def sssd_conf(self, section, parameters, action='add'):
        """ Create sssd conf """
        tmpconf = tempfile.NamedTemporaryFile(suffix='sssd.conf', delete=False)
        config = ConfigParser.RawConfigParser()
        config.optionxform = str
        try:
            self.multihost.transport.get_file(SSSD_DEFAULT_CONF, tmpconf.name)
        except IOError:
            config.add_section('sssd')
            config.set('sssd', 'config_file_version', '2')
            config.set('sssd', 'services', 'nss, pam')
        else:
            try:
                config.read(tmpconf.name)
            except IOError:
                raise SSSDException("Unable to fetch sssd.conf")
        if action == 'add' or action == 'update':
            if section not in config.sections():
                config.add_section(section)
            for key, value in parameters.items():
                config.set(section, key, value)
        elif action == 'delete':
            if section not in config.sections():
                raise SSSDException("%s section do not exist" % section)
            else:
                for key, _ in parameters.items():
                    config.remove_option(section, key)
                if not parameters:
                    config.remove_section(section)
        with open(tmpconf.name, 'w') as conf:
            config.write(conf)
        self.multihost.transport.put_file(tmpconf.name, SSSD_DEFAULT_CONF)
        set_perms = f'chmod 600 {SSSD_DEFAULT_CONF}'
        self.multihost.run_command(set_perms, raiseonerr=False)
        self.multihost.run_command(
            f'chown {self.sssd_user}:{self.sssd_user} {SSSD_DEFAULT_CONF}',
            raiseonerr=False
        )
        os.unlink(tmpconf.name)

    def get_domain_section_name(self):
        """ Get Domain section """
        tmpconf = tempfile.NamedTemporaryFile(suffix='sssd.conf', delete=False)
        self.multihost.transport.get_file(SSSD_DEFAULT_CONF, tmpconf.name)
        config = ConfigParser.ConfigParser()
        try:
            config.read(tmpconf.name)
        except IOError:
            pytest.fail("cannot read sssd.conf")
        else:
            return config.get('sssd', 'domains')
        os.unlink(tmpconf.name)

    def restore_authconfig(self):
        """ Restore the default authconfig """
        authconfig = RedHatAuthConfig(self.multihost)
        authconfig.restore(self.authbackup)

    def config_smb_net_ads_join(self, domainname):
        """ Configure smb.conf as Domain Member to Windows AD
            :param str domainname: domain name of AD/IPA
            :return: None
            :Exception: None
        """
        workgroup_name = domainname.strip().split('.')[0].upper()
        realm = domainname.strip().upper()
        sambaconfig = ConfigParser.RawConfigParser()
        sambaconfig.optionxform = str
        sambaconfig.add_section('global')
        sambaconfig.set("global", "workgroup", workgroup_name)
        sambaconfig.set("global", "security", "ads")
        sambaconfig.set("global", "realm", realm)
        sambaconfig.set("global", "kerberos method", "secrets and keytab")
        sambaconfig.set("global", "client signing", "yes")
        sambaconfig.set("global", "client use spnego", "yes")
        tmp_fd, tmp_file_path = tempfile.mkstemp(suffix='conf', prefix='smb')
        with open(tmp_file_path, "w") as outfile:
            sambaconfig.write(outfile)
        self.multihost.transport.put_file(tmp_file_path, '/etc/samba/smb.conf')
        os.close(tmp_fd)

    def realm_join(self, domainname, admin_password,
                   client_software='sssd',
                   server_software='active-directory',
                   membership_software='adcli'):
        """ Join system to AD/IPA Domain using realmOA
            :param str domainname: domain name of AD/IPA
            :param str admin_password: Administrator password required to join
            :param str client_software: client software to be used (sssd/samba)
            :param str server_software: server software (active-directory/ipa)
            :param str membership_software: membership software (samba/adcli)
            :Exception: Raises SSSDException
        """
        realm_cmd = f'timeout 300 /usr/sbin/realm join {domainname} ' \
                    f'--client-software={client_software} ' \
                    f'--server-software={server_software} ' \
                    f'--membership-software={membership_software} -v'
        # For AD sasl authid tests we need to have user-principal populated.
        if server_software == 'active-directory':
            hostname = self.multihost.run_command(
                'hostname', raiseonerr=False).stdout_text.rstrip()
            ad_realm = self.adhost.domainname.upper()
            realm_cmd += f' --user-principal=host/{hostname}@{ad_realm}'

        print(realm_cmd)
        # When AD is on a diffent network that client this is not
        # quite reliable so we retry
        for _ in range(5):
            cmd = self.multihost.run_command(
                realm_cmd, stdin_text=admin_password, raiseonerr=False)
            if cmd.returncode == 0:
                break
            elif cmd.returncode == 124: # Timeout occured
                # When the command fails, there is still realmd running
                # that might be doing something so we stop it so
                # the following realm leave is not stuck on
                # "realm: Already running another action".
                print("WARNING: realm join timed out, retrying!")
                self.service_ctrl('stop', 'realmd')
            else:
                # other error
                print("realm join failed!")
                if "realm: Already joined to this domain" in cmd.stderr_text:
                    print("Already joined to realm.")
                    break
            time.sleep(30)
        else:
            self.multihost.run_command("cat /etc/krb5.conf", raiseonerr=False)
            self.multihost.run_command("resolvectl dns", raiseonerr=False)
            raise SSSDException("Error: %s" % cmd.stderr_text)
        return cmd.stderr_text


    def realm_leave(self, domainname, raiseonerr=True):
        """ Leave system from AD/IPA Domain

            :param str domainname: domain name of AD/IPA
            :param bool raiseonerr: ignore failure, do not raise an exception
            :return bool: True if successfully dis-joined to AD/IPA
             else raises Exception
            :Exception: Raises SSSDException
        """
        # When we do not want to raise exception we also do not want to see
        # the output as it is probably a pre-emptive realm leave before
        # joining again and the error in log is misleading.
        cmd = self.multihost.run_command(
            f'realm leave {domainname} -v', log_stdout=raiseonerr, raiseonerr=False)
        if cmd.returncode != 0 and "realm: Couldn't connect to realm service" in cmd.stderr_text:
            print("WARNING: realm leave timed out, retrying!")
            self.service_ctrl('restart', 'realmd')
            cmd = self.multihost.run_command(
                f'realm leave {domainname} -v', log_stdout=raiseonerr, raiseonerr=False)
        if cmd.returncode != 0 and raiseonerr:
            raise SSSDException("Error: %s", cmd.stderr_text)
        elif cmd.returncode != 0:
            return False
        return True

    def join_ad(self, realm=None, adpassword=None, mem_sw=None):
        """ Join AD using realm
        pass membership software as argument
        use adcli ad default
        """
        if not realm:
            realm = self.ad_realm
        if not adpassword:
            adpassword = self.ad_password
        prg = mem_sw if mem_sw == 'samba' else 'adcli'
        try:
            output = self.realm_join(realm, adpassword,
                                     membership_software=prg)
            print("Successfully join to AD")
        except SSSDException:
            pytest.fail("Failed to join to AD")
        return output

    def disjoin_ad(self, realm_output=None, raiseonerr=True):
        """ Disjoin system from Domain """
        if realm_output:
            account_name = self.get_computer_account(realm_output)
        else:
            account_name = self.multihost.sys_hostname.split('.')[0]
        if len(account_name) > 15:
            account_name = account_name[:15]
        account_dn = f'CN={account_name},CN=Computers,{self.ad_basedn}'

        # Try to leave the realm normally
        result = self.realm_leave(self.ad_realm, raiseonerr=False)
        remove_computer = f"powershell.exe -inputformat none -noprofile "\
                          f"'(Remove-ADComputer -Identity"\
                          f" \"{account_dn}\" -Confirm:$false)'"
        # Remove the machine on the AD end
        self.adhost.run_command(remove_computer, raiseonerr=False)
        if raiseonerr and not result:
            raise SSSDException("Failed to Disjoin system from Windows AD")

    def get_computer_account(self, realm_output):
        """ Get DN of system joined to AD """
        out_list = realm_output.split('\n')
        req_str = 'Using computer account name:'
        matching = [s for s in out_list if req_str in s]
        name = matching[0].split(': ')[1]
        return name

    def export_nfs_fs(self, path_list, nfs_client, permissions=None):
        """ Add local file systems directories to /etc/exports

        Todo: We are not checking if the directories added
        to /etc/exports already exist.

            :param str path_list: list of directories to be created
            :param str nfs_client: hostname/ip-address of nfs client
            :return bool: True if successfully added values in /etc/exports
            :Exception: Raises SSSDException
        """
        if not permissions:
            permissions = '(rw,sync,fsid=0)'
        self.multihost.transport.get_file('/etc/exports', '/tmp/exports')
        for local_dir in path_list:
            cmd = self.multihost.run_command(['mkdir', '-p', local_dir],
                                             raiseonerr=False)
            if cmd.returncode != 0:
                raise SSSDException("failed creating %s directory" % local_dir)
            exp_share = '{}{}{}{}'.format(local_dir, ' ', nfs_client,
                                          permissions)

            with open('/tmp/exports', "a+") as outfile:
                outfile.write(exp_share + "\n")
        self.multihost.transport.put_file('/tmp/exports', '/etc/exports')
        return True

    def remove_sss_cache(self, cache_path):
        """ Remove the sssd cache
            :param str cache_path: The relative path of cache/log
            :return bool: True if deletion succeeded
        """
        rm_cmd = self.multihost.run_command(
            f'rm -f {cache_path}/*', raiseonerr=False)
        if rm_cmd.returncode != 0:
            print("Error: %s", rm_cmd.stderr_text)
            return False
        print("Successfully deleted.")
        return True

    def clear_sssd_cache(self, start=True):
        """ Stop sssd, clear sssd cache/logs and start sssd
            :param bool start: Shall the sssd be started afterward
        """
        self.multihost.service_sssd('stop')
        rm_cmd = self.multihost.run_command(
            'rm -f /var/lib/sss/{db,mc}/* /var/log/sssd/*', raiseonerr=False)
        if rm_cmd.returncode != 0:
            print("Error: %s", rm_cmd.stderr_text)
        else:
            print("Successfully deleted.")
        if start:
            self.multihost.service_sssd('start')
            time.sleep(5)

    def domain_from_suffix(self, suffix):
        """ Domain name from the suffix
        :param suffix: The suffix of 389 RHDS instance
        :return: domain name in upper case
        :Exception: Raises exception(builtin)
        """
        if suffix is None:
            raise Exception("Error: suffix should be passed")
        else:
            l1 = suffix.split("dc=")
            elist = []
            for i in l1:
                d1 = i.strip(',')
                elist.append(d1)
            str1 = '.'.join(elist)
            l_domain = str1.lstrip('.')
            u_domain = l_domain.upper()
            return u_domain

    def delete_sssd_domain_log(self, domainname):
        """ Remove the sssd domain log

            :param str cache_path: domain name from default configuration file
            :return bool: True if deletion is successful
            :Exception: Raises exception(builtin)
        """
        path = ("/var/log/sssd/sssd_%s.log" % domainname)
        cmd = self.multihost.run_command(['rm', '-rf', path], raiseonerr=False)
        if cmd.returncode != 0:
            raise SSSDException("Error: %s", cmd.stderr_text)
        else:
            return True

    def get_ad_user_info(self, username, ad_host):
        """ Get the ad user information through 'net ads dn' command

            :param str username: The name of ad user
            :param str ad_host: Host of active directory
            :return bool: True is command is successful
            :return: output of command
            :Exception: Raises exception(builtin)
        """
        user_dn = "CN=%s,CN=Users,%s" % (username, ad_host.domain_basedn_entry)
        cmd = self.multihost.run_command(['net', 'ads', 'dn', user_dn],
                                         raiseonerr=False)
        if cmd.returncode != 0:
            raise SSSDException("Error: %s", cmd.stderr_text)
        else:
            return (True, cmd.stdout_text)

    def su_success(self, username, password='Secret123', with_password=True):
        """Helper function for testing su access
        :param str username: username including domain if needed
        :param str password: password for the user
        :param bool with_password: whether su should be with password or not
        :return bool: True is command is successful
        """
        escaped = shlex.quote(username)
        if with_password:
            # To sun su with password we switch to user nobody first
            su_cmd = self.multihost.run_command(
                rf'su --shell /bin/sh nobody -c "su --shell /bin/true --'
                rf' {escaped}"',
                stdin_text=password, raiseonerr=False
            )
        else:
            su_cmd = self.multihost.run_command(
                rf'su - {escaped} -c whoami', raiseonerr=False
            )
        return su_cmd.returncode == 0

    def auth_from_client(self, username, password):
        """ ssh to user from client environment
        :param str username: The name of user
        :param str password: Login password of user
        :return: exit status
        if timeout the return status is 0
        if user successfully login then return status is 3
        if not then return status is 10
        """
        shortname = username.split("@")[0]
        expect_script = 'spawn ssh -o NumberOfPasswordPrompts=1 ' \
                        '-o StrictHostKeyChecking=no '\
                        '-o UserKnownHostsFile=/dev/null ' \
                        '-l ' + username + ' localhost whoami' + '\n'
        expect_script += 'expect "*assword: "\n'
        expect_script += 'send "' + password + '\\r"\n'
        expect_script += 'sleep 30 \n'
        expect_script += 'expect {\n'
        expect_script += '\ttimeout { set result_code 0 }\n'
        expect_script += '\t"Permission denied " { exit 10 }\n'
        expect_script += '\t"' + username + '" { set result_code 3 }\n'
        expect_script += '\t"' + shortname + '" { set result_code 3 }\n'
        expect_script += '\teof { set result_code 10 }\n'
        expect_script += '}\n'
        expect_script += 'exit $result_code\n'
        print(expect_script)
        randtag = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                          for _ in range(10))
        exp_file = "/tmp/qe_pytest_expect_file" + randtag
        self.multihost.put_file_contents(exp_file, expect_script)
        print(("remote side expect script filename: %s") % exp_file)

        # Next run expect
        cmd = self.multihost.run_command(['expect', '-f', exp_file],
                                         raiseonerr=False)
        print("----expect output start----")
        print(cmd.stdout_text)
        print(cmd.stderr_text)
        print("----expect output end----")
        return cmd.returncode

    def auth_from_client_key(self, user):
        """Helper function to login over ssh with a key
        :param str user: username including domain if needed
        :return: bool whether login succeeded
        """
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write('#!/usr/bin/expect\n')
            tfile.write('set timeout 20\n')
            tfile.write(f'set user {user}\n')
            tfile.write('spawn ssh -o StrictHostKeyChecking=no -o'
                        ' GSSAPIAuthentication=no -o PasswordAuthentication=no'
                        ' -l $user localhost\n')
            tfile.write('expect "$ "\n')
            tfile.write('send "exit\\r"\n')
            tfile.write('expect eof\n')
            tfile.flush()
            self.multihost.transport.put_file(tfile.name, '/tmp/ssh.exp')
        expect_cmd = 'chmod +x /tmp/ssh.exp; /tmp/ssh.exp 2>&1'
        cmd = self.multihost.run_command(expect_cmd, raiseonerr=False)
        message = "Connection to localhost closed"
        result = message in cmd.stdout_text
        return result

    def change_user_password(self, username, login_password, current_password,
                             new_password, retype_new_password):
        """ ssh to user from client environment and change the user's password
        :param str username: The name of user
        :param str login_password: Login password of user
        :param str current_password: Current login password of user
        :param str new_password: New password of the user
        :param str retype_new_password: Retype the new password of the user
        :return: exit status
            if timeout the return status is 0
            if user is able to change the password then return status is 3
            if character length of password is less than 8 characters then
                return status is 4
            if while retyping new password is not matching the return status
                is 5
            if current password did not match the return status is 6
            if not then return status is 10
        """
        expect_script = 'spawn ssh -o NumberOfPasswordPrompts=1 ' \
                        '-o StrictHostKeyChecking=no ' \
                        '-o UserKnownHostsFile=/dev/null ' \
                        '-l ' + username + ' localhost' + '\n'
        expect_script += 'expect "*assword: "\n'
        expect_script += 'send "' + login_password + '\r"\n'
        expect_script += 'expect "$ "\n'
        expect_script += 'send "passwd\r"\n'
        expect_script += 'expect "Current password: "\n'
        expect_script += 'send "' + current_password + '\r"\n'
        expect_script += 'expect "New password: "\n'
        expect_script += 'send "' + new_password + '\r"\n'
        expect_script += 'expect "Retype new password:"\n'
        expect_script += 'send "' + retype_new_password + '\r"\n'
        expect_script += 'expect {\n'
        expect_script += '\ttimeout { set result_code 0 }\n'
        expect_script += '\t"passwd: all authentication tokens updated ' \
                         'successfully" { set result_code 3 }\n'
        expect_script += '\t"passwd: Authentication token is no longer ' \
                         'valid; new one required" { set result_code 4 }\n'
        expect_script += '\t"Sorry, passwords do not match." ' \
                         '{ set result_code 5}\n'
        expect_script += '\t"Password change failed. Server message: ' \
                         'Old password not accepted." { set result_code 6 }\n'
        expect_script += '\teof {}\n'
        expect_script += '\t"Permission denied " { set result_code 10 }\n'
        expect_script += '}\n'
        expect_script += 'exit $result_code\n'
        print(expect_script)
        randtag = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                          for _ in range(10))
        exp_file = "/tmp/qe_pytest_expect_file" + randtag
        self.multihost.put_file_contents(exp_file, expect_script)
        print(("remote side expect script filename: %s") % exp_file)

        # Next run expect
        cmd = self.multihost.run_command(['expect', '-f', exp_file],
                                         raiseonerr=False)
        print("----expect output start----")
        print(cmd.stdout_text)
        print(cmd.stderr_text)
        print("----expect output end----")
        return cmd.returncode

    def dump_ldb(self, entity, domain):
        """Dump entity info from ldb
        :param entity: The user or group name as a string.
        :param domain: The domain as a string.
        :returns dictionary"""
        cmd = self.multihost.run_command(
            f'ldbsearch -H /var/lib/sss/db/cache_{domain.lower()}.ldb name='
            f'"{entity}"*',
            raiseonerr=False)
        ldb_info = {}
        lines = cmd.stdout_text.split('\n')
        for idx, line in enumerate(lines):
            if ':' in line:
                parts = line.split(':')
                item_name = parts[0].strip()
                ldb_info[item_name] = parts[1].strip()
                # Handle line continuation
                if idx + 1 < len(lines):
                    if ":" not in lines[idx + 1]:
                        ldb_info[item_name] += lines[idx + 1].strip()
        return ldb_info

    def auth_client_ssh_password(self, user, user_pass):
        """This function will make sure that user can authenticate
        :client_hostname: host name of client machine
        :user: the username as string
        :user_pass: password of user
        :returns boolean
        """
        client = pexpect_ssh(self.multihost.ip, user, user_pass, debug=False)
        try:
            client.login(login_timeout=30, sync_multiplier=5,
                         auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
            return False
        else:
            client.logout()
            return True

    def get_getent_passwd(self, user):
        """Parses the output of getent passwd for a user
        Returns empty dict when entity is not found.
        :param user: the username as string
        :returns dictionary
        :Exception: IndexError
        """
        parsed = {}
        getent_cmd = self.multihost.run_command(
            f'getent passwd {user}', raiseonerr=False)
        if getent_cmd.returncode != 0:
            return parsed
        splits = getent_cmd.stdout_text.strip().split(':')
        for index, val in enumerate(GETENT_PASSWD_ITEMS):
            parsed[val] = splits[index]
        return parsed

    def get_getent_group(self, group):
        """Parses the output of getent group for a group
        Returns empty dict when entity is not found.
        :param group: the group name as string
        :returns dictionary
        :Exception: IndexError
        """
        parsed = {}
        getent_cmd = self.multihost.run_command(
            f'getent group {group}', raiseonerr=False)

        if getent_cmd.returncode != 0:
            return parsed
        splits = getent_cmd.stdout_text.strip().split(':')
        for index, val in enumerate(GETENT_GROUP_ITEMS):
            parsed[val] = splits[index]
        return parsed

    def create_kdcinfo(self, realm, ipaddress):
        """ create kdcinfo file """
        kdc_path = '/var/lib/sss/pubconf/kdcinfo.%s' % (realm)
        self.multihost.put_file_contents(kdc_path, ipaddress)

    def config_etckrb5(self, realm, krb5_server=None):
        """ Configure /etc/krb5.conf with realm specified
            :param str realm: Kerberos realm
            :param krb5_server: kerberos server
            :return: None
            :Exception: Raise exception(builtin)
        """
        if krb5_server is None:
            krb5_server = self.multihost.sys_hostname
        if realm is None:
            raise SSSDException("Error: realm should be passed")
        else:
            realm_def = ("{\n"
                         "kdc = %s\n"
                         "admin_server = %s\n"
                         "}") % (krb5_server, krb5_server)
            krb5config = ConfigParser.RawConfigParser()
            krb5config.optionxform = str
            krb5config.add_section('logging')
            krb5config.set("logging", "default", "FILE:/var/log/krb5libs.log")
            krb5config.set("logging", "kdc", "FILE:/var/log/krb5kdc.log")
            krb5config.set("logging", "admin_server",
                           "FILE:/var/log/kadmind.log")
            krb5config.add_section('libdefaults')
            krb5config.set("libdefaults", "ticket_lifetime", "24h")
            krb5config.set("libdefaults", "default_realm", realm.upper())
            krb5config.set("libdefaults", "dns_lookup_realm", "false")
            krb5config.set("libdefaults", "dns_lookup_kdc", "false")
            krb5config.set("libdefaults", "forwardable", "true")
            krb5config.set("libdefaults", "rdns", "false")
            krb5config.set("libdefaults", "pkinit_anchors",
                           "FILE:/etc/pki/tls/certs/ca-bundle.crt")
            krb5config.set("libdefaults", "spake_preauth_groups",
                           "edwards25519")
            krb5config.set("libdefaults", "default_ccache_name",
                           "KEYRING:persistent:%{uid}")
            krb5config.set(
                "libdefaults", "default_tgs_enctypes",
                "aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96 "
                "aes128-cts-hmac-sha256-128 aes128-cts-hmac-sha1-96 "
                "aes256-cts des3-cbc-sha1 arcfour-hmac des-cbc-md5 "
                "des-cbc-crc"
            )
            krb5config.set(
                "libdefaults", "default_tkt_enctypes",
                "aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96 "
                "aes128-cts-hmac-sha256-128 aes128-cts-hmac-sha1-96 "
                "aes256-cts des3-cbc-sha1 arcfour-hmac des-cbc-md5 "
                "des-cbc-crc"
            )
            krb5config.add_section("realms")
            krb5config.set("realms", "%s" % realm.upper(), realm_def)
            krb5config.add_section("domain_realm")
            krb5config.set("domain_realm", realm.lower(), realm.upper())
            krb5config.set("domain_realm", ".%s" % (realm.lower()),
                           realm.upper())
            krb5config.add_section("appdefaults")
            krb5config.set("appdefaults", "validate", "true")
            krb5config.add_section("kdc")
            krb5config.set("kdc", "profile", "/var/kerberos/krb5kdc/kdc.conf")
            temp_fd, temp_file_path = tempfile.mkstemp(suffix='conf',
                                                       prefix='krb5conf')
            with open(temp_file_path, "w") as outfile:
                krb5config.write(outfile)
            self.multihost.transport.put_file(temp_file_path, '/etc/krb5.conf')
            os.close(temp_fd)

    def enable_kcm(self):
        """ Enable kcm
            :param: None
            :Return: None
            :Exception: Raise SSSDException
        """
        self.multihost.transport.get_file('/etc/krb5.conf', '/tmp/krb5.conf')
        str2 = 'includedir /etc/krb5.conf.d/'
        with open('/tmp/krb5.conf', 'r') as krb_org_file:
            with open('/tmp/krb5.conf.kcm', 'w+') as krb_new_file:
                krb_new_file.write(str2)
                krb_new_file.write('\n')
                krb_new_file.write('\n')
                krb_new_file.write(krb_org_file.read())
        self.multihost.transport.put_file('/tmp/krb5.conf.kcm',
                                          '/etc/krb5.conf')
        enable_sssd_kcm_socket = 'systemctl enable sssd-kcm.socket'
        cmd = self.multihost.run_command(enable_sssd_kcm_socket,
                                         raiseonerr=False)
        symlink = '/etc/systemd/system/sockets.target.wants/sssd-kcm.socket'
        try:
            self.multihost.run_command(['ls', '-l', symlink])
        except subprocess.CalledProcessError:
            self.multihost.log.info("kcm socket not enabled")
            raise SSSDException("kcm socket not enabled")
        start_ssd_kcm_socket = 'systemctl start sssd-kcm.socket'
        cmd = self.multihost.run_command(start_ssd_kcm_socket,
                                         raiseonerr=False)
        if cmd.returncode != 0:
            raise SSSDException("sssd-kcm.socket service not started")
        enable_kcm_service = 'systemctl enable sssd-kcm.service'
        cmd = self.multihost.run_command(enable_kcm_service,
                                         raiseonerr=False)
        symlink = '/etc/systemd/system/sockets.target.wants/sssd-kcm.socket'
        if cmd.returncode != 0:
            raise SSSDException("sssd-kcm.service not enabled")
        try:
            self.multihost.run_command(['ls', '-l', symlink])
        except subprocess.CalledProcessError:
            self.multihost.log.info("kcm socket not enabled")
            raise SSSDException("kcm socket not enabled")

    def find_rid(self, user):
        """ Find Relative id from object SID """
        name = "name=%s" % user.lower()
        domains = self.get_domain_section_name()
        cache_path = '/var/lib/sss/db/cache_%s.ldb' % domains
        ldb_cmd = 'ldbsearch -H %s %s' % (cache_path, name)
        cmd = self.multihost.run_command(ldb_cmd, raiseonerr=False)
        if cmd.returncode == 0:
            ret = re.compile(r'objectSIDString.*')
            found = ret.search(cmd.stdout_text)
            str_new = found.group()
            list_new = str_new.split()
            str1 = ''.join(list_new)
            str2 = str1.rsplit(']', 1)[0]
            str3 = str2.split('-', 1)[-1]
            rid = str3.split('-', 6)[-1]
            return int(rid)
        else:
            raise SSSDException("Unable to find RID for %s" % user)

    def reset_machine_password(self):
        """ Reset Machine Password on AD """
        client_hostname = self.multihost.sys_hostname.strip()
        client_short_name = client_hostname.split('.')[0][:15]
        client_dn_entry = f'CN={client_short_name},CN=Computers,' \
                          f'{self.ad_basedn}'
        ps_cmd = f"powershell.exe -inputformat none -noprofile "\
                 f"'(Set-ADComputer -Identity \"{client_dn_entry}\" " \
                 f"-Replace @{{pwdLastSet=0}} -Confirm:$false)'"
        cmd = self.adhost.run_command(ps_cmd, raiseonerr=False)
        return cmd.returncode

    def create_ad_user(self, username, groupname, mail=None):
        """ Create AD user

            :param str username: AD Username
            :param str groupname: AD Groupname
            :param str mail: User mail id
        """
        self.ad_ops.create_ad_unix_user_group(username, groupname, mail)

    def remove_ad_user_group(self, name):
        """ Remove AD User and Group

            param str: AD user or group name
        """
        self.ad_ops.delete_ad_user_group(name)

    def create_ad_unix_group(self, groupname):
        """ create AD Domain local group
            :param str: groupname
        """
        self.ad_ops.create_ad_unix_group(groupname)

    def add_aduser_member_group(self, groupname, username):
        """ Add AD user as member to the group

            :param str groupname: AD Group name
            :param str username: AD User name
        """
        self.ad_ops.add_user_member_of_group(groupname, username)

    def autofs_ad_schema(self):
        """ Enable autofs schema(rfc2307) on windows AD """
        self.ad_conn.autofs_ad_schema(self.ad_basedn)

    def remove_automount(self, verbose=True):
        """ Deletes all map entries, maps and automount DN """
        automount_dn = '{},{}'.format('ou=automount', self.ad_basedn)
        # Unprotect the OU so it can be deleted recursively
        mod_ou = f"powershell.exe -inputformat none -noprofile '" \
                 f"Set-ADOrganizationalUnit  -Identity \"{automount_dn}\"" \
                 f" -Confirm:$False -ProtectedFromAccidentalDeletion $false'"
        self.adhost.run_command(mod_ou, log_stdout=verbose, raiseonerr=False)
        remove_automount = f"powershell.exe -inputformat none -noprofile "\
                           f"'(Remove-ADOrganizationalUnit -Recursive "\
                           f"-Identity \"{automount_dn}\" -Confirm:$false)'"
        self.adhost.run_command(
            remove_automount, log_stdout=verbose, raiseonerr=False)

    def fix_sssd_conf_perms(self):
        """Restore ownership, permissions and selinux on sssd.conf"""
        self.multihost.run_command(
            f'chown {self.sssd_user}:{self.sssd_user} {SSSD_DEFAULT_CONF}',
            raiseonerr=False
        )
        self.multihost.run_command(f'chmod 600 {SSSD_DEFAULT_CONF}', raiseonerr=False)
        self.multihost.run_command(f'restorecon -v {SSSD_DEFAULT_CONF}', raiseonerr=False)

    def backup_sssd_conf(self):
        """ Backup sssd conf """
        bkup_cmd = f'cp -af {SSSD_DEFAULT_CONF} /etc/sssd/sssd.conf.orig'
        self.multihost.run_command(bkup_cmd)

    def restore_sssd_conf(self):
        """ Restore sssd conf """
        restore_cmd = f'cp -af /etc/sssd/sssd.conf.orig {SSSD_DEFAULT_CONF}'
        self.multihost.run_command(restore_cmd)
        self.fix_sssd_conf_perms()

    def add_service_principals(self, spn_list):
        """ Add service principal to Windows AD """
        host = self.multihost.sys_hostname
        for spn in spn_list:
            cmd = "net ads keytab add_update_ads %s/%s "\
                  "-U %s " % (spn, host, self.admin_user,)
            try:
                self.multihost.run_command(cmd, stdin_text='Secret123')
            except subprocess.CalledProcessError:
                pytest.fail("Failed to add %s Service principal" % (spn))

    def remove_service_principals(self, spn_list):
        """ Remove service principal from AD """
        client_name = self.multihost.external_hostname.strip().split('.')[0]
        client_host_entry = self.multihost.external_hostname
        if len(client_name) > 15:
            client_name = client_name[:15]
        for spn in spn_list:
            spn_entry = '{}/{}'.format(spn, client_host_entry)
            # short spn entry
            short_entry = '{}/{}'.format(spn, client_host_entry)
            setspn_cmd = "setspn.exe -D %s %s" % (spn_entry, client_name)
            short_spn_cmd = "setspn.exe -D %s %s" % (short_entry,
                                                     client_name)
            try:
                self.adhost.run_command(setspn_cmd)
            except subprocess.CalledProcessError:
                pytest.fail("setspn failed to delete %s SPN" % spn)

            try:
                self.adhost.run_command(short_spn_cmd)
            except subprocess.CalledProcessError:
                pytest.fail("setspn failed to delete %s SPN" % (short_entry))


class LdapOperations(object):
    """
    LDapOperations consists of functions related to ldap operations, like
    adding entry, adding a DN, modifying DN, search entries.

    Attributes:
        uri(str): ldap server uri(ldap(s):///<hostname/ipaddress>
        binddn(str): Binddn required to bind
        bindpw(str): Bind password
        conn: ldap bind object (already  initialized)
    """

    def __init__(self, uri, binddn, bindpw, port=None):
        self.uri = uri if not port else '%s:%s' % (uri, port)
        self.binddn = binddn
        self.bindpw = bindpw
        self.conn = ldap.initialize(uri)
        self.conn = self.bind()

    def bind(self):
        """ Bind to ldap server
            :param: None
            :return: None
            :Exceptions: None
        """
        try:
            self.conn.simple_bind_s(self.binddn, self.bindpw)
        except ldap.SERVER_DOWN as err:
            return self._parseException(err)
        except ldap.INVALID_CREDENTIALS as err:
            return self._parseException(err)
        else:
            return self.conn

    def add_entry(self, entry, ldap_dn):
        """ Add an entry to ldap server
            :param dict entry: attributes/objectclass to be added to dn
            :param str dn: Entry dn to be added
        """
        print("Adding entry: %s" % (ldap_dn))
        ldif = modlist.addModlist(entry)
        self.conn.add_s(ldap_dn, ldif)
        return "Success", True

    def _parseException(self, err):
        """ Parsing Exception """
        return_value = False
        return err, return_value

    def del_dn(self, ldap_dn):
        """Delete dn
           :param str ldap_dn: DN to be deleted
           :return tupele: "Success", return_value
           :Exception: ldap exception
        """
        ret = self.conn.delete_s(ldap_dn)
        return "Success", ret

    def search(self, basedn, criteria, attributes, scope=ldap.SCOPE_SUBTREE):
        """ Search ldap server and return results

            :param str base: basedn of ldap server
            :param str criteria: Search criteria(ex:
                   "(&(objectClass=user)(sAMAccountName=Administrator))"
            :param str attributes: Attributes to be returned in the result
            :scope obj : scope to be used when search default:
                         ldap.SCOPE_SUBTREE
            :return tuple: Success/Fail, bool(True,False)
        """

        self.conn.set_option(ldap.OPT_REFERRALS, 0)
        result = self.conn.search_s(basedn, ldap.SCOPE_SUBTREE,
                                    criteria, attributes)
        result_set = [entry for _, entry in result if isinstance(entry, dict)]
        return result_set

    def modify_ldap(self, ldap_dn, modify_list):
        """ Modify ldap dn """
        try:
            self.conn.modify_s(ldap_dn, modify_list)
        except ldap.NO_SUCH_ATTRIBUTE:
            return "Fail", False
        except ldap.NO_SUCH_OBJECT as err:
            return self._parseException(err)
        except ldap.OBJECT_CLASS_VIOLATION as err:
            return self._parseException(err)
        except ldap.TYPE_OR_VALUE_EXISTS as err:
            return self._parseException(err)
        except ldap.UNWILLING_TO_PERFORM as err:
            return self._parseException(err)
        else:
            return 'Success', True

    def posix_user(self, org_unit, basedn, user_attr):
        """ Add POSIX Users
            :param str ou: Organizational unit (ou=Users)
            :param str basedn: Base dn ('dc=example,dc=test')
            :param dict user_attr: Entry attributes
            :Return bool: Return True
            :Exception: Raise LdapException if unable to add user
        """
        common_name = user_attr['cn']
        uid = user_attr['uid']
        uidnumber = user_attr['uidNumber']
        gidnumber = user_attr['gidNumber']
        try:
            surname = user_attr['sn']
        except KeyError:
            surname = common_name
        try:
            shell = user_attr['loginShell']
        except KeyError:
            shell = '/bin/bash'
        try:
            password = user_attr['userPassword']
        except KeyError:
            password = 'Secret123'
        try:
            home_directory = user_attr['homeDirectory']
        except KeyError:
            home_directory = '/home/%s' % (uid)
        try:
            mail = user_attr['mail']
        except KeyError:
            mail = '%s@example.test' % (uid)
        try:
            gecos = user_attr['gecos']
        except KeyError:
            gecos = '%s User' % common_name
        try:
            location = user_attr['location']
        except KeyError:
            location = 'US'

        attr = {
            'objectClass': [b'top', b'posixAccount', b'inetOrgPerson'],
            'cn': common_name.encode('utf-8'), 'uid': uid.encode('utf-8'),
            'sn': surname.encode('utf-8'), 'loginShell': shell.encode('utf-8'),
            'homeDirectory': home_directory.encode('utf-8'),
            'uidNumber': uidnumber.encode('utf-8'),
            'gidNumber': gidnumber.encode('utf-8'),
            'userPassword': password.encode('utf-8'),
            'mail': mail.encode('utf-8'), 'gecos': gecos.encode('utf-8'),
            'l': location.encode('utf-8')}

        user_dn = 'uid=%s,%s,%s' % (uid, org_unit, basedn)
        (ret, _) = self.add_entry(attr, user_dn)
        if ret == 'Success':
            return True
        else:
            raise LdapException('Unable to add User to ldap')

    def posix_group(self, org_unit, basedn, group_attr, memberUid=False):
        """ Add POSIX group
            :param str ou: Organizational unit (ou=Groups)
            :param str basedn: Base dn ('dc=example,dc=test')
            :param dict group_attr: Entry attributes
            :param memberUid: set by default to false, True when
             posix group add with memberUid
            :Return bool: Return True
            :Exception: Raise LdapException if unable to add user
        """
        attr = {}
        group_cn = group_attr['cn']
        gidnumber = group_attr['gidNumber']
        if memberUid:
            member_uid = group_attr['memberUid']
            objectClass = [b'posixGroup', b'top']
            attr['memberUid'] = member_uid.encode('utf-8')
        else:
            member_dn = group_attr['uniqueMember']
            objectClass = [b'posixGroup', b'top', b'groupOfUniqueNames']
            attr['uniqueMember'] = member_dn.encode('utf-8')
        user_password = '{crypt}x'
        attr['objectClass'] = objectClass
        attr['gidNumber'] = gidnumber.encode('utf-8')
        attr['cn'] = group_cn.encode('utf-8')
        attr['userPassword'] = user_password.encode('utf-8')
        group_dn = 'cn=%s,%s,%s' % (group_cn, org_unit, basedn)
        (ret, _) = self.add_entry(attr, group_dn)
        if ret != 'Success':
            raise LdapException('Unable to add group to ldap')

    def org_unit(self, org_unit, basedn):
        """ Add Organizational Unit
            :param str ou: Organizational unit name
            :param str basedn: Base dn ('dc=example,dc=test')
            :Exception: Raise LdapException if unable to organizational
        """
        attr = {
            'objectClass': [b'top', b'organizationalUnit'],
            'ou': org_unit.encode('utf-8')}
        org_dn = 'ou=%s,%s' % (org_unit, basedn)
        (ret, _) = self.add_entry(attr, org_dn)
        if ret != 'Success':
            raise LdapException('Unable to add organizational unit to ldap')

    def add_sudo_rule(self, ruledn, sudoHost,
                      sudoCommand, sudoUser, sudoOption=None):
        """ Add Sudo rules in Directory Server
            parm str ruledn: sudo rule DN
            param str sudoHost: Host on which sudo command should run
            param str sudoCommand: Command to run with sudo
            param str sudoUser: Posix user name
            param list sudoOption: options like requiretty,authenticate
        """
        rulename = ruledn.split(',')[0].split('=')[1]
        sudo_attr = {
            'objectClass': [b'top', b'sudoRole'],
            'cn': rulename.encode('utf-8'),
            'sudoHost': sudoHost.encode('utf-8'),
            'sudoCommand': sudoCommand.encode('utf-8'),
            'sudoUser': sudoUser.encode('utf-8')}
        (ret, _) = self.add_entry(sudo_attr, ruledn)

        if ret != 'Success':
            raise LdapException("Unable to add sudo rule %s" % ruledn)
        if sudoOption:
            for option in sudoOption:
                mod = [(ldap.MOD_ADD, 'sudoOption', option.encode('utf-8'))]
                (_, _) = self.modify_ldap(ruledn, mod)

    def create_netgroup(self, netgroupdn, NetgroupTriple):
        """ Create NIS Netgroup entry """
        cn = netgroupdn.split(',')[0].split('=')[1]
        netgroup_attr = {'objectClass': [b'top', b'nisNetgroup'],
                         'cn': cn.encode('utf-8'),
                         'nisNetgroupTriple': NetgroupTriple.encode('utf-8')}
        (ret, _) = self.add_entry(netgroup_attr, netgroupdn)
        assert ret == 'Success'

    def autofs_ad_schema(self, basedn):
        """ Enable autofs nis entries

            :param str basedn: base dn of the ldap server
            :return: None
            :Exceptions: None
        """

        autofs_schema = ("""
dn: ou=automount,%s
ou: automount
objectClass: organizationalUnit

dn: CN=auto.master,OU=automount,%s
objectClass: top
objectClass: nisMap
cn: auto.master
nisMapName: auto.master

dn: cn=/-,cn=auto.master,ou=automount,%s
objectClass: nisObject
objectClass: top
cn: /-
nisMapEntry: auto.direct
nisMapName: auto.master

dn: cn=auto.direct,ou=automount,%s
objectClass: nisMap
objectClass: top
cn: auto.direct
nisMapName: auto.direct

dn: cn=auto.home,ou=automount,%s
objectClass: nisMap
objectClass: top
nisMapName: auto.home""") % (basedn, basedn, basedn, basedn, basedn)
        ldif_file = StringIO(autofs_schema)
        parser = ldif.LDIFRecordList(ldif_file)
        parser.parse()

        for ldap_dn, entry in parser.all_records:
            self.add_entry(entry, ldap_dn)

    def autofs_nis_schema(self, basedn):
        """ Enable autofs ldap entries

            :param str basedn: base dn of the ldap server
            :return: None
            :Exceptions: None
        """

        autofs_schema = ("""
dn: ou=automount,%s
ou: automount
objectClass: organizationalUnit

dn: nisMapName=auto.direct,ou=automount,%s
objectClass: nisMap
objectClass: top
nisMapName: auto.direct

dn: nisMapName=auto.master,ou=automount,%s
objectClass: top
objectClass: nisMap
nisMapName: auto.master

dn: cn=/-,nisMapName=auto.master,ou=automount,%s
objectClass: nisObject
objectClass: top
cn: /-
nisMapEntry: auto.direct
nisMapName: auto.master

dn: nisMapName=auto.idmtest,ou=automount,%s
objectClass: top
objectClass: nisMap
nisMapName: auto.idmtest

dn: nisMapName=auto.home,ou=automount,%s
objectClass: top
objectClass: nisMap
nisMapName: auto.home

dn: cn=/idmtest,nisMapName=auto.master,ou=automount,%s
objectClass: nisObject
objectClass: top
cn: /idmtest
nisMapName: auto.master
nisMapEntry: auto.idmtest""") % (basedn, basedn, basedn, basedn,
                                 basedn, basedn, basedn)
        ldif_file = StringIO(autofs_schema)
        parser = ldif.LDIFRecordList(ldif_file)
        parser.parse()

        for ldap_dn, entry in parser.all_records:
            self.add_entry(entry, ldap_dn)

    def add_map(self, key, mapname, nfs_server, server_path, basedn):
        """ Add a nisobject to auto.direct map """
        entrydn = 'cn=%s,nisMapName=%s,ou=automount,%s' % (key, mapname,
                                                           basedn)
        nismapentry = '-fstype=nfs,rw %s:%s' % (nfs_server, server_path)
        attr = {
            'objectclass': [b'top', b'nisObject'],
            'cn': key.encode('utf-8'),
            'nisMapEntry': nismapentry.encode('utf-8'),
            'nisMapName': mapname.encode('utf-8')}
        (ret, _) = self.add_entry(attr, entrydn)
        return ret

    def delete_map(self, key, mapname, basedn):
        """ Remove nismap """
        entrydn = 'cn=%s,nisMapName=%s,ou=automount,%s' % (key, mapname,
                                                           basedn)
        (ret, _) = self.del_dn(entrydn)
        return ret


class PkiTools(object):
    """
        PkiTools consists of functions related to creation of
        certificate requests, updating profile XML with certificate
        requests.
    """

    def __init__(self, nssdir=None, nssdir_pwd=None):

        if nssdir is None:
            self.nssdb = tempfile.mkdtemp('nssdir')
        else:
            self.nssdb = nssdir
        if nssdir_pwd is None:
            self.nssdb_pwd = 'Secret12@38/-\245550'
        else:
            self.nssdb_pwd = nssdir_pwd
        self.pwdfilename = 'pwfile'
        self.noisefilename = 'noiseFile'
        self.pwdfilepath = os.path.join(self.nssdb, self.pwdfilename)
        self.noise = array.array('B', os.urandom(128))
        self.noisefilepath = os.path.join(self.nssdb, self.noisefilename)

    def create_nssdb(self):
        """
        Create a NSS Database on a temporary Directory

            :return:
            str nssdb: path of the NSS DB Directory
        """
        with open(self.pwdfilepath, 'w') as outfile:
            outfile.write(self.nssdb_pwd)
        certutil_cmd = 'certutil -N -d %s -f %s' % (self.nssdb,
                                                    self.pwdfilepath)
        _, _, ret = self.execute(shlex.split(certutil_cmd))
        if ret != 0:
            raise PkiLibException('Could not setup NSS DB on %s' % self.nssdb)
        else:
            return self.nssdb

    def execute(self,
                args,
                stdin=None,
                capture_output=True,
                raiseonerr=False,
                env=None,
                cwd=None):
        """
        Execute a command and return stdout, stderr and return code

        :param str args: List of arguments for the command
        :param str stdin: Optional input
        :param bool: capture_output: Capture output of the command
                     (default True)
        :param bool raiseonerr: Raise exception if command fails
        :param str env: Env variables to be set before the command is run
        :param str cwd: Current working Directory

        :return stdout, stderr and returncode: if command return code is 0
        :Exception: raises exception if raiseonerr is True
        """

        p_in = None
        p_out = None
        p_err = None
        if env is None:
            env = os.environ.copy()
        if capture_output:
            p_out = subprocess.PIPE
            p_err = subprocess.PIPE
        try:
            proc = subprocess.Popen(args, stdin=p_in, stdout=p_out,
                                    stderr=p_err, close_fds=True,
                                    env=env, cwd=cwd)
            stdout, stderr = proc.communicate(stdin)
        except KeyboardInterrupt:
            proc.wait()
            raise
        if proc.returncode != 0 and raiseonerr:
            raise subprocess.CalledProcessError(proc.returncode, args, stdout)
        else:
            return (stdout, stderr, proc.returncode)

    def createselfsignedcerts(self,
                              serverlist,
                              ca_dn=None,
                              passphrase='Secret12@38/-\245550',
                              canickname='ExampleCA'):
        """
        Creates a NSS DB in /tmp/nssDirxxxx where self signed Root CA
        and Server Certs are created

        :param str CA_DN: Distinguished Name for CA Cert
        :param str Server_DN: Distinguished Name for Server Cert
        """
        if ca_dn is None:
            ca_dn = 'CN=ExampleCA,O=Example,L=Raleigh,C=US'
        nss_passphrase = passphrase
        pin_filename = 'pin.txt'
        nss_dir = self.create_nssdb()
        pin_filepath = os.path.join(nss_dir, pin_filename)
        ca_pempath = os.path.join(nss_dir, 'cacert.pem')
        server_pempath = os.path.join(nss_dir, 'server.pem')
        ca_p12_path = os.path.join(nss_dir, 'ca.p12')
        # #server_p12_path = os.path.join(nss_dir, 'server.p12')
        with open(self.noisefilepath, 'w') as outfile:
            outfile.write(str(self.noise))
        keyUsage = 'digitalSignature,certSigning,crlSigning,critical'
        ca_args = 'certutil -d %s -f %s -S -n "%s" -s %s' \
                  ' -t "CT,," -x --keyUsage %s -z %s' % (nss_dir,
                                                         self.pwdfilepath,
                                                         canickname, ca_dn,
                                                         keyUsage,
                                                         self.noisefilepath)

        ca_pem = 'certutil -d %s -f %s -L -n "%s"' \
                 ' -a -o %s' % (nss_dir, self.pwdfilepath,
                                canickname, ca_pempath)
        with open(pin_filepath, 'w') as outfile:
            outfile.write('Internal (Software) Token:%s' % nss_passphrase)
        _, _, return_code = self.execute(shlex.split(ca_args))
        if return_code != 0:
            raise PkiLibException('Could not create Self signed CA Cert')
        else:
            self.execute(shlex.split(ca_pem))
        for server in serverlist:
            server_cn = 'CN=%s' % (server)
            server_nickname = 'Server-Cert-%s' % (server)
            server_pem = 'certutil -d %s -f %s -L '\
                         '-n "%s" -a -o %s' % (nss_dir,
                                               self.pwdfilepath,
                                               server_nickname,
                                               server_pempath)
            rand_var = str(random.randint(1000, 2000))
            server_args = 'certutil -d %s -f %s -S -n "%s" -s %s -c "%s"'\
                          ' -t u,u,u -v 720 -m %s -z %s' % (nss_dir,
                                                            self.pwdfilepath,
                                                            server_nickname,
                                                            server_cn,
                                                            canickname,
                                                            rand_var,
                                                            self.noisefilepath)
            _, _, return_code = self.execute(shlex.split(server_args))
            if return_code != 0:
                raise PkiLibException('Could not create Server-Cert')
            else:
                _, _, return_code = self.execute(shlex.split(server_pem))
                if return_code != 0:
                    raise PkiLibException('Could not create Server pem file')
                export_ca_p12 = 'pk12util -d %s -o %s -n "%s"'\
                                ' -k %s -w %s' % (nss_dir, ca_p12_path,
                                                  canickname, self.pwdfilepath,
                                                  self.pwdfilepath)
                _, _, return_code = self.execute(shlex.split(export_ca_p12))
                server_pkcs12_file = '%s-%s' % (server, 'server.p12')
                server_p12 = os.path.join(nss_dir, server_pkcs12_file)
                export_svr_p12 = 'pk12util -d %s -o %s -n %s'\
                                 ' -k %s -w %s' % (nss_dir, server_p12,
                                                   server_nickname,
                                                   self.pwdfilepath,
                                                   self.pwdfilepath)
                _, _, return_code = self.execute(shlex.split(export_svr_p12))
        return nss_dir


class ADOperations(object):  # pylint: disable=useless-object-inheritance
    """
    ADOperations class consists of methods related to managing AD User With
    Unix properties.
    """

    def __init__(self, ad_host):
        self.ad_host = ad_host
        self.ad_uri = 'ldap://%s' % ad_host.external_hostname
        # host_domain_basedn_entry = self.ad_host.domain_basedn_entry
        self.ad_basedn = self.ad_host.domain_basedn_entry
        self.ad_users_dn_entry = '{},{}'.format('CN=Users', self.ad_basedn)
        self.ad_dn = 'CN={},{}'.format("Administrator", self.ad_users_dn_entry)
        self.ad_admin_passwd = self.ad_host.ssh_password
        cmd = ['powershell.exe',
               '-inputformat',
               'none',
               '-noprofile',
               '(Get-ADDomain -Current LocalComputer).NetBIOSName']
        self._ad_netbionsname = self.ad_host.run_command(cmd).stdout_text

    def ad_conn(self):
        """ Create a LDAP Connection with AD

        :param None
        :Return obj: Object of LdapOperations
        :Exceptions: None
        """

        ad_conn_inst = LdapOperations(self.ad_uri, self.ad_dn,
                                      self.ad_admin_passwd)
        return ad_conn_inst

    def create_ad_unix_user_group(self, username, groupname,
                                  mail=None, password='Secret123', uid=None):
        """ Create a AD User with Unix Attributes

        :param str username: AD User Name
        :param str groupname: AD Group Name
        :param str mail: AD User e-mail address
        :param str password: User password (default: Secret123)
        :param int uid: User uid
        :Return bool: if user/group added correctly return True else False
        :Exceptions: False
        """
        # pylint: disable=too-many-arguments
        if uid is None:
            uid = random.randint(9999, 999999)

        user = self.create_ad_nonposix_user(username, password)
        group = self.create_ad_unix_group(groupname, gid=uid)
        mbr = self.add_user_member_of_group(groupname, username)

        if mail is None:
            mail = '%s@%s' % (username, self.ad_host.realm)

        usr = f"powershell.exe -inputformat none -noprofile 'Set-ADUser " \
              f"-Identity \"{username}\" -Add @{{" \
              f"msSFU30NisDomain = \"{self.ad_host.netbiosname}\";" \
              f"uidNumber = \"{str(uid)}\";" \
              f"gidNumber = \"{str(uid)}\";" \
              f"unixHomeDirectory = \"/home/{username}\";"\
              f"loginShell = \"/bin/bash\";" \
              f"msSFU30Name = \"{username}\";" \
              f"mail = \"{mail}\";" \
              f"}}'"
        usr_res = self.ad_host.run_command(usr, raiseonerr=False)
        mod = usr_res.returncode == 0
        return user and group and mbr and mod

    def create_ad_unix_user(self, username, mail=None,
                            password='Secret123', uid=None):
        """ Create a AD User with Unix Attributes
        :param str username: AD User Name
        :param str mail: AD User e-mail address
        :param str password: User password (default: Secret123)
        :param int uid: User uid
        :Return bool: if user added correctly return True else False
        :Exceptions: False
        """
        if uid is None:
            uid = random.randint(9999, 999999)

        user = self.create_ad_nonposix_user(username, password)

        if mail is None:
            mail = f'{username}@{self.ad_host.realm}'

        usr = f"powershell.exe -inputformat none -noprofile 'Set-ADUser " \
              f"-Identity \"{username}\" -Add @{{" \
              f"msSFU30NisDomain = \"{self.ad_host.netbiosname}\";" \
              f"uidNumber = \"{str(uid)}\";" \
              f"gidNumber = \"{str(uid)}\";" \
              f"unixHomeDirectory = \"/home/{username}\";"\
              f"loginShell = \"/bin/bash\";" \
              f"msSFU30Name = \"{username}\";" \
              f"mail = \"{mail}\";" \
              f"}}'"
        usr_res = self.ad_host.run_command(usr, raiseonerr=False)
        mod = usr_res.returncode == 0
        return user and mod

    def create_ad_unix_group(self, groupname, gid=None):
        """ Create AD Group with UNIX Attributes

        :param str groupname: Windows AD Group name
        :param int gid: Windows AD Group gid
        :Return bool : True if AD group was created with Unix Attributes
        :Exceptions: None
        """
        if gid is None:
            gid = random.randint(9999, 999999)
        self.create_ad_nonposix_group(groupname)
        mod_grp = f"powershell.exe -inputformat none -noprofile '" \
                  f"Set-ADGroup -Identity \"{groupname}\" -Add @{{" \
                  f"msSFU30NisDomain = \"{self.ad_host.netbiosname}\";" \
                  f"gidNumber = \"{str(gid)}\";" \
                  f"msSFU30Name = \"{groupname}\";" \
                  f"}}'"
        grp_result = self.ad_host.run_command(mod_grp, raiseonerr=False)
        return grp_result.returncode == 0

    def create_ad_nonposix_user(self, username, password='Secret123'):
        """ Create AD User without UNIX Attributes

        :param str username: Windows AD User name
        :param str password: Windows AD User password (default: Secret123)
        :Return bool : True if a nonposix AD user was created
        :Exceptions: None
        """
        new_usr = f"powershell.exe -inputformat none -noprofile '" \
                  f"New-ADUser -Name \"{username}\" -Enabled $true " \
                  f"-Accountpassword (ConvertTo-SecureString -String " \
                  f"\"{password}\" -AsPlainText -Force) '"
        usr_result = self.ad_host.run_command(new_usr, raiseonerr=False)
        return usr_result.returncode == 0

    def create_ad_nonposix_group(self, groupname):
        """ Create AD Group without UNIX Attributes

        :param str groupname: Windows AD Group name
        :Return bool : True if a nonposix AD group was created
        :Exceptions: None
        """
        new_grp = f"powershell.exe -inputformat none -noprofile '" \
                  f"New-ADGroup -Name \"{groupname}\" -GroupScope Global '"
        grp_result = self.ad_host.run_command(new_grp, raiseonerr=False)
        return grp_result.returncode == 0

    def delete_ad_user_group(self, user_group):
        """ Delete AD user or group

        :param str user_group: User or Group Name to be deleted
        :Return bool: True if delete is successful else False
        :Exceptions: None
        """
        # Original implementation was using dsrm which was able to delete both
        # group and user without making any difference. To keep the
        # compatibility with existing tests we use this less-than-elegant way.

        grp = f"powershell.exe -inputformat none -noprofile '" \
              f"Remove-ADGroup -Confirm:$False -Identity \"{user_group}\"'"

        usr = f"powershell.exe -inputformat none -noprofile '" \
              f"Remove-ADUser -Confirm:$False -Identity \"{user_group}\"'"

        if "group" in user_group:
            grp_result = self.ad_host.run_command(grp, raiseonerr=False)
            result = grp_result.returncode == 0
        elif "user" in user_group:
            usr_result = self.ad_host.run_command(usr, raiseonerr=False)
            result = usr_result.returncode == 0
        else:
            grp_result = self.ad_host.run_command(grp, raiseonerr=False)
            usr_result = self.ad_host.run_command(usr, raiseonerr=False)
            result = usr_result.returncode == 0 or grp_result.returncode == 0
        return result

    def add_user_member_of_group(self, group, user):
        """ Add user or group member of a group

        :param str group: Name of Windows AD Group
        :param str user: Name of Windows AD user or group
        :Return bool: True if member is added to group
        :Exceptions: None
        """
        mod_mbr = f"powershell.exe -inputformat none -noprofile '" \
                  f"Add-ADGroupMember -Identity \"{group}\" " \
                  f"-Members \"{user}\"'"
        grp_result = self.ad_host.run_command(mod_mbr, raiseonerr=False)
        return grp_result.returncode == 0

    def remove_user_from_group(self, group, user):
        """ Remove User or Group from Group membership

        :param str group: Name of Windows AD Group
        :param str user: Name of Windows AD user or group
        :Return bool: True if member is removed from group else False
        :Exceptions: None
        """
        del_mbr = f"powershell.exe -inputformat none -noprofile '" \
                  f"Remove-ADGroupMember -Identity \"{group}\" " \
                  f"-Members \"{user}\" -Confirm:$False'"
        grp_result = self.ad_host.run_command(del_mbr, raiseonerr=False)
        return grp_result.returncode == 0

    def add_autofs_schema(self):
        """Create autofs schema on AD server"""
        add_ou = f"powershell.exe -inputformat none -noprofile '" \
                 f"New-ADOrganizationalUnit  -Name \"automount\" " \
                 f"-Path \"{self.ad_basedn}\" -Confirm:$False " \
                 f"-ProtectedFromAccidentalDeletion $false'"
        self.ad_host.run_command(add_ou, raiseonerr=False)

        add_top = f"powershell.exe -inputformat none -noprofile '" \
                  f"New-ADObject -Name \"auto.master\" -Path \"OU=automount," \
                  f"{self.ad_basedn}\" -Type nisMap -OtherAttributes " \
                  f"@{{\"nisMapName\"=\"auto.master\"}}'"
        self.ad_host.run_command(add_top)

        add_root = f"powershell.exe -inputformat none -noprofile '" \
                   f"New-ADObject -Name \"/-\" -Path \"CN=auto.master," \
                   f"OU=automount,{self.ad_basedn}\" -Type nisObject " \
                   f"-OtherAttributes @{{\"nisMapName\"=\"auto.master\" ; " \
                   f"\"nisMapEntry\"=\"auto.direct\"}}'"
        self.ad_host.run_command(add_root)

        add_direct = f"powershell.exe -inputformat none -noprofile '" \
                     f"New-ADObject -Name \"auto.direct\" -Path \"" \
                     f"OU=automount,{self.ad_basedn}\" -Type nisMap " \
                     f"-OtherAttributes @{{\"nisMapName\"=\"auto.direct\"}}'"
        self.ad_host.run_command(add_direct)

        add_home = f"powershell.exe -inputformat none -noprofile '" \
                   f"New-ADObject -Name \"auto.home\" -Path \"" \
                   f"OU=automount,{self.ad_basedn}\" -Type nisMap " \
                   f"-OtherAttributes @{{\"nisMapName\"=\"auto.home\"}}'"
        self.ad_host.run_command(add_home)

    def add_map(self, name, nfs_server):
        """ Add a nisobject to auto.direct map """
        entrydn = f'cn=auto.direct,ou=automount,{self.ad_basedn}'
        nismapentry = f'-fstype=nfs,rw {nfs_server}:{name}'

        add_map = f"powershell.exe -inputformat none -noprofile '" \
                  f"New-ADObject -Name \"{name}\" -Path \"" \
                  f"{entrydn}\" -Type nisObject " \
                  f"-OtherAttributes @{{\"nisMapName\"=\"auto.direct\" ; " \
                  f"\"nisMapEntry\"=\"{nismapentry}\"}}'"
        add = self.ad_host.run_command(add_map, raiseonerr=False)
        ret = 'Success' if add.returncode == 0 else 'Failed to add an ADObject'
        return ret

    def delete_map(self, name):
        """ Remove nismap """
        del_map = f"powershell.exe -inputformat none -noprofile '" \
                  f"Remove-ADObject -Confirm:$False -Identity " \
                  f"\"CN={name},cn=auto.direct,ou=automount,{self.ad_basedn}\"'"
        del_cmd = self.ad_host.run_command(del_map, raiseonerr=False)
        ret = 'Success' if del_cmd.returncode == 0 else 'Failed to ' \
                                                        'delete an ADObject'
        return ret

    def add_sudo_ou(self, verbose=True, raiseonerr=True):
        """ Add SudoOU in Active Directory Server
        parm bool verbose: Log command output
        parm bool raiseonerr: Raise exception on command failure
        return bool: Returns true if operation succeeded
        """
        add_ou = f"powershell.exe -inputformat none -noprofile '" \
                 f"New-ADOrganizationalUnit  -Name \"Sudoers\" " \
                 f"-Path \"{self.ad_basedn}\" -Confirm:$False " \
                 f"-ProtectedFromAccidentalDeletion $false'"
        cmd = self.ad_host.run_command(
            add_ou, log_stdout=verbose, raiseonerr=raiseonerr)
        return cmd.returncode == 0

    def del_sudo_ou(self, verbose=False, raiseonerr=False):
        """ Delete SudoOU in Active Directory Server
        parm bool verbose: Log command output
        parm bool raiseonerr: Raise exception on command failure
        return bool: Returns true if operation succeeded
        """
        sudo_ou = f'ou=Sudoers,{self.ad_basedn}'
        remove_sudo = f"powershell.exe -inputformat none -noprofile " \
                      f"'(Remove-ADOrganizationalUnit -Recursive " \
                      f"-Identity \"{sudo_ou}\" -Confirm:$false)'"
        cmd = self.ad_host.run_command(
            remove_sudo, log_stdout=verbose, raiseonerr=raiseonerr)
        return cmd.returncode == 0

    def add_sudo_rule(self, ruledn, host, command, users=[], options=[],
                      runas=None, runasuser=None, runasgroup=None,
                      notbefore=None, notafter=None, order=None,
                      verbose=True, raiseonerr=True):
        """ Add Sudo rules in Active Directory Server
        parm str ruledn: sudo rule DN
        param str host: Host on which sudo command should run
        param str command: Command to run with sudo
        param str/list users: list of Posix user name
        param str/list options: options like requiretty, authenticate
        param str runas: sudoRunAs parameter of sudo rule
        param str runasuser: sudoRunAsUser parameter of sudo rule
        param str runasgroup: sudoRunAsGroup parameter of sudo rule
        param str notbefore: sudoNotBefore parameter of sudo rule
        param str notafter: sudoNotAfter parameter of sudo rule
        param str order: sudoOrder parameter of sudo rule
        parm bool verbose: Log command output
        parm bool raiseonerr: Raise exception on command failure
        return bool: Returns true if operation succeeded
        """
        rulename = ruledn.split(',')[0].split('=')[1]
        rulepath = ",".join(ruledn.split(',')[1:])

        def _wrap_in_quotes(items):
            """Wraps the items in double quotes and concatenates
            them with commas if needed.
            param list/str items: item(s) to be wrapped in quotes
            return: str
            """
            if type(items) == str:
                return f'"{items}"'
            if type(items) == list:
                items = [f'"{x}"' for x in items]
                return ','.join(items)
            raise ValueError(f"Incorrect parameter type {type(items)}!")

        opt_str = ""
        if options:
            opt_str = f"\"sudoOption\"={_wrap_in_quotes(options)};"
        if runas:
            opt_str += f"\"sudoRunAs\"=\"{runas}\";"
        if runasuser:
            opt_str += f"\"sudoRunAsUser\"=\"{runasuser}\";"
        if runasgroup:
            opt_str += f"\"sudoRunAsGroup\"=\"{runasgroup}\";"
        if notbefore:
            opt_str += f"\"sudoNotBefore\"=\"{notbefore}\";"
        if notafter:
            opt_str += f"\"sudoNotAfter\"=\"{notafter}\";"
        if order:
            opt_str += f"\"sudoOrder\"=\"{order}\";"
        if users:
            opt_str += f"\"sudoUser\"={_wrap_in_quotes(users)};"

        add_rule = f"powershell.exe -inputformat none -noprofile '" \
                   f"New-ADObject -Name \"{rulename}\" -Path \"" \
                   f"{rulepath}\" -Type \"sudoRule\" " \
                   f"-OtherAttributes @{{\"objectClass\"=\"sudoRole\";" \
                   f"\"sudoHost\"=\"{host}\";" \
                   f"\"sudoCommand\"=\"{command}\";{opt_str} }}'"
        add = self.ad_host.run_command(
            add_rule, log_stdout=verbose, raiseonerr=raiseonerr)
        if verbose:
            # Search for the rule and display it in the log
            show_rule = f"powershell.exe -inputformat none -noprofile '" \
                        f"Get-ADObject -Identity \"{ruledn}\" -Properties *'"
            self.ad_host.run_command(show_rule, raiseonerr=False)
        return add.returncode == 0

    def del_sudo_rule(self, ruledn, verbose=True, raiseonerr=False):
        """ Delete Sudo rule from Active Directory Server
        parm str ruledn: sudo rule DN
        parm bool verbose: Log command output
        parm bool raiseonerr: Raise exception on command failure
        return bool: Returns true if operation succeeded
        """
        del_rule = f"powershell.exe -inputformat none -noprofile '" \
                   f"Remove-ADObject -Identity \"{ruledn}\" " \
                   f" -Confirm:$False '"
        del_cmd = self.ad_host.run_command(
            del_rule, log_stdout=verbose, raiseonerr=raiseonerr)
        return del_cmd.returncode == 0

    def expire_account(self, user):
        """ Expire User account

        :param str user: Name of Windows AD user
        :Return bool: True if user is expired else False
        :Exceptions: None
        """
        try:
            self.ad_host.run_command(
                f"powershell -inputformat none -noprofile '"
                f"Set-ADAccountExpiration -identity"
                f" \"{user}\" -DateTime \"12/18/2011\"'"
            )
        except subprocess.CalledProcessError:
            return False
        return True

    def unexpire_account(self, user):
        """ Un-expire User account
        :param str user: Name of Windows AD user
        :Return bool: True if user is unexpired else False
        :Exceptions: None
        """
        try:
            self.ad_host.run_command(
                f"powershell -inputformat none -noprofile '"
                f"Set-ADAccountExpiration -identity"
                f" \"{user}\" -DateTime \"10/05/2036\"'"
            )
        except subprocess.CalledProcessError:
            return False
        return True

    def disable_account(self, user):
        """ Disable User account
        :param str user: Name of Windows AD user
        :Return bool: True if user is disabled else False
        :Exceptions: None
        """
        try:
            self.ad_host.run_command(
                f"powershell -inputformat none -noprofile '"
                f"Disable-ADAccount -identity \"{user}\"'"
            )
        except subprocess.CalledProcessError:
            return False
        return True

    def enable_account(self, user):
        """ Enable User account
        :param str user: Name of Windows AD user
        :Return bool: True if user is enabled else False
        :Exceptions: None
        """
        try:
            self.ad_host.run_command(
                f"powershell -inputformat none -noprofile '"
                f"Enable-ADAccount -identity \"{user}\"'"
            )
        except subprocess.CalledProcessError:
            return False
        return True

    def expire_account_password(self, user):
        """ Expire account password
        :param str user: Name of Windows AD user
        :Return bool: True if user password is expired else False
        :Exceptions: None
        """
        try:
            self.ad_host.run_command(
                f"powershell -inputformat none -noprofile 'Set-ADUser"
                f" -identity \"{user}\" -Replace @{{pwdLastSet=0}}'"
            )
        except subprocess.CalledProcessError:
            return False
        return True

    def unexpire_account_password(self, user):
        """ Unexpire account password
        :param str user: Name of Windows AD user
        :Return bool: True if user password is unexpired else False
        :Exceptions: None
        """
        try:
            self.ad_host.run_command(
                f"powershell -inputformat none -noprofile 'Set-ADUser"
                f" -identity \"{user}\" -Replace @{{pwdLastSet=-1}}'"
            )
        except subprocess.CalledProcessError:
            return False
        return True

    def get_user_info(self, user):
        """ Dump user account information from AD as a dictionary
        Empty dictionary is returned if user is not found.
        :param str user: Name of Windows AD user
        :Return dict: Dictionary with the fields from AD
        """
        info_cmd = f"powershell.exe -inputformat none -noprofile '" \
                   f"Get-ADUser -Identity {user} -Properties *'"
        cmd = self.ad_host.run_command(info_cmd, raiseonerr=False)
        user_info = {}
        lines = cmd.stdout_text.split('\n')
        for idx, line in enumerate(lines):
            if ':' in line:
                parts = line.split(':')
                item_name = parts[0].strip()
                user_info[item_name] = parts[1].strip()
                # Handle line continuation
                if idx + 1 < len(lines):
                    if ":" not in lines[idx + 1]:
                        user_info[item_name] += lines[idx + 1].strip()
        return user_info

    def get_group_info(self, group):
        """ Dump group account information from AD as a dictionary
        Empty dictionary is returned if group is not found.
        :param str group: Name of Windows AD user
        :Return dict: Dictionary with the fields from AD
        """
        info_cmd = f"powershell.exe -inputformat none -noprofile '" \
                   f"Get-ADGroup -Identity {group} -Properties *'"
        cmd = self.ad_host.run_command(info_cmd, raiseonerr=False)
        group_info = {}
        lines = cmd.stdout_text.split('\n')
        for idx, line in enumerate(lines):
            if ':' in line:
                parts = line.split(':')
                item_name = parts[0].strip()
                group_info[item_name] = parts[1].strip()
                # Handle line continuation
                if idx + 1 < len(lines):
                    if ":" not in lines[idx + 1]:
                        group_info[item_name] += lines[idx + 1].strip()
        return group_info

    @staticmethod
    def compute_id_mapping(
            object_sid, primary_group=0, range_min=200000, range_size=400000,
            range_max=2000200000):
        """ Compute the uid/gid based on its object_sid and primary group id.
        When used for user, first value is uid, second gid.
        When used for group, primary_group should be 0 and gid will be the
        first item in the tuple, the second one will be the start of ids.
        :param str object_sid: objectSid
        :param int primary_group: primary group id
        :param int range_min: lower bound of the id range
        :param int range_size: size of the the id range
        :param int range_max: upper bound of the range (ldap_idmap_range_size)
        :Return tuple of int: computed uid/gid of the object
        """
        # Get domain sid
        domain_sid = "-".join(object_sid.split("-")[0:-1])
        # Get rid
        rid = int(object_sid.split("-")[-1])
        number_hash = mmh3.hash(domain_sid, seed=0xdeadbeef) & 0xffffffff
        slice_max = (range_max - range_min) // range_size
        slice_val = number_hash % slice_max
        uid = range_size * slice_val + rid + range_min
        gid = range_size * slice_val + range_min + primary_group
        return uid, gid


class ADDNS(object):  # pylint: disable=useless-object-inheritance
    """ ADDNS class consists of methods to search and manage AD DNS """

    def __init__(self, ad_host):
        self.ad_host = ad_host

    def get_zones(self):
        """ Returns a list of all the forward and reverse zones  on the server excluding msdcs """
        zones = self.ad_host.run_command("dnscmd.exe /EnumZones").stdout_text
        zone_list = re.sub("\n\s*\n", "\n", re.sub("(.*?)Cache(.*?)\n|(.*?)Zone(.*?)\n|(.*?)Enumerated(.*?)\n|"
                           "(.*?)_msdcs(.*?)\n|(.*?)Command(.*?)\n", "", zones))
        return zone_list

    def print_zone(self, zone):
        """ Prints all the contents of a zone file, takes domain.com or 1.168.192.in-addr.arpa string """
        zone_out = self.ad_host.run_command(f"dnscmd.exe /zoneprint {zone}").stdout_text
        zone = re.sub("\n\s*\n", "\n", re.sub("[;_](.*?)\n|.*?(NS|SOA|DnsZones|@).*?\n", "", zone_out))

        return zone

    def find_a(self, hostname, ip):
        """ Searches the zone for a specific A record, returning True for success and False for failure """
        domain = self.ad_host.realm.lower()
        host = str(hostname.split(".")[0])
        for x in range(0, 600, 15):
            results = self.print_zone(domain)
            if re.search(f'{host} .*A.*{ip}', results, re.M):
                return True
            else:
                time.sleep(15)
                x += 15
                print(results)
        return False

    def find_ptr(self, hostname, ip):
        """ Searches the zone for a specific PTR record, returning True for success and False for failure """
        hostname += '.'
        net = str(ip.split(".")[2]) + '.' + str(ip.split(".")[1]) + '.' + str(ip.split(".")[0]) + '.in-addr.arpa'
        ptr = str(ip.split(".")[3])
        for x in range(0, 600, 15):
            results = self.print_zone(net)
            if re.search(f'{ptr} .*PTR.*{hostname}', results, re.M):
                return True
            else:
                time.sleep(15)
                x += 15
                print(results)
        return False

    def add_zone(self, zone):
        """ Adds a forward or reverse zone with dynamic updates in AD DNS, True if zone is listed and False if not """
        self.ad_host.run_command(f"dnscmd.exe /zoneadd {zone} /primary", raiseonerr=False)
        self.ad_host.run_command(f"dnscmd.exe /config {zone} /allowupdate 1", raiseonerr=False)
        check_zone = self.get_zones()
        if zone in check_zone:
            return True
        return False

    def del_zone(self, zone):
        """ Deletes the DNS forward or reverse zone in AD DNS, True if not found in zone list and False if found """
        self.ad_host.run_command(f"dnscmd.exe /zonedelete {zone} /f", raiseonerr=False)
        check_zone = self.get_zones()
        if zone not in check_zone:
            return True
        return False

    def del_record(self, record):
        """ Deletes both A/AAAA records when a hostname is used, deletes the PTR when an IP address is used """
        domain = str(self.ad_host.realm).lower()
        if domain in record:
            hostname = record
            short_hostname = hostname.split(".")[0]
            self.ad_host.run_command(f"dnscmd.exe /recorddelete {domain} {short_hostname} A /f", raiseonerr=False)
            self.ad_host.run_command(f"dnscmd.exe /recorddelete {domain} {short_hostname} AAAA /f", raiseonerr=False)
        else:
            ip = record
            net = str(ip.split(".")[2]) + '.' + str(ip.split(".")[1]) + '.' + str(ip.split(".")[0]) + '.in-addr.arpa'
            ptr = str(ip.split(".")[3])
            self.ad_host.run_command(f"dnscmd.exe /recorddelete {net} {ptr} PTR /f", raiseonerr=False)

