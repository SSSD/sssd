""" This provides common functions for ipa """
from sssd.testlib.common.exceptions import SSSDException
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.exceptions import SSHLoginException
import subprocess
import pexpect


class ipaTools(object):
    """ Collection of assorted functions for ipa to be used in fixtures
        Attributes:
          Host(obj: `Multihost object type`): Multihost Object
    """
    def __init__(self, Host):
        """ Initialize multihost """
        self.multihost = Host

    def install_common_pkgs(self):
        """ Install common required packages """
        pkgs = 'ldb-tools tcpdump wireshark-cli expect'
        if '8.' in self.multihost.distro:
            enable_idm1 = "dnf -y module reset idm"
            self.multihost.run_command(enable_idm1)
            enable_idm2 = "dnf -y module enable idm:DL1"
            self.multihost.run_command(enable_idm2)
            enable_idm3 = "dnf -y module install idm:DL1/client"
            self.multihost.run_command(enable_idm3)
        if 'Fedora' in self.multihost.distro:
            client_pkgs = ' freeipa-client'
            pkgs = pkgs + client_pkgs
        self.multihost.package_mgmt(pkgs, action='install')

    def setup_chrony(self, ntp_server='pool.ntp.org'):
        """ Setup chrony
            Attributes:
            ntp_server(str): NTP server. Default ntp_server is pool.ntp.org
            Return: bool
        """
        stop_chrony = 'systemctl stop chronyd'
        self.multihost.run_command(stop_chrony)
        cmd = "chronyd -q 'server %s iburst'" % ntp_server
        try:
            self.multihost.run_command(cmd)
        except subprocess.CalledProcessError:
            raise SSSDException("Unable to set ntp server")

        start_chrony = 'systemctl start chronyd'
        try:
            self.multihost.run_command(cmd)
        except subprocess.CalledProcessError:
            return False
        else:
            return True

    def get_default_nw_uuid(self):
        """ Get default network interface uuid"""
        nmcli_cmd = "nmcli con show --active"
        cmd = self.multihost.run_command(nmcli_cmd, raiseonerr=False)
        conn_list = cmd.stdout_text.split('\n')[1].split(' ')
        filtered_list = list(filter(None, conn_list))
        return filtered_list[2]

    def get_interface_ip(self, uuid):
        """ Get IP Address associated with interface
            using nmcli
        """
        if uuid is None:
            return False
        nmcli_cmd = "nmcli -f IP4.ADDRESS conn show %s" % uuid
        cmd = self.multihost.run_command(nmcli_cmd, raiseonerr=False)
        if cmd.returncode == 0:
            ipaddr = cmd.stdout_text.split()[1].split('/')[0]
            return ipaddr
        else:
            return False

    def add_hbac_rule(self, rulename, username, hostname,
                      service, group=False):
        """ Add IPA hbac rule """
        # add rule
        add_rule = "ipa hbacrule-add %s" % rulename
        # add user
        if group:
            add_user = "ipa hbacrule-add-user --groups %s %s" % (username,
                                                                 rulename)
        else:
            add_user = "ipa hbacrule-add-user --users %s %s" % (username,
                                                                rulename)
        # add host
        add_host = "ipa hbacrule-add-host --hosts %s %s " % (hostname,
                                                             rulename)
        # add service
        add_service = "ipa hbacrule-add-service --hbacsvcs=%s %s" % (service,
                                                                     rulename)
        cmd_list = [add_rule, add_user, add_host, add_service]
        for cmd in cmd_list:
            ret = self.multihost.run_command(cmd, raiseonerr=False)
            if ret.returncode != 0:
                raise SSSDException(ret.stderr_text)

    def del_hbac_rule(self, rulename):
        """ Delete hbac rule """
        # delete rule
        del_rule = "ipa hbacrule-del %s" % rulename
        ret = self.multihost.run_command(del_rule, raiseonerr=False)
        if ret.returncode != 0:
            raise SSSDException(ret.stderr_text)

    def ssh_login(self, username, password, host, command=None):
        """ SSH login to host """
        pxssh = pexpect_ssh(host, username, password, debug=False)
        try:
            pxssh.login()
        except SSHLoginException:
            return False
        except pexpect.exceptions.EOF:
            return False
        else:
            if command:
                (output, ret) = pxssh.command('id')
                print(output)
                print("Return status: ", ret)
        pxssh.logout()
        del pxssh
        return True

    def create_group(self, group_name, external=False):
        """ Create external groups for Active Directory """
        if external:
            grp_add = "ipa group-add --desc='%s users external map' "\
                      "%s --external" % (group_name, group_name)
        else:
            grp_add = "ipa group-add --desc='%s users' %s" % (group_name,
                                                              group_name)
        cmd = self.multihost.run_command(grp_add, raiseonerr=False)
        if cmd.returncode != 0:
            raise SSSDException(cmd.stderr_text)

    def group_add_member(self, source_group, target_group, external=False):
        """ Make source group member of target group """
        if external:
            add_mem = "ipa -n group-add-member %s "\
                      "--external %s" % (target_group, source_group)
        else:
            add_mem = "ipa group-add-member %s --groups %s" % (target_group,
                                                               source_group)
        cmd = self.multihost.run_command(add_mem, raiseonerr=False)
        if cmd.returncode != 0:
            raise SSSDException(cmd.stderr_text)
