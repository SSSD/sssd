""" Automation of sanity/services suite"""
from __future__ import print_function
import pytest
import paramiko
import re
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSHClient


@pytest.mark.usefixtures('default_sssd')
@pytest.mark.services
class TestServices(object):
    """ SSSD sanity services """
    @pytest.mark.tier1
    def test_0001_bz1432010(self, multihost):
        """
        :Title: IDM-SSSD-TC: sanity: services: SSSD ships a drop-in
        configuration snippet in /etc/systemd/system
        """
        rpm_grep = 'rpm -ql sssd-common'
        cmd = multihost.client[0].run_command(rpm_grep, raiseonerr=False)
        assert cmd.stdout_text.find('/etc/systemd/system') == -1

    @pytest.mark.tier1
    def test_0002_1736796(self, multihost, localusers):
        """
        :Title: config: "default_domain_suffix" should not
        cause files domain entries to be qualified, this can break sudo access
        """
        users = localusers
        for user in users.keys():
            allow_sudo = '%s    ALL=(ALL) NOPASSWD:ALL' % user
            sudoers_file = '/etc/sudoers.d/%s' % user
            multihost.client[0].put_file_contents(sudoers_file, allow_sudo)
        tools = sssdTools(multihost.client[0])
        sssd_params = {'default_domain_suffix': 'foo'}
        tools.sssd_conf('sssd', sssd_params)
        multihost.client[0].service_sssd('restart')
        for user in users.keys():
            try:
                ssh = SSHClient(multihost.client[0].external_hostname,
                                username=user,
                                password='Secret123')
            except paramiko.ssh_exception.AuthenticationException:
                pytest.fail("%s failed to login" % user)
            else:
                (stdout, _, exit_status) = ssh.execute_cmd('id')
                for line in stdout.readlines():
                    if '%s@implicit_files' % (user) in line:
                        pytest.fail("id command contains implicit_files")
                (_, _, exit_status) = ssh.execute_cmd('sudo su - -c id')
                assert exit_status == 0
            if exit_status != 0:
                journalctl_cmd = 'journalctl -x -n 100 --no-pager'
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("%s cmd failed for user %s" % ('sudo su - -c id',
                                                           user))
            ssh.close()
        for user in users.keys():
            sudoers_file = '/etc/sudoers.d/%s' % user
            delete_file = 'rm -f %s' % sudoers_file
            multihost.client[0].run_command(delete_file)

    @pytest.mark.tier1
    def test_0003_bz1713368(self, multihost):
        """
        :Title: services: Add sssd-dbus package as a dependency of sssd-tools
        """
        # sssd-dbus is a weak dependency of sssd-tools package so we did not
        # get sssd-dbus in '# yum deplist sssd-tools' command
        rpm_grep = 'yum repoquery --recommends sssd-tools'
        cmd = multihost.client[0].run_command(rpm_grep, raiseonerr=False)
        if cmd.returncode == 0:
            status = 'PASS'
            find = re.compile(r'sssd-dbus')
            result = find.search(cmd.stdout_text)
            if result is None:
                status = 'FAIL'
            assert status != 'FAIL'

    @pytest.mark.tier1
    def test_0004_membership_with_files_provider(self, multihost):
        """
        :Title: services: SSSD must be able to resolve
        membership involving root with files provider
        @bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1794607
        """
        # take backup:
        back_up = "cp -vf /etc/pam.d/su /etc/pam.d/su_bkp"
        cmd = multihost.client[0].run_command(back_up, raiseonerr=False)
        ps_cmd = "sed -i '/sufficient/s/#auth/auth/' /etc/pam.d/su"
        cmd = multihost.client[0].run_command(ps_cmd)
        useradd = "useradd -g root -G wheel user_its_some"
        cmd = multihost.client[0].run_command(useradd, raiseonerr=False)
        check_wheel = "runuser -l user_its_some -c 'getent group wheel'"
        cmd = multihost.client[0].run_command(check_wheel, raiseonerr=False)
        if 'wheel:x:10:user_its_some' in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        # restore
        restore = "cp -vf /etc/pam.d/su_bkp /etc/pam.d/su "
        cmd = multihost.client[0].run_command(restore, raiseonerr=False)
        # clean up
        deluser = "userdel  user_its_some"
        cmd = multihost.client[0].run_command(deluser, raiseonerr=False)
        if cmd.returncode != 0:
            status = 'FAIL'
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0005_sssd_stops_monitoring(self, multihost):
        """
        :Title: services: When the passwd or group files
        are replaced, sssd stops monitoring the file for
        inotify events, and no updates are triggered
        @bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1827432
        """
        group_bkp = "cp -vf /etc/group /etc/group_bkp"
        multihost.client[0].run_command(group_bkp, raiseonerr=False)
        group_tmp = "echo g10001:x:10001: >> /etc/group.tmp"
        multihost.client[0].run_command(group_tmp, raiseonerr=False)
        group_move = "mv -f /etc/group.tmp /etc/group"
        multihost.client[0].run_command(group_move, raiseonerr=False)
        group_add = "echo g10002:x:10002: >> /etc/group"
        multihost.client[0].run_command(group_add, raiseonerr=False)
        cmd_getent = "getent group g10002"
        cmd = multihost.client[0].run_command(cmd_getent, raiseonerr=False)
        if "g10002:x:10002" in cmd.stdout_text:
            status = "PASS"
        else:
            status = "FALSE"
        group_restore = "cp -vf /etc/group_bkp /etc/group"
        multihost.client[0].run_command(group_restore, raiseonerr=False)
        assert status == "PASS"




