""" Automation of sanity/services suite

:requirement: IDM-SSSD-REQ : Configuration and Service Management
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import subprocess
import re
import pytest
import random
import string
from sssd.testlib.common.utils import sssdTools


def exceute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.usefixtures('default_sssd')
@pytest.mark.services
class TestServices(object):
    """ SSSD sanity services """
    @pytest.mark.tier1
    def test_0001_bz1432010(self, multihost):
        """
        :title: IDM-SSSD-TC: sanity: services: SSSD ships a drop-in
         configuration snippet in /etc/systemd/system
        :id: 755973b3-200c-456d-8057-f4a6b093e3f4
        """
        rpm_grep = 'rpm -ql sssd-common'
        cmd = multihost.client[0].run_command(rpm_grep, raiseonerr=False)
        assert cmd.stdout_text.find('/etc/systemd/system') == -1

    @pytest.mark.tier1
    def test_0002_1736796(self, multihost, localusers):
        """
        :title: config: "default_domain_suffix" should not
         cause files domain entries to be qualified, this can break sudo access
        :id: 4b7bdeff-51ba-46ed-b8e1-0685515b87a0
        """
        users = localusers
        for user in users.keys():
            allow_sudo = '%s    ALL=(ALL) NOPASSWD:ALL' % user
            sudoers_file = '/etc/sudoers.d/%s' % user
            multihost.client[0].put_file_contents(sudoers_file, allow_sudo)
        tools = sssdTools(multihost.client[0])
        sssd_params = {'default_domain_suffix': 'foo',
                       'domains': 'LOCAL'}
        tools.sssd_conf('sssd', sssd_params)
        domain_section = 'domain/LOCAL'
        domain_params = {'id_provider': 'files'}
        tools.sssd_conf(domain_section, domain_params)
        multihost.client[0].service_sssd('restart')
        failures = []
        for user in users.keys():
            cmd = multihost.client[0].run_command(
                f'su - {user} -c "id"', raiseonerr=False)
            if f'{user}@implicit_files' in cmd.stdout_text:
                failures.append(
                    f"id command contains implicit_files for {user}")
            cmd2 = multihost.client[0].run_command(
                f'su - {user} -c "sudo su - -c id"', raiseonerr=False)
            if cmd2.returncode != 0:
                journalctl_cmd = 'journalctl -x -n 100 --no-pager'
                multihost.client[0].run_command(journalctl_cmd)
                failures.append(f"'sudo su - -c id' cmd failed for {user}")
        for user in users.keys():
            sudoers_file = '/etc/sudoers.d/%s' % user
            delete_file = 'rm -f %s' % sudoers_file
            multihost.client[0].run_command(delete_file)
        assert not failures, "\n".join(failures)

    @pytest.mark.tier1
    def test_0003_bz1713368(self, multihost):
        """
        :title: services: Add sssd-dbus package as a dependency of sssd-tools
        :id: dfbdcb9f-09ed-4467-97a6-0407c779dd08
        :customerscenario: True
        """
        # sssd-dbus is a weak dependency of sssd-tools package so we did not
        # get sssd-dbus in '# yum deplist sssd-tools' command
        version = float(re.findall(r"\d+\.\d+", multihost.client[0].distro)[0])
        if version >= 9:
            cmd = multihost.client[0].run_command('yum repoquery'
                                                  ' --requires sssd-tools',
                                                  raiseonerr=False)
        else:
            cmd = multihost.client[0].run_command('yum repoquery --recommends'
                                                  ' sssd-tools',
                                                  raiseonerr=False)
        if cmd.returncode == 0:
            find = re.compile(r'sssd-dbus')
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1
    def test_0004_membership_with_files_provider(self, multihost):
        """
        :title: services: SSSD must be able to resolve
         membership involving root with files provider
        :id: ca7adb25-6a2b-4f09-b5ed-dc083226c6c9
        :customerscenario: True
        :bugzilla:
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
        :title: services: When the passwd or group files
         are replaced, sssd stops monitoring the file for
         inotify events, and no updates are triggered
        :id: c6bf72fa-75be-4004-b04b-b5ea3e662c7d
        :customerscenario: True
        :bugzilla:
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

    @pytest.mark.tier1_2
    def test_0006_bz1909755(self, multihost, backupsssdconf):
        """
        :title: Suppress log message "[sssd] [service_signal_done]
         (0x0010): Unable to signal service [2]:
         No such file or directory" during logrote
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1909755
        :customerscenario: true
        :id: a4f5d404-070b-11ec-8055-845cf3eff344
        :steps:
          1. Find main sssd process id
          2. Send SIGHUP
          3. There should not be any logs for
             'Unable to signal service .* No such
             file or directory
             modifyTimestamp' in the filter
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': 'LOCAL'}
        tools.sssd_conf('sssd', sssd_params)
        domain_section = 'domain/LOCAL'
        domain_params = {'id_provider': 'files'}
        tools.sssd_conf(domain_section, domain_params)
        multihost.client[0].service_sssd('restart')
        proces_id = int(exceute_cmd(multihost,
                                    "pidof sssd").stdout_text.split()[0])
        exceute_cmd(multihost, f"kill -1 {proces_id}")
        with pytest.raises(subprocess.CalledProcessError):
            exceute_cmd(multihost, 'grep -ri "Unable '
                                   'to signal service .* No '
                                   'such file or directory" '
                                   '/var/log/sssd')

    @pytest.mark.tier1_2
    def test_0007_bz971435(self, multihost, backupsssdconf):
        """
        :title: Enhance sssd init script so that it would source a configuration
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=971435
        :id: ba764db9-90e0-4e6a-bd3c-b7bd6221f340
        :steps:
          1. Add 'PIZZA=YUMMY' string in /etc/sysconfig/sssd
          2. Restart the sssd
          3. Check pid of sssd and grep the string under /proc directory
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        # port bash to pytest
        tools = sssdTools(multihost.client[0])
        sssd_params = {'debug_level': '9', 'enable_files_domain': 'true'}
        tools.sssd_conf('sssd', sssd_params)
        multihost.client[0].run_command('echo "PIZZA=YUMMY" > /etc/sysconfig/sssd', raiseonerr=False)
        multihost.client[0].service_sssd('restart')
        process_id = (exceute_cmd(multihost, "pidof sssd").stdout_text.split()[0])
        file_for_grep = f"/proc/{process_id}/environ"
        grep_cmd = f'grep "PIZZA=YUMMY" {file_for_grep}'
        cmd_check = multihost.client[0].run_command(grep_cmd, raiseonerr=False)
        multihost.client[0].run_command('rm -f /etc/sysconfig/sssd', raiseonerr=False)
        assert cmd_check.returncode == 0, "string 'PIZZA=YUMMY' not found in /proc file"

    @pytest.mark.tier1_2
    def test_0008_bz1516266(self, multihost, backupsssdconf):
        """
        :title: detailed debug and system-log message if krb5_init_context failed
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1516266
        :id: fe126445-21d2-4572-b32a-b66c8486569f
        :steps:
          1. Update the sssd.conf with id and auth provider
          2. Add 'includedir /var/lib/sss/pubconf/krb5.include.d/' in krb5.conf
          3. Check sssd status, sssd should start
          4. Revert back the krb.conf and add 'includedir /var/lib/sss/pubconf/krb5.include.d/$$$$' in krb5.conf
             here $$$ is spaces after string
          5. Check sssd status, sssd should fail to start
        :expectedresults:
          1. Successfully upadated sssd.conf
          2. Successfully added string in krb5.conf
          3. Successfully start the sssd service
          4. Successfully reverted the krb5.conf and added string with spaces at the end
          5. SSSD failing to start
        """
        # port bash to pytest
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': 'LDAP',
                       'debug_level': '9'}
        tools.sssd_conf('sssd', sssd_params)
        domain_section = 'domain/LDAP'
        domain_params = {'id_provider': 'ldap',
                         'ldap_uri': 'ldap://ldap.example.com',
                         'ldap_search_base': 'dc=example,dc=com',
                         'auth_provider': 'krb5',
                         'krb5_server': 'kerberos.example.com',
                         'krb5_realm': 'EXAMPLE.COM',
                         'debug_level': '9'}
        tools.sssd_conf(domain_section, domain_params)
        # stop sssd, delete logs and cache, start sssd
        tools.clear_sssd_cache()
        random_file1 = 'random' + ''.join(
            random.choice(string.ascii_lowercase) for i in range(5))
        take_bk = 'cp -f /etc/krb5.conf /etc/krb5.conf.backup'
        multihost.client[0].run_command(take_bk, raiseonerr=False)
        cmd_to_add = '{ echo "includedir /var/lib/sss/pubconf/krb5.include.d' \
                     '/"; cat /etc/krb5.conf; } > ' \
                     f'/tmp/{random_file1}'
        multihost.client[0].run_command(cmd_to_add, raiseonerr=False)
        copy_radom = f'mv -f /tmp/{random_file1} /etc/krb5.conf'
        multihost.client[0].run_command(copy_radom, raiseonerr=False)
        start_sssd = multihost.client[0].service_sssd('restart')
        restore_krb = 'cp -f /etc/krb5.conf.backup /etc/krb5.conf'
        multihost.client[0].run_command(restore_krb, raiseonerr=False)
        assert start_sssd == 0, "SSSD service fails to start after " \
                                "adding string in /etc/krb5.conf"
        random_file2 = 'random' + ''.join(
            random.choice(string.ascii_lowercase) for i in range(5))
        # Dont remove the extra space in bellow line. Its needed for this test
        cmd_with_sp = '{ echo "includedir /var/lib/sss/pubconf/krb5.include' \
                      '.d/  "; cat /etc/krb5.conf; } > ' \
                      f'/tmp/{random_file2}'
        multihost.client[0].run_command(cmd_with_sp, raiseonerr=False)
        copy_radom2 = f'mv -f /tmp/{random_file2} /etc/krb5.conf'
        multihost.client[0].run_command(copy_radom2, raiseonerr=False)
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/log/sssd')
        # Here sssd expected to fail, and if we use function from common
        # to start, it will raise an exception, so added command to check
        # log message after sssd fails to start.
        start_sssd_sp = multihost.client[0].run_command(
            'systemctl start sssd', raiseonerr=False)
        log_str = multihost.client[0].get_file_contents(
            '/var/log/sssd/sssd_LDAP.log').decode('utf-8')
        multihost.client[0].run_command(restore_krb, raiseonerr=False)
        multihost.client[0].run_command(
            'rm -f /etc/krb5.conf.backup', raiseonerr=False)
        assert start_sssd_sp.returncode != 0
        assert re.compile(r'Failed to init Kerberos context .Included '
                          r'profile directory could not be read').search(
            log_str)
