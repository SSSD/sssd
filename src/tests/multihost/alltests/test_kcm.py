"""Automation of kcm related bugs

:requirement: IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import pytest
import time
from sssd.testlib.common.ssh2_python import check_login_client
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.kcm
class TestKcm(object):
    """
    This is for kcm bugs automation
    """
    @pytest.mark.tier1_2
    def test_client_timeout(self, multihost, backupsssdconf):
        """
        :title: kcm: Increase client idle
         timeout to 5 minutes
        :id: 6933cb85-1616-4b7f-a049-e81ab4c05347
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1884205
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'debug_level': '9'}
        client.sssd_conf('kcm', domain_params)
        multihost.client[0].service_sssd('restart')
        user = 'foo1@example1'
        check_login_client(multihost, user, 'Secret123')
        sssdTools(multihost.client[0]).clear_sssd_cache()
        multihost.client[0].run_command("systemctl restart sssd-kcm")
        multihost.client[0].run_command("> /var/log/sssd/sssd_kcm.log")
        start_time = time.time()
        multihost.client[0].run_command("kinit foo1 <&- & ")
        end_time = time.time()
        assert end_time - start_time >= 300
        grep_cmd = multihost.client[0].run_command("grep"
                                                   " 'Terminated"
                                                   " client'"
                                                   " /var/log/sssd/"
                                                   "sssd_kcm.log")
        assert 'Terminated client' in grep_cmd.stdout_text

    @pytest.mark.tier1_2
    def test_refresh_contain_timestamp(self,
                                       multihost,
                                       backupsssdconf):
        """
        :title: kcm: First smart refresh query contains
         modifyTimestamp even if the modifyTimestamp is 0
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1926454
        :customerscenario: true
        :id: 09f654c4-759d-11eb-bfff-002b677efe14
        :steps:
          1. Configure SSSD with sudo
          2. Leave ou=sudoers empty - do not define any rules
          3. See that smart refresh does not contain
             modifyTimestamp in the filter
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        ldap_params = {'domains': 'example1'}
        tools.sssd_conf('sssd', ldap_params)
        ldap_params = {'sudo_provider': 'ldap',
                       'ldap_sudo_smart_refresh_interval': '60'}
        tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
        multihost.client[0].service_sssd('restart')
        multihost.client[0].run_command("> /var/log/sssd/sssd_example1.log")
        time.sleep(65)
        log_location = "/var/log/sssd/sssd_example1.log"
        grep_cmd = multihost.client[0].run_command(f"grep "
                                                   f"'calling "
                                                   f"ldap_search_ext with' "
                                                   f"{log_location}")
        assert 'modifyTimestamp>=' not in grep_cmd.stdout_text

    @pytest.mark.tier1_2
    def test_kcm_check_socket_path(self, multihost, backupsssdconf):
        """
        :title: kcm: Test socket path when sssd-kcm is activated by systemd
        :id: 6425bf2c-d07e-4d65-b15d-946141422f96
        :ticket: https://github.com/SSSD/sssd/issues/5406
        """
        # Start from a known-good state after removing log file and adding a
        # new socket path
        client = sssdTools(multihost.client[0])
        domain_log = '/var/log/sssd/sssd_kcm.log'
        multihost.client[0].service_sssd('stop')
        client.service_ctrl('stop', 'sssd-kcm')
        client.remove_sss_cache(domain_log)
        domain_params = {'debug_level': '9',
                         'socket_path': '/some_path/kcm.socket'}
        client.sssd_conf('kcm', domain_params)
        multihost.client[0].service_sssd('start')
        # After starting sssd-kcm, latest sssd_kcm.log will generate
        client.service_ctrl('start', 'sssd-kcm')
        # Give sssd some time to load
        time.sleep(2)
        # Check log file for the expected warning message
        log = multihost.client[0].get_file_contents(domain_log).decode('utf-8')
        msg = "Warning: socket path defined in systemd unit .*." \
              "and.sssd.conf...some_path.kcm.socket..don't.match"
        find = re.compile(r'%s' % msg)
        assert find.search(log)

    @pytest.mark.tier1_2
    def test_expired_tickets(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: kcm_provider: Expired tickets are removed
        :id: db532785-a00f-4be9-b413-592e0550fe9c
        :requirement: sssd-kcm does not appear to expire Kerberos tickets (RFE: sssd_kcm
          should have the option to automatically delete the expired tickets)
        :setup:
         1. Configure short ticket lifetime in krb5.
         2. Create a user.
         3. Cleanup all ticket caches
        :steps:
          1. Create about 64 tickets for user
          2. Try to create 65th ticket
          3. Wait for them to expire
          4. Try to create about 10 more tickets
          5. Check the sssd kcm log
        :expectedresults:
          1. Tickets are created
          2. Ticket is not created
          3. Tickets are expired
          4. New tickets are created
          5. Log contains a message about deleting expired credentials
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1900973
        """
        client = sssdTools(multihost.client[0])
        client.sssd_conf('kcm', {'debug_level': '9'})
        multihost.client[0].service_sssd('restart')

        sssdTools(multihost.client[0]).clear_sssd_cache()
        # Setup short ticker validity (60s)  in krb5.conf using ticket_lifetime
        backup_krb5 = 'cp -rf /etc/krb5.conf /etc/krb5.conf.bak'
        restore_krb5 = 'mv /etc/krb5.conf.bak /etc/krb5.conf ; ' \
                       'restorecon -Rv /etc/krb5.conf'
        edit_krb5_conf = 'sed -i "s/ticket_lifetime.*/ticket_lifetime = ' \
            '60/" /etc/krb5.conf'
        multihost.client[0].run_command(backup_krb5, raiseonerr=False)
        multihost.client[0].run_command(edit_krb5_conf, raiseonerr=False)
        multihost.client[0].run_command("systemctl restart sssd-kcm")
        multihost.client[0].run_command("> /var/log/sssd/sssd_kcm.log")
        multihost.client[0].run_command("kdestroy -A", raiseonerr=False)
        for i in range(1, 65):
            multihost.client[0].run_command(
                f"kinit -c KCM:0:12345{i} foo1",
                stdin_text="Secret123",
                raiseonerr=False
            )
        # This credential should not be created due to secrets being full now.
        cmd_fail = multihost.client[0].run_command(
            "kinit -c KCM:0:666666 foo1",
            stdin_text="Secret123",
            raiseonerr=False
        )
        log_str_1 = multihost.client[0].get_file_contents(
            "/var/log/sssd/sssd_kcm.log").decode('utf-8')
        # Wait for secrets to expire.
        time.sleep(120)
        multihost.client[0].run_command("date; klist -l", raiseonerr=False)
        fail_count = 0
        for i in range(65, 75):
            cmd = multihost.client[0].run_command(
                f"kinit -c KCM:0:12345{i} foo1",
                stdin_text="Secret123",
                raiseonerr=False
            )
            fail_count += cmd.returncode
        log_str = multihost.client[0].get_file_contents(
            "/var/log/sssd/sssd_kcm.log").decode('utf-8')
        multihost.client[0].run_command(restore_krb5, raiseonerr=False)
        multihost.client[0].run_command("kdestroy -A", raiseonerr=False)
        assert fail_count == 0, f"At least one kinit failed. Failures: {fail_count}."
        assert cmd_fail.returncode != 0, "kinit succeeded but should have failed."
        assert "The maximum number of stored secrets has been reached" in log_str_1
        assert "Removing the oldest expired credential" in log_str

    @pytest.mark.tier1_2
    @staticmethod
    def test_kcm_logrotate(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: sssd_kcm.log is rotated with other sssd logs
        :id: 9ac9a11c-c176-431b-b690-03181f014c25
        :setup:
         1. Create a user.
        :steps:
          1. Create a ticket for a user and collect kcm log file
          2. Initiate logrotate for sssd and  collect the sssd kcm log
          3. Swich off sssd-kcm service and initiate logrotate
          4. Swich off sssd service and initiate logrotate
        :expectedresults:
          1. Ticket is created
          2. Log file size is lower that in step 1.
          3. Logrotate does not fail.
          4. Logrotate does not fail.
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2176768
        """
        client = sssdTools(multihost.client[0])
        client.sssd_conf('kcm', {'debug_level': '9'})
        sssdTools(multihost.client[0]).clear_sssd_cache()
        client.service_ctrl('restart', 'sssd-kcm')
        kinit = multihost.client[0].run_command(
            "kinit -c KCM:0:666666 foo1",
            stdin_text="Secret123",
            raiseonerr=False
        )
        log_str_len_start = len(multihost.client[0].get_file_contents(
            "/var/log/sssd/sssd_kcm.log").decode('utf-8'))
        multihost.client[0].run_command("logrotate -f /etc/logrotate.d/sssd")
        time.sleep(20)
        log_str_len_end = len(multihost.client[0].get_file_contents(
            "/var/log/sssd/sssd_kcm.log").decode('utf-8'))
        client.service_ctrl('stop', 'sssd-kcm')
        logrotate_kcm = multihost.client[0].run_command("logrotate -f /etc/logrotate.d/sssd")
        multihost.client[0].service_sssd('stop')
        logrotate_sssd = multihost.client[0].run_command("logrotate -f /etc/logrotate.d/sssd")
        assert kinit.returncode == 0, "kinit failed."
        assert log_str_len_start > log_str_len_end, "Log was not rotated!"
        assert logrotate_kcm.returncode == 0, "Logrotation error when sssd-kcm is stopped!"
        assert logrotate_sssd.returncode == 0, "Logrotation error when sssd is stopped!"
