""" Automation of offline suite

:requirement: offline
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.offline
class TestOffline(object):
    """
    This is test case class for ldap offline suite
    """
    @pytest.mark.tier1
    def test_0001_bz1416150(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: ldap_provider: offline: Log to syslog when sssd
         cannot contact servers goes offline
        :id: fd062319-fa78-4a9e-98ad-be6636b36c5e
        """
        hostname = multihost.master[0].sys_hostname
        bad_ldap_uri = "ldaps://typo.%s" % (hostname)

        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        domain_params = {'ldap_uri': bad_ldap_uri,
                         'ldap_sudo_random_offset': '0'}
        tools.sssd_conf('domain/%s' % (ds_instance_name), domain_params)
        start = multihost.client[0].service_sssd('start')
        # Check backend status
        status = "sssctl domain-status %s -o" % ds_instance_name
        chk_status = multihost.client[0].run_command(status, raiseonerr=False)
        assert 'Offline' in chk_status.stdout_text.strip()
        if start == 0:
            date = "date" + " --rfc-3339=ns"
            get_date = multihost.client[0].run_command(date, raiseonerr=False)
            date_org = get_date.stdout_text
            date = '"' + date_org[0:19] + '"'
            multihost.client[0].service_sssd('restart')
            # Check server status in syslog
            syslog = 'journalctl --since %s -xeu sssd' % date
            time.sleep(80)
            chk_req = multihost.client[0].run_command(syslog, raiseonerr=False)
            result = chk_req.stdout_text.strip()
            assert 'Backend is offline' in result
        else:
            pytest.fail("Failed to start sssd")

    @pytest.mark.tier1_2
    def test_0002_bz1928648(self, multihost, backupsssdconf):
        """
        :title: clarify which config option applies to each timeout in the logs
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1928648
        :customerscenario: true
        :id: b6c3a1e4-f0ee-11eb-9718-845cf3eff344
        :steps:
          1. Login into server running sssd service.
          2. Configure SSSD with only 1  id_provider.
          3. Block "id_provider" using "iptables" command.
          4. Step 6 should fail and similar messages
             should be observed in log file
             (/var/log/sssd/sssd_<domainname>.log).
          5. The log snip should contain following
             timeout parameters.
             - ldap_opt_timeout
             - ldap_search_timeout
             - ldap_network_timeout
             - dns_resolver_timeout
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        multihost.client[0].run_command("> /var/log/sssd/sssd_example1.log")
        multihost.client[0].service_sssd('restart')
        time.sleep(30)
        it_cat = "cat /var/log/sssd/sssd_example1.log"
        cat_read = multihost.client[0].run_command(it_cat)
        for i in ['Setting 6 seconds timeout', "ldap_network_timeout"]:
            assert i in cat_read.stdout_text
        find_id = multihost.client[0].run_command("id foo1@example1")
        assert find_id.returncode == 0
        hostname = multihost.master[0].external_hostname
        block_ip = multihost.client[0].run_command(f'iptables'
                                                   f' -I OUTPUT '
                                                   f'-d {hostname}'
                                                   f' -j DROP')
        assert block_ip.returncode == 0
        user = 'foo1@example1'
        time.sleep(5)
        with pytest.raises(Exception):
            check_login_client(multihost, user, 'Secret123')
        multihost.client[0].run_command(f"iptables "
                                        f"-D OUTPUT -d "
                                        f"{hostname} -j DROP")
        it_cat = "cat /var/log/sssd/sssd_example1.log"
        cat_read = multihost.client[0].run_command(it_cat)
        for i in ['ldap_opt_timeout',
                  'ldap_search_timeout',
                  'ldap_network_timeout',
                  'dns_resolver_timeout']:
            assert i in cat_read.stdout_text
