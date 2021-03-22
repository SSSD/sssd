""" Automation of offline suite

:requirement: offline
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
from __future__ import print_function
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.offline
class TestOffline(object):
    """
    This is test case class for ldap offline suite
    """
    @pytest.mark.tier1
    def test_0001_bz1416150(self, multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: offline: Log to syslog when sssd
         cannot contact servers goes offline
         offline.
        :id: fd062319-fa78-4a9e-98ad-be6636b36c5e
        """
        hostname = multihost.master[0].sys_hostname
        bad_ldap_uri = "ldaps://typo.%s" % (hostname)

        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        domain_params = {'ldap_uri': bad_ldap_uri}
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
            # Check server status in syslog
            syslog = 'journalctl --since %s -xeu sssd' % date
            time.sleep(80)
            chk_req = multihost.client[0].run_command(syslog, raiseonerr=False)
            result = chk_req.stdout_text.strip()
            assert 'Backend is offline' in result
        else:
            pytest.fail("Failed to start sssd")
