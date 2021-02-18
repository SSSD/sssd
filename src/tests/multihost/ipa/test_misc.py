""" Miscellaneous IPA Bug Automations

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_identity_management
:upstream: yes
"""

import pytest
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException
import re


@pytest.mark.tier1
class Testipabz(object):
    """ IPA BZ Automations """
    def test_blank_kinit(self, multihost):
        """
        :title: verify sssd fails to start with
         invalid default keytab file
        :id: 525cbe28-f835-4d2e-9583-d3f614b8486e
        :requirement: IDM-SSSD-REQ : KRB5 Provider
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1748292
        :description: systemctl status sssd says No such file or
         directory about "default" when keytab exists but is empty file
        """
        tools = sssdTools(multihost.client[0])
        # stop sssd
        multihost.client[0].service_sssd('stop')
        # backup /etc/krb5.keytab
        backup = 'mv /etc/krb5.keytab /etc/krb5.keytab.orig'
        multihost.client[0].run_command(backup)
        # create an empty keytab
        empty_keytab = 'echo -n > /etc/krb5.keytab'
        multihost.client[0].run_command(empty_keytab)
        # start sssd
        try:
            multihost.client[0].service_sssd('start')
        except SSSDException:
            STATUS = 'PASS'
            logs = 'journalctl -x -n 50 --no-pager'
            cmd = multihost.client[0].run_command(logs, raiseonerr=False)
            search_txt = 'krb5_kt_start_seq_get failed: '\
                         'Unsupported key table format version number'
            check = re.compile(r'%s' % search_txt)
            if not check.search(cmd.stdout_text):
                STATUS = 'FAIL'
        else:
            STATUS = 'FAIL'
            pytest.fail("sssd should fail to restart")
        # restore /etc/krb5.keytab
        restore = 'mv /etc/krb5.keytab.orig /etc/krb5.keytab'
        multihost.client[0].run_command(restore)
        assert STATUS == 'PASS'

    def test_sssdConfig_remove_Domains(self, multihost):
        """
        :title: Verify SSSDConfig.save_domain API removes
         all autofs entries from sssd.conf
        :id: 3efaf0af-58a7-4631-8555-da8a7bbcf351
        :description:
         SSSDConfig.save_domain(domain) does not always
         remove all entries removed from domain
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1796989
        """
        tools = sssdTools(multihost.client[0])
        setup_automount = "ipa-client-automount --location default -U " \
                          "--server %s" % multihost.master[0].sys_hostname
        uninstall_automount = "ipa-client-automount --uninstall -U " \
                              "--server %s" % multihost.master[0].sys_hostname
        for i in range(5):
            cmd1 = multihost.client[0].run_command(setup_automount,
                                                   raiseonerr=False)
            time.sleep(5)
            cmd2 = multihost.client[0].run_command(uninstall_automount,
                                                   raiseonerr=False)
            assert cmd1.returncode == 0
            assert cmd2.returncode == 0
