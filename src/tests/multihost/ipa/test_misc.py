""" Miscellaneous IPA Bug Automations

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

import pytest
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException
import re


@pytest.mark.usefixtures('default_ipa_users')
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

    def test_filter_groups(self, multihost, default_ipa_groups,
                           add_group_member, backupsssdconf):
        """
        :title:  filter_groups option partially filters the group from id
        output of the user because gidNumber still appears in id output
        :id: 8babb6ee-7141-4723-a79d-c5cf7879a9b4
        :description:
         filter_groups option partially filters the group from 'id' output
         of the user because gidNumber still appears in 'id' output
        :steps:
          1. Create IPA users, groups and add users in groups.
          2. Add filter_groups in sssd.conf.
          3. Check filter_groups option filters the group from 'id' output.
        :expectedresults:
          1. Successfully add users, groups and users added in groups.
          2. Successfully added filter_groups in sssd.conf.
          3. Successfully filter out the groups.
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1876658
        """
        gid_start = default_ipa_groups
        sssd_client = sssdTools(multihost.client[0])
        domain_name = '%s/%s' % ('domain',
                                 sssd_client.get_domain_section_name())
        enable_filtergroups1 = {'filter_groups': 'ipa-group1, ipa-group2'}
        sssd_client.sssd_conf(domain_name, enable_filtergroups1)
        sssd_client.clear_sssd_cache()
        lk_cmd1 = 'id foobar1'
        cmd1 = multihost.client[0].run_command(lk_cmd1, raiseonerr=False)
        assert cmd1.returncode == 0
        assert all(x not in cmd1.stdout_text for x in ["ipa-group1",
                                                       "ipa-group2"]), \
            "The unexpected group name found in the id output!"
        assert all(x not in cmd1.stdout_text for x in [str(gid_start+1),
                                                       str(gid_start+2)]), \
            "The unexpected gid found in the id output!"
        enable_filtergroups2 = {'filter_groups': 'ipa-group3, ipa-group4, '
                                                 'ipa-group5'}
        sssd_client.sssd_conf(domain_name, enable_filtergroups2)
        sssd_client.clear_sssd_cache()
        lk_cmd2 = 'id foobar2'
        cmd2 = multihost.client[0].run_command(lk_cmd2, raiseonerr=False)
        assert cmd2.returncode == 0
        assert all(x not in cmd2.stdout_text for x in ["ipa-group3",
                                                       "ipa-group4",
                                                       "ipa-group5"]), \
            "The unexpected group name found in the id output!"
        assert all(x not in cmd2.stdout_text for x in [str(gid_start+3),
                                                       str(gid_start+4),
                                                       str(gid_start+5)]), \
            "The unexpected gid found in the id output!"
