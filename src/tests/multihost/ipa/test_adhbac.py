""" IPA AD Trust HBAC Cases

:requirement: HBAC (ipa_provider)
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
import re
from sssd.testlib.ipa.utils import ipaTools
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException


@pytest.mark.usefixtures('disable_allow_all_hbac',
                         'create_ad_users',
                         'create_ad_groups')
@pytest.mark.tier2
@pytest.mark.adhbac
class TestADTrustHbac(object):
    """ AD Trust HBAC Test cases """
    def test_allowed_ad_group(self, multihost):
        """
        :title: Verify Member of allowed AD Group
         through hbac is able to login
        :id: 401fb710-b876-4693-92d0-86a75b94973f
        """
        ipa_server_tools = ipaTools(multihost.master[0])
        ipa_client = sssdTools(multihost.client[0])
        ipa_server = sssdTools(multihost.master[0])
        client_host = multihost.client[0].sys_hostname
        ad_domain_name = multihost.ad[0].domainname.lower()
        aduser = 'idm_user1@%s' % ad_domain_name
        adgroup = 'idm_group1@%s' % ad_domain_name
        status = ''
        try:
            ipa_server_tools.create_group('idm_ext_group1', external=True)
        except SSSDException:
            status = 'FAIL'
        try:
            ipa_server_tools.group_add_member(adgroup, 'idm_ext_group1',
                                              external=True)
        except SSSDException:
            status = 'FAIL'

        try:
            ipa_server_tools.create_group('idm_posix_group1')
        except SSSDException:
            status = 'FAIL'
        try:
            ipa_server_tools.group_add_member('idm_ext_group1',
                                              'idm_posix_group1')
        except SSSDException:
            status = 'FAIL'
        ipa_server_tools.add_hbac_rule('ad_test1', 'idm_posix_group1',
                                       client_host, 'sshd', group=True)
        sssctl_cmd = 'sssctl user-checks -s sshd %s' % aduser
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        result = test_pam.search(cmd.stderr_text)
        if not result:
            status = 'FAIL'
        else:
            status = 'PASS'
        for i in ['idm_ext_group1', 'idm_posix_group1']:
            cmd = 'ipa group-del %s' % i
            multihost.master[0].run_command(cmd, raiseonerr=False)
        ipa_server_tools.del_hbac_rule('ad_test1')
        ipa_client.clear_sssd_cache()
        ipa_server.clear_sssd_cache()
        assert status == 'PASS'

    def test_disallowed_ad_group(self, multihost, create_aduser_group):
        """
        :title: Verify Member of denied AD Group through
         hbac is not able to login
        :id: 7092f403-ca58-4683-89b8-400c64dd0a1d
        """
        (aduser, adgroup) = create_aduser_group
        ipa_server_tools = ipaTools(multihost.master[0])
        ipa_client = sssdTools(multihost.client[0])
        ipa_server = sssdTools(multihost.master[0])
        client_host = multihost.client[0].sys_hostname
        ad_domain_name = multihost.ad[0].domainname.lower()
        allow_adgroup = 'idm_group1@%s' % ad_domain_name
        status = ''
        try:
            ipa_server_tools.create_group('idm_ext_group2', external=True)
        except SSSDException:
            status = 'FAIL'
        try:
            ipa_server_tools.group_add_member(allow_adgroup, 'idm_ext_group2',
                                              external=True)
        except SSSDException:
            status = 'FAIL'

        try:
            ipa_server_tools.create_group('idm_posix_group2')
        except SSSDException:
            status = 'FAIL'
        try:
            ipa_server_tools.group_add_member('idm_ext_group2',
                                              'idm_posix_group2')
        except SSSDException:
            status = 'FAIL'
        ipa_server_tools.add_hbac_rule('ad_test2', 'idm_posix_group2',
                                       client_host, 'sshd', group=True)
        diallowed_user = '%s@%s' % (aduser, ad_domain_name)
        sssctl_cmd = 'sssctl user-checks -s sshd %s' % diallowed_user
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Permission denie')
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        result = test_pam.search(cmd.stderr_text)
        if not result:
            status = 'FAIL'
        else:
            status = 'PASS'
        for i in ['idm_ext_group2', 'idm_posix_group2']:
            cmd = 'ipa group-del %s' % i
            multihost.master[0].run_command(cmd, raiseonerr=False)
        ipa_server_tools.del_hbac_rule('ad_test2')
        ipa_client.clear_sssd_cache()
        ipa_server.clear_sssd_cache()
        assert status == 'PASS'

    def test_multiple_ad_groups(self, multihost):
        """
        :title: Verify hbac evaluation when user is member
         of multiple AD Groups and with different hbac rules
        :id: eb78448d-8a4d-4800-9334-8d8cdb8b0af2
        """
        ipa_server_tools = ipaTools(multihost.master[0])
        ipa_client = sssdTools(multihost.client[0])
        ipa_server = sssdTools(multihost.master[0])
        client_host = multihost.client[0].sys_hostname
        ad_domain_name = multihost.ad[0].domainname.lower()
        aduser = 'idm_user3@%s' % ad_domain_name
        adgroup = 'idm_group3@%s' % ad_domain_name
        status = ''
        for i in range(3, 5, 1):
            ext_group = 'idm_ext_group%d' % i
            adgroup = 'idm_group%d@%s' % (i, ad_domain_name)
            posix_group = 'idm_posix_group%d' % i
            try:
                ipa_server_tools.create_group(ext_group, external=True)
            except SSSDException:
                status = 'FAIL'
            try:
                ipa_server_tools.group_add_member(adgroup, ext_group,
                                                  external=True)
            except SSSDException:
                status = 'FAIL'
            try:
                ipa_server_tools.create_group(posix_group)
            except SSSDException:
                status = 'FAIL'
            try:
                ipa_server_tools.group_add_member(ext_group, posix_group)
            except SSSDException:
                status = 'FAIL'

        ipa_server_tools.add_hbac_rule('ad_test3', 'idm_posix_group3',
                                       client_host, 'sshd', group=True)
        ipa_server_tools.add_hbac_rule('ad_test4', 'idm_posix_group4',
                                       client_host, 'sudo', group=True)
        sssctl_cmd = 'sssctl user-checks -s sshd %s' % aduser
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        result = test_pam.search(cmd.stderr_text)
        if not result:
            status = 'FAIL'
        else:
            status = 'PASS'
        for i in ['idm_ext_group3', 'idm_ext_group4',
                  'idm_posix_group3', 'idm_posix_group4']:
            cmd = 'ipa group-del %s' % i
            multihost.master[0].run_command(cmd, raiseonerr=False)
        ipa_server_tools.del_hbac_rule('ad_test3')
        ipa_server_tools.del_hbac_rule('ad_test4')
        ipa_client.clear_sssd_cache()
        ipa_server.clear_sssd_cache()
        assert status == 'PASS'

    def test_hbac_nested_group(self, multihost):
        """
        :title: Verify hbac evaluation of AD Nested Groups
        :id: f7fc6349-daba-43c2-be4e-e13923e201f9
        """
        ipa_server_tools = ipaTools(multihost.master[0])
        ipa_client = sssdTools(multihost.client[0])
        ipa_server = sssdTools(multihost.master[0])
        client_host = multihost.client[0].sys_hostname
        ad_domain_name = multihost.ad[0].domainname.lower()
        aduser = 'idm_user1@%s' % ad_domain_name
        adgroup = 'nested_group1@%s' % ad_domain_name
        status = ''
        try:
            ipa_server_tools.create_group('idm_ext_group5', external=True)
        except SSSDException:
            status = 'FAIL'
        try:
            ipa_server_tools.group_add_member(adgroup, 'idm_ext_group5',
                                              external=True)
        except SSSDException:
            status = 'FAIL'

        try:
            ipa_server_tools.create_group('idm_posix_group5')
        except SSSDException:
            status = 'FAIL'
        try:
            ipa_server_tools.group_add_member('idm_ext_group5',
                                              'idm_posix_group5')
        except SSSDException:
            status = 'FAIL'
        ipa_server_tools.add_hbac_rule('ad_test5', 'idm_posix_group5',
                                       client_host, 'sshd', group=True)
        sssctl_cmd = 'sssctl user-checks -s sshd %s' % aduser
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        result = test_pam.search(cmd.stderr_text)
        if not result:
            status = 'FAIL'
        else:
            status = 'PASS'
        for i in ['idm_ext_group5', 'idm_posix_group5']:
            cmd = 'ipa group-del %s' % i
            multihost.master[0].run_command(cmd, raiseonerr=False)
        ipa_server_tools.del_hbac_rule('ad_test5')
        ipa_client.clear_sssd_cache()
        ipa_server.clear_sssd_cache()
        assert status == 'PASS'
