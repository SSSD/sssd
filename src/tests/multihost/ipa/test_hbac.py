""" IPA hbac test cases

:requirement: HBAC (ipa_provider)
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
import time
import re
from sssd.testlib.ipa.utils import ipaTools
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh


@pytest.mark.usefixtures('default_ipa_users',
                         'disable_allow_all_hbac',
                         'reset_password')
@pytest.mark.tier2
@pytest.mark.hbac
class Testipahbac(object):

    def test_sssctl_sshd(self, multihost, hbac_sshd_rule):
        """
        :title: hbac: Verify using sssctl sshd service is allowed
        :id: 33a4288a-6c05-4472-a956-378736e030c8
        """
        sssctl_cmd = 'sssctl user-checks -s sshd foobar1'
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        cmd = multihost.client[0].run_command(sssctl_cmd)
        result = test_pam.search(cmd.stderr_text)
        if not result:
            STATUS = 'FAIL'
        else:
            STATUS = 'PASS'
        assert STATUS == 'PASS'

    def test_hbac_changes(self, multihost, hbac_sshd_rule):
        """
        :title: hbac: verify hbac rule changes are applied
        :id: fcd4fc73-2425-46f8-8d66-95a49b5fb361
        """
        update_rule = "ipa hbacrule-remove-user --users='foobar1' test1"
        multihost.master[0].run_command(update_rule)
        sssctl_cmd = 'sssctl user-checks -s sshd foobar1'
        cmd = multihost.client[0].run_command(sssctl_cmd)
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Permission denied')
        result = test_pam.search(cmd.stderr_text)
        if not result:
            STATUS = 'FAIL'
        else:
            STATUS = 'PASS'
        assert STATUS == 'PASS'

    def test_hbac_refresh_time(self, multihost):
        """
        :title: hbac: Verify cached hbac rule is applied
         for the refresh time period
        :id: c839fd33-65da-4252-82cf-5ba88ad02f55
        """
        ipa_server = ipaTools(multihost.master[0])
        ipa_client = ipaTools(multihost.client[0])
        sssd_client = sssdTools(multihost.client[0])
        domain_name = '%s/%s' % ('domain',
                                 sssd_client.get_domain_section_name())
        client_host = multihost.client[0].sys_hostname
        pexpect_ssh(client_host, 'foobar1', 'Secret123', debug=False)
        ipa_server.add_hbac_rule('test1', 'foobar1', client_host, 'sshd')
        multihost.client[0].service_sssd('stop')
        sssd_client.remove_sss_cache('/var/lib/sss/db')
        hbac_params = {'ipa_hbac_refresh': '60'}
        sssd_client.sssd_conf(domain_name, hbac_params)
        multihost.client[0].service_sssd('start')
        login_status = ipa_client.ssh_login('foobar1', 'Secret123',
                                            client_host, command='id')
        if login_status:
            status = 'PASS'
        # update the rule
        update_rule = "ipa hbacrule-remove-user --users='foobar1' test1"
        # sleep for 20 seconds
        time.sleep(20)
        multihost.master[0].run_command(update_rule)
        login_status = ipa_client.ssh_login('foobar1', 'Secret123',
                                            client_host, command='id')
        if login_status:
            status = 'PASS'
        time.sleep(45)
        # now it should not allow login
        login_status = ipa_client.ssh_login('foobar1', 'Secret123',
                                            client_host)
        if not login_status:
            status = 'PASS'
        sssd_client.sssd_conf(domain_name, hbac_params, action='delete')
        multihost.client[0].service_sssd('restart')
        ipa_server.del_hbac_rule('test1')
        assert status == 'PASS'

    def test_multiple_hbac_rules(self, multihost):
        """
        :title: hbac: Verify HBAC Evaluation happens per service
         when user is associated  with multiple hbac rules
        :id: 6981b637-f4ea-449b-8916-60cc938c4d0f
        """
        ipa_server = ipaTools(multihost.master[0])
        client_host = multihost.client[0].sys_hostname
        ipa_server.add_hbac_rule('test1', 'foobar1', client_host, 'sshd')
        ipa_server.add_hbac_rule('test2', 'foobar1', client_host, 'sudo')
        sssctl_cmd = 'sssctl user-checks -s sshd foobar1'
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        cmd = multihost.client[0].run_command(sssctl_cmd)
        result = test_pam.search(cmd.stderr_text)
        if not result:
            STATUS = 'FAIL'
        else:
            STATUS = 'PASS'
        ipa_server.del_hbac_rule('test1')
        ipa_server.del_hbac_rule('test2')
        assert STATUS == 'PASS'

    def test_nested_groups(self, multihost):
        """
        :title: hbac: Verify hbac evaluation works as expected
         with nested group evaluation
        :id: fb2fd287-b217-487c-a59a-d827c426b0bb
        """
        ipa_server = ipaTools(multihost.master[0])
        client_host = multihost.client[0].sys_hostname
        groups = ['std_group', 'admin_group']
        for grp in groups:
            cmd = 'ipa group-add %s' % grp
            multihost.master[0].run_command(cmd)
        # Add members
        cmd1 = 'ipa group-add-member --users=foobar1 std_group'
        cmd2 = 'ipa group-add-member --users=foobar2 admin_group'
        multihost.master[0].run_command(cmd1, raiseonerr=False)
        multihost.master[0].run_command(cmd2, raiseonerr=False)
        # make admin_group member of std_group
        nested_group = 'ipa group-add-member --groups=admin_group std_group'
        multihost.master[0].run_command(nested_group, raiseonerr=False)
        # add rule
        ipa_server.add_hbac_rule('allow_ssh_access', 'std_group', client_host,
                                 'sshd', group=True)
        ipa_server.add_hbac_rule('allow_sudo_access', 'admin_group',
                                 client_host, 'sudo', group=True)
        users = ['foobar1', 'foobar2']
        for user in users:
            sssctl_cmd = 'sssctl user-checks -s sshd %s' % user
            cmd1 = multihost.client[0].run_command(sssctl_cmd)
            test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
            result = test_pam.search(cmd1.stderr_text)
            if not result:
                STATUS = 'FAIL'
            else:
                STATUS = 'PASS'
        ipa_server.del_hbac_rule('allow_ssh_access')
        ipa_server.del_hbac_rule('allow_sudo_access')
        for grp in groups:
            cmd = 'ipa group-del %s' % grp
            multihost.master[0].run_command(cmd)
        assert STATUS == 'PASS'

    def test_auto_private_group(self, multihost):
        """
        :title: hbac: Verify hbac rule associated with
         User private Groups
        :id: 99904ccd-bf2f-4c09-9636-92e036e19a0e
        """
        ipa_server = ipaTools(multihost.master[0])
        sssd_client = sssdTools(multihost.client[0])
        domain_name = '%s/%s' % ('domain',
                                 sssd_client.get_domain_section_name())
        client_host = multihost.client[0].sys_hostname
        pexpect_ssh(client_host, 'foobar1', 'Secret123', debug=False)
        multihost.client[0].service_sssd('stop')
        sssd_client.remove_sss_cache('/var/lib/sss/db')
        enable_pvtgroups = {'auto_private_groups': 'True'}
        sssd_client.sssd_conf(domain_name, enable_pvtgroups)
        multihost.client[0].service_sssd('start')
        cmd = 'ipa group-add std_group'
        multihost.master[0].run_command(cmd)
        # Add members
        cmd1 = 'ipa group-add-member --users=foobar1 std_group'
        multihost.master[0].run_command(cmd1, raiseonerr=False)
        # add rule
        ipa_server.add_hbac_rule('allow_ssh_access', 'std_group',
                                 client_host, 'sshd', group=True)
        sssctl_cmd = 'sssctl user-checks -s sshd foobar1'
        cmd1 = multihost.client[0].run_command(sssctl_cmd)
        test_pam = re.compile(r'%s' % 'pam_acct_mgmt: Success')
        result = test_pam.search(cmd1.stderr_text)
        if not result:
            STATUS = 'FAIL'
        else:
            STATUS = 'PASS'
        ipa_server.del_hbac_rule('allow_ssh_access')
        cmd = 'ipa group-del std_group'
        multihost.master[0].run_command(cmd)
        sssd_client.sssd_conf(domain_name, enable_pvtgroups, action='delete')
        multihost.client[0].service_sssd('restart')
        assert STATUS == 'PASS'
