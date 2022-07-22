""" AD access control test ported from bash
:requirement: ad_access_control
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import pytest
import time
import re
import random
import pexpect
import tempfile
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import ADOperations
from sssd.testlib.common.exceptions import SSHLoginException


@pytest.mark.usefixtures('joinad')
@pytest.mark.ad_access_control
@pytest.mark.tier1_3
class TestAccessControl(object):
    """ Test cases for BZ: 1268902

    :setup:
      1. Join to AD using realm command.
      2. Add the user using adcli user add.
    """
    @staticmethod
    def test_001_simple_allow_user_to_user1(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple_allow_user to user1
        :description: Allow only one ADuser to log in with simple_allow_user option
        :id: 31b37c8e-2ea4-45d3-90a6-b0be9deb1599
        :steps:
        1. Set 'simple_allow_users' to a AD-user
        2. Restart SSSD
        3. Log in with Allowed AD-user
        :expectedresults:
        1. Option should be correctly set
        2. SSSD should start correctly
        3. Allowed ADuser should be able to log in
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_users': f'{aduser}@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF as err:
            pytest.fail(f'{aduser} access is denied by sssd  to login with error: {err}')
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()
        assert aduser in stdout, 'id cmd fetched user information successfully'

    @staticmethod
    def test_002_too_much_logging_from_sssd_be(multihost, create_aduser_group, backupsssdconf):
        """
        :title: too much logging from sssd_be bz1269018
        :description: sssd_be is logging in the authentications in /var/log/messages
        :id: 82dd0c1a-cf62-4e15-978f-2a6e6c4c007c
        :steps:
        1. Clear /var/log/messages
        2. AD-user log in multiple times vi ssh
        :expectedresults:
        1. /var/log/messages should be empty
        2. /var/log/messages should not have logs related sssd_be
        """
        (aduser, _) = create_aduser_group
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_users': f'{aduser}@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        multihost.client[0].run_command('echo > /var/log/messages', raiseonerr=False)
        client_hostname = multihost.client[0].sys_hostname
        for i in range(4):
            locals()[f'cl{i}'] = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
            client = locals()[f'cl{i}']
            try:
                client.login()
            except SSHLoginException:
                pytest.fail(f'{aduser} failed to login')
            else:
                client.logout()
        log_str = multihost.client[0].get_file_contents('/var/log/messages').decode('utf-8')
        patt = re.compile(r'sssd_be')
        assert not patt.findall(log_str)

    @staticmethod
    def test_003_simple_allow_user_to_dollar_symbol(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple_allow_user to dollar symbol
        :description: Setting simple_allow_user to '$' to deny all user log in
        :id: 3317cb9f-fa25-40b4-835b-d8c5da9cda5b
        :steps:
        1. Set simple_allow_user to $ symbol in sssd.conf and restart sssd
        2. Log in as AD user
        :expectedresults:
        2. Changes should reflected in restarted sssd
        2. Any AD-User log in should be denied
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_users': '$'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        sssd_filec = multihost.client[0].get_file_contents('/etc/sssd/sssd.conf').decode('utf-8')
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF as err:
            pytest.fail(f'{aduser} access is denied by sssd  to login with error: {err}')
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()
        log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        patt = re.compile(r'Access.*denied for user')
        assert patt.findall(log_str)

    @staticmethod
    def test_simple_allow_user_to_invalid_user(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple_allow_user to an invalid user
        :id: fdde80ab-1364-4953-893e-62f7c3377ff8
        :description: Setting simple_allow_user to an invalid user, with this sssd would deny log in of all users
        :steps:
        1. Set simple_allow_user to non existing user in sssd.conf and restart sssd
        2. Log in as AD user
        :expectedresults:
        2. Changes should reflected in restarted sssd
        2. User log in should be denied
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_users': f'nonuser@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
            assert patt.findall(log_str)
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()

    @staticmethod
    def test_simple_deny_user_to_user1(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple_deny_user to a user
        :id: 8a068411-4ac7-4b15-b21e-210f3473d164
        :description: Setting simple_deny_user to an AD-user, with this sssd would deny log in of that user only
        :steps:
        1. Set simple_deny_user to a user in sssd.conf and restart sssd
        2. Log in as AD user
        :expectedresults:
        2. Changes should reflected in restarted sssd
        2. User log in should be denied
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_deny_users': f'{aduser}@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
            assert patt.findall(log_str)
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()

    @staticmethod
    def test_simple_deny_user_to_invalid(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple_deby_user to a user
        :id: 76aea575-420b-4276-b0c6-383a4a8499a0
        :description: Setting simple_deny_user to an invalid user would allow all users to log in
        :steps:
        1. Set 'simple_deny_users' to an invalid AD-user
        2. Restart SSSD
        3. Log in with any AD-user
        :expectedresults:
        1. Option should be correctly set
        2. SSSD should start correctly
        3. Any ADuser should be able to log in
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_deny_users': f'nonuser@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
            assert patt.findall(log_str)
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()
        assert aduser in stdout, 'id cmd fetched user information successfully'

    @staticmethod
    def test_simple_allow_groups_top_nested(multihost, create_aduser_group, create_nested_group, backupsssdconf):
        """
        :title: Set simple allow groups to the top-level nested group
        :id: ae19a604-1ce4-4a03-b1a6-4023aa71961f
        :description: Set simple_allow_groups to a top-level nested group. This top-level group will have one group
         as it's member. The member-group has one AD-user as group-member. The AD-user from group should be able to log in.
        :Steps:
        1. Create two groups.
        2. Add one group as a member of other group.
        3. Create an AD user and add that user as member of a member group
        4. Set 'simple_allow_groups' to a top level nested group
        5. Restart SSSD
        6. Log in with Allowed AD-user
        :expectedresults:
        1. Option should be correctly set
        2. SSSD should start correctly
        3. Should succeed
        4. Should succeed
        5. Should succeed
        6. Should succeed
        """
        (l1_grp, l2_grp, aduser) = create_nested_group
        tools = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_groups': f'{l1_grp}@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        cmd = multihost.client[0].run_command(f'id {aduser}@{domain_name}', raiseonerr=False)
        client_hostname = multihost.client[0].sys_hostname
        client1 = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client1.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        else:
            (stdout1, _) = client1.command(f'id {aduser}@{domain_name}')
            client1.logout()
        assert aduser in stdout1, 'id cmd fetched user information successfully'

    @staticmethod
    def test_simple_deny_groups_top_nested(multihost, create_aduser_group, create_nested_group, backupsssdconf):
        """
        :title: Set simple deny groups to the top-level nested group
        :id: 2befaf3c-509d-4421-9276-a8328a9d48ec
        :description: Set simple_deny_groups to a top-level nested group. This top-level group will have one group
         as it's member. The member-group has one AD-user as group-member. The AD-user from group should be able to log in.
        :Steps:
        1. Create two groups.
        2. Add one group as a member of other group.
        3. Create an AD user and add that user as member of a member group
        4. Set 'simple_deny_groups' to a top level nested group
        5. Restart SSSD
        6. Log in with Allowed AD-user
        :expectedresults:
        1. Option should be correctly set
        2. SSSD should start correctly
        3. Should succeed
        4. Should succeed
        5. Should succeed
        6. Log in should deny
        """
        (l1_grp, l2_grp, aduser) = create_nested_group
        tools = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_deny_groups': f'{l1_grp}@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        cmd = multihost.client[0].run_command(f'id {aduser}@{domain_name}', raiseonerr=False)
        cmd1 = cmd.stdout_text
        client_hostname = multihost.client[0].sys_hostname
        client1 = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client1.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        else:
            (stdout1, _) = client1.command(f'id {aduser}@{domain_name}')
            client1.logout()
        patt = re.compile(r'Access.*denied for user')
        assert patt.findall(log_str)

    @staticmethod
    def test_simple_allow_groups_invalid_group(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple allow groups to invalid group
        :id: d930ce65-0488-4e51-886a-c0ca4040fbaa
        :description: Set simple_allow_groups to a invalid group in sssd.conf.
         This should deny log in of any valid AD-user
        :steps:
         1.Set simple_allow_group to the non-existing group
         2.Log in as any AD-user
        :expectedresults:
         1. SSSD should restart correctly
         2. Log in should be denied
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_groups': f'nongrp@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
            assert patt.findall(log_str)
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()

    @staticmethod
    def test_simple_deny_groups_invalid_grp(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set simple deny groups to invalid group
        :id: 2befaf3c-509d-4421-9276-a8328a9d48ec
        :description: Set simple_deny_groups to a invalid group in sssd.conf.
         This should allow log in of any valid AD-user
        :steps:
         1.Set simple_deny_group to the non-existing group
         2.Log in as any AD-user
        :expectedresults:
         1. SSSD should restart correctly
         2. Log in should be successful
        """
        tools = sssdTools(multihost.client[0])
        (aduser, _) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_deny_groups': f'invalidgroup@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF as err:
            pytest.fail(f'{aduser} access is denied by sssd  to login with error: {err}')
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()
        assert aduser in stdout, 'id cmd fetched user information successfully'

    @staticmethod
    def test_permit_all_users(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set access_provider to permit all users
        :id: 747a8268-69b9-4387-bce4-61e7facd03ad
        :description: Set access_provider to permit This should allow log in of any valid AD-user
        :steps:
         1.Set  access_provider to permit in sssd.conf
         2.Log in as any AD-user
        :expectedresults:
         1. SSSD should restart correctly
         2. Log in should be successful
        """
        tools = sssdTools(multihost.client[0])
        (aduser, adgrp) = create_aduser_group
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'permit'}
        tools.sssd_conf(dom_section, sssd_params)
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF as err:
            pytest.fail(f'{aduser} access is denied by sssd  to login with error: {err}')
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()
        assert aduser in stdout, 'id cmd fetched user information successfully'

    @staticmethod
    def test_deny_all_users(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set access provider to deny all users
        :id: 36f82023-3029-4fe4-82b1-7390f01bb5d6
        :description: Set access_provider to deny This should allow log in of any valid AD-user
        :steps:
         1.Set  access_provider to deny in sssd.conf
         2.Log in as any AD-user
        :expectedresults:
         1. SSSD should restart correctly
         2. Log in should be denied
        """
        (aduser, _) = create_aduser_group
        tools = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = tools.get_domain_section_name()
        multihost.client[0].run_command('realm deny --all', raiseonerr=False)
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
            assert patt.findall(log_str)
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()

    @staticmethod
    def test_dont_fail_auth_with_allow_rules(multihost, create_aduser_group, backupsssdconf):
        """
        :title: Set access_provider to permit all users
        :id: 4e746a3b-8f8e-4884-930f-2ae8ef72e626
        :description: When simple_allow_groups has one valid and one invalid group as inputs then
         sssd should ignore invalid group argument. SSSD should allow member-users from valid group
         to log in
        :steps:
         1. Define simple_allow_group with one valid group and one invalid group
         2. Log in from that valid-groups's member-user
        :expectedresults:
         1. SSSD should restart correctly
         2. Log in should be allowed
        """
        (aduser, adgroup) = create_aduser_group
        tools = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = tools.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        sssd_params = {'access_provider': 'simple',
                       'simple_allow_groups': f'{adgroup}@{domain_name}, non_grp@{domain_name}'}
        tools.sssd_conf(dom_section, sssd_params, action='add')
        tools.clear_sssd_cache()
        client_hostname = multihost.client[0].sys_hostname
        client = pexpect_ssh(client_hostname, f'{aduser}@{domain_name}', 'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{aduser} failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        else:
            (stdout, _) = client.command(f'id {aduser}@{domain_name}')
            client.logout()
        assert aduser in stdout, 'id cmd fetched user information successfully'
