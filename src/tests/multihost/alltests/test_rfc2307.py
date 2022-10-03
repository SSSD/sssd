""" Automation of rfc2307

:requirement: rfc2307
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
from sssd.testlib.common.libkrb5 import krb5srv
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_suffix, ds_rootdn, ds_rootpw
from sssd.testlib.common.exceptions import SSHLoginException, LdapException
from sssd.testlib.common.expect import pexpect_ssh


def usr_grp(multihost, obj_info, type):
    """
    Add an object, user or group, in the ldap-server
        :param dict obj_info: an object(user/group) details
        :param str type: Either 'user' or 'group'
        :return: None
        :exception: LdapException
    """
    ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    krb = krb5srv(multihost.master[0], 'EXAMPLE.TEST')
    if type == 'user':
        usr = obj_info.get('uid')
        try:
            if ldap_inst.posix_user("ou=People", ds_suffix, obj_info):
                krb.add_principal(usr, 'user', 'Secret123')
        except LdapException:
            print(f"Unable to add ldap User {obj_info}")
    if type == 'group':
        try:
            ldap_inst.posix_group("ou=Groups", ds_suffix, obj_info,
                                  memberUid=obj_info.get('memberUid'))
        except LdapException:
            print(f"Unable to add ldap group {obj_info}")


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.rfc2307
class Testrfc2307(object):
    """
    This is test case class for ldap rfc2307

        :setup:
          1. Configure SSSD to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
    """
    @pytest.mark.tier2
    def test_0001_bz1362023(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: rfc2307: user with spaces at beginning
        :id: 6923436c-d4e4-4a0d-a8f3-1e94ecb1dee3
        :description: user with a white space at the beginning in it's name
         should be able to log in
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1067476
          https://bugzilla.redhat.com/show_bug.cgi?id=1065534
        :steps:
          1. Create user with a white space at beginning in their name
          2. Restart SSSD with cleared cache
          3. Fetch user information using 'id'
          4. Confirm user is able to log in via ssh
          5. A normal user information is fetched
          6. Confirm a user information is not fetched if a space is added
             as it's first character
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          """
        usr = ' tuser'
        usr_info = {'cn': usr, 'uid': usr,
                    'uidNumber': '34583100',
                    'gidNumber': '34564100'}
        usr_grp(multihost, usr_info, 'user')
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        tools.clear_sssd_cache()
        user = f'\\ tuser@{domain_name}'
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{user} failed to login')
        else:
            id_cmd = f'id {user}'
            cmd = client.command(id_cmd)
            assert 'uid=34583100' in cmd[0]
            client.logout()
        user = f'tuser@{domain_name}'
        cmd = multihost.client[0].run_command(f'id {user}', raiseonerr=False)
        assert cmd.returncode != 0
        user = f'foo1@{domain_name}'
        cmd = multihost.client[0].run_command(f'id {user}', raiseonerr=False)
        assert cmd.returncode == 0
        user = f'\\ foo1@{domain_name}'
        cmd = multihost.client[0].run_command(f'id {user}', raiseonerr=False)
        assert cmd.returncode != 0
