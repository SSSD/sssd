""" Automation of rfc2307

:requirement: rfc2307
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
import random
import re
import time
import ldap
from sssd.testlib.common.libkrb5 import krb5srv
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_suffix, ds_rootdn, ds_rootpw
from sssd.testlib.common.exceptions import SSHLoginException, LdapException
from sssd.testlib.common.expect import pexpect_ssh


def usr_grp(multihost, obj_info, obj_type, action):
    """
    Add an object, user or group, in the ldap-server
        :param dict obj_info: an object(user/group) details
        :param str obj_type: Either 'user' or 'group'
        :param: str action: Either 'add' or 'del'
        :return: None
        :exception: LdapException
    """
    ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    krb = krb5srv(multihost.master[0], 'EXAMPLE.TEST')
    if obj_type == 'user':
        if action == 'add':
            usr = obj_info.get('uid')
            try:
                if ldap_inst.posix_user("ou=People", ds_suffix, obj_info):
                    krb.add_principal(usr, 'user', 'Secret123')
            except LdapException:
                print(f"Unable to add ldap User {obj_info}")
        if action == 'del':
            try:
                ldap_inst.del_dn(f"uid={obj_info['uid']},ou=People,{ds_suffix}")
                krb.delete_principal(f"{obj_info['uid']}")
            except LdapException:
                print(f"Unable to delete ldap user {obj_info}")
    if obj_type == 'group':
        if action == 'add':
            try:
                ldap_inst.posix_group("ou=Groups", ds_suffix, obj_info,
                                      memberUid=obj_info.get('memberUid'))
            except LdapException:
                print(f"Unable to add ldap group {obj_info}")
        if action == 'del':
            try:
                ldap_inst.del_dn(f"cn={obj_info['cn']},ou=Groups,{ds_suffix}")
            except LdapException:
                print(f"Unable to delete ldap group {obj_info}")


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.rfc2307
@pytest.mark.tier1_9
class Testrfc2307(object):
    """
    This is test case class for ldap rfc2307

        :setup:
          1. Configure SSSD to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
    """
    @staticmethod
    def test_0001_bz1362023(multihost, backupsssdconf):
        """
        :title: rfc2307: user with spaces at beginning
        :id: 6923436c-d4e4-4a0d-a8f3-1e94ecb1dee3
        :description: user with a white space at the beginning in it's name
         should be able to log in
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1067476
          https://bugzilla.redhat.com/show_bug.cgi?id=1065534
        :setup:
          1. Create user with a white space at beginning in their name
          2. Restart SSSD with cleared cache
        :steps:
          1. Fetch user information using 'id'
          2. Confirm user is able to log in via ssh
          3. A normal user information is fetched
          4. Confirm a user information is not fetched if a space is added
             as it's first character
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          """
        usr = ' tuser'
        usr_info = {'cn': usr, 'uid': usr,
                    'uidNumber': '34583100',
                    'gidNumber': '34564100'}
        usr_grp(multihost, usr_info, 'user', 'add')
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        tools.clear_sssd_cache()
        user = f'\\ tuser@{domain_name}'
        ssh1 = tools.auth_from_client(f'{user}', 'Secret123') == 3
        cmd = multihost.client[0].run_command(f'id tuser@{domain_name}', raiseonerr=False)
        cmd1 = multihost.client[0].run_command(f'id foo1@{domain_name}', raiseonerr=False)
        user = f'\\ foo1@{domain_name}'
        cmd2 = multihost.client[0].run_command(f'id {user}', raiseonerr=False)
        usr_grp(multihost, usr_info, 'user', 'del')
        assert ssh1 != 0, 'User ssh authentication failed'
        assert cmd.returncode != 0
        assert cmd1.returncode == 0
        assert cmd2.returncode != 0

    @staticmethod
    def test_0002_gecos_finger(multihost):
        """
        :title: rfc2307: user with root user membership
        :id: aaafdfd6-02cd-430d-a1ef-3291a9f54848
        :description: a user, with one of it's group having gid zero,
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748857
        :setup:
        1. Create user and two groups with a different ids and one group with
          with zero gid
        2. Restart SSSD with cleared cache
        :steps:
        1. Fetch user information using 'id'
        2. Fetch group information whose gid is zero
        3. Confirm user is able to log in via ssh
        :expectedresults:
        1. User's group information should not include group with gid=0
        2. Group should not be returned
        3. Successful User login
        """
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        r_num = random.randint(9999, 99999)
        usr = f'user{r_num}'
        usr_info = {'cn': usr, 'uid': usr,
                    'uidNumber': f'{r_num}',
                    'gidNumber': f'{r_num}'}
        usr_grp(multihost, usr_info, 'user', 'add')
        user = f'{usr}@{domain_name}'
        memberdn = f'uid={usr},ou=People,{ds_suffix}'
        grp_dict = {f'grp{r_num}': r_num,
                    f'grp{r_num+1}': r_num+1,
                    f'root{r_num}': '0'}
        for obj in grp_dict:
            group_info = {'cn': obj,
                          'gidNumber': f'{grp_dict.get(obj)}',
                          'memberUid': f'{usr}',
                          'uniqueMember': memberdn}
            usr_grp(multihost, group_info, 'group', 'add')
        client.clear_sssd_cache()
        id_usr = multihost.client[0].run_command(f'id {usr}@{domain_name}', raiseonerr=False)
        get_grp = multihost.client[0].run_command(f'getent -s sss group root{r_num}@{domain_name}', raiseonerr=False)
        ssh1 = client.auth_from_client(f'{user}', 'Secret123') == 3
        usr_grp(multihost, usr_info, 'user', 'del')
        for obj in grp_dict:
            group_info = {'cn': obj,
                          'gidNumber': f'{grp_dict.get(obj)}'}
            usr_grp(multihost, group_info, 'group', 'del')
        assert f'root{r_num}' not in id_usr.stdout_text, f'group with gid 0 is returned'
        assert get_grp.returncode != 0, f'group with gid 0 is returned'
        assert ssh1, 'User authentication failed'

    @staticmethod
    def test_0003_skip_groups_with_gidNumber_is_zerobz748865(multihost, backupsssdconf):
        """
        :title: rfc2307: user with root user membership
        :id: fdf26120-1163-4a95-a8b8-3c0b7c8abfae
        :description: skip a group with gid set to zero
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748857
        :setups:
        1. Configure sssd to authenticate against directory server
        2. Create a user, and a zero-gid group
        3. Add newly created user to the zero-gid group
        4. Restart SSSD with cleared cache
        :steps:
        1. Fetch user information using 'id'
        2. Fetch group information whose gid is zero
        2. Confirm user is able to log in via ssh
        :expectedresults:
        1. Users group information should not return zero-gid-group
        2. Group with gid=0 should not be returned
        3. User login successful
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        r_num = random.randint(9999, 99999)
        usr = f'user{r_num}'
        user = f'{usr}@{domain_name}'
        usr_info = {'cn': usr, 'uid': usr,
                    'uidNumber': f'{r_num}',
                    'gidNumber': f'{r_num}'}
        usr_grp(multihost, usr_info, 'user', 'add')
        group_info = {'cn': f'testgrp{r_num}',
                      'gidNumber': '0',
                      'memberUid': usr,
                      'uniqueMember': f'uid={usr},ou=People,{ds_suffix}'
                     }
        usr_grp(multihost, group_info, 'group', 'add')
        tools.clear_sssd_cache()
        id_usr = multihost.client[0].run_command(f'id user{r_num}@{domain_name}', raiseonerr=False)
        get_grp = multihost.client[0].run_command(f'getent -s sss group testgrp{r_num}@{domain_name}', raiseonerr=False)
        ssh1 = tools.auth_from_client(f'user{r_num}@{domain_name}', 'Secret123') == 3
        usr_grp(multihost, usr_info, 'user', 'del')
        usr_grp(multihost, group_info, 'group', 'del')
        assert f'testgrp{r_num}' not in id_usr.stdout_text, f'group with gid 0 is returned'
        assert get_grp.returncode != 0, f'group with gid 0 is returned'
        assert ssh1, 'User failed to log in via ssh'


    @staticmethod
    @pytest.mark.flaky(reruns=5, reruns_delay=30)
    def test_0005_user_groups_special_character(multihost, backupsssdconf):
        """
        :title: rfc2307: user and groups with special characters
        :id: 86cd52ca-559e-4a3f-aafd-ed529fe498b5
        :description: users as well as members with groups with special
         characters in their name can log in or ther
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748857
        :steps:
        3. Create user, and add it to a group with a zero gid
        4. Restart SSSD with cleared cache
        5. Fetch user information using 'id'
        6. Confirm user is able to log in via ssh
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        4. Should succeed
        5. Should succeed
        6. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        start = multihost.client[0].service_sssd('start')
        r_num = random.randint(9999, 99999)
        char = [' ', '_', '|', '&', '*', '{', '[', '}', ']', "'", '!', '?', '.']
        for sp_char in char:
            usr_info = {'cn': f'user{sp_char}{r_num}', 'uid': f'user{sp_char}{r_num}',
                        'uidNumber': f'{r_num}',
                        'gidNumber': f'{r_num}'}
            usr_grp(multihost, usr_info, 'user', 'add')
            memberdn = f'uid=user{sp_char}{r_num},ou=People,{ds_suffix}'
            grp = f'grp{sp_char}{r_num}'
            group_info = {'cn': f'{grp}',
                          'gidNumber': f'{r_num}',
                          'memberUid': f'user{sp_char}{r_num}',
                          'uniqueMember': memberdn}
            usr_grp(multihost, group_info, 'group', 'add')
            tools.clear_sssd_cache()
            user = f'user\\{sp_char}{r_num}@{domain_name}'
            grp_n = f'grp\\{sp_char}{r_num}@{domain_name}'
            cmd = multihost.client[0].run_command(f'id {user}', raiseonerr=False)
            cmd_returnc0de = cmd.returncode
            ssh1 = tools.auth_from_client(f'{user}', 'Secret123') == 3
            client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                                 'Secret123', debug=False)
            try:
                client.login()
            except SSHLoginException:
                pytest.fail(f'{user} failed to login')
            else:
                cmds = [f'id -gn {user}',
                        f'getent -s sss passwd {user}',
                        f'getent -s sss group {grp_n}']
                for cmdz in cmds:
                    (opt, ret) = client.command(cmdz)
                    ptn = re.compile(f'{r_num}')
                    assert ptn.search(opt), 'failed to fetch User and group information'
                client.logout()
            usr_grp(multihost, usr_info, 'user', 'del')
            usr_grp(multihost, group_info, 'group', 'del')

    @staticmethod
    def test_0006_explicit_base_converting_uidNumber_to_int(multihost, backupsssdconf):
        """
        :title: rfc2307: explct_base_convrtng_uidnumber_to_int
        :id: 86cd52ca-559e-4a3f-aafd-ed529fe498b5
        :description: Use an explicit base 10 when converting uidNumber
         to integer
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748881
        :steps:
        3. Create user, and set gecos attribute to expected gid number
        4. Set 'ldap_user_uid_numer = gecos' in domain section of sssd.conf
        5. Restart SSSD with cleared cache
        6. Confirm user is able to log in via ssh
        7. Confirm with getent that gid of user is taken from the option set in sssd.conf
        8. Confirm with id command that gid of user is taken from the option set in sssd.conf
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        4. Should succeed
        5. Should succeed
        6. Should succeed
        7. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        num = random.randint(9999, 99999)
        usr = f'user{num}'
        usr_info = {'cn': usr, 'uid': usr,
                    'uidNumber': f'{num}',
                    'gecos': f'{num}',
                    'gidNumber': f'{num}'}
        usr_grp(multihost, usr_info, 'user', 'add')
        param = {'ldap_user_uid_number': 'gecos'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        user = f'{usr}@{domain_name}'
        ssh1 = tools.auth_from_client(f'{user}', 'Secret123') == 3
        getent = multihost.client[0].run_command(f'getent -s sss passwd {user}')
        id_cmd = multihost.client[0].run_command(f'id -g {user}')
        assert ssh1 != 0, 'User is not able to log in'
        assert f'{num}' in getent.stdout_text, 'getent is not fetching user info'
        assert f'{num}' in id_cmd.stdout_text, 'id is not fetching user group info'

    @staticmethod
    def test_0007_login_user_with_local_group_as_primary(multihost,
                                                         backupsssdconf):
        """
        :title: rfc2307: user with local group membership
         able to log in
         are denied access by the simple access provider bz700168
        :id: 8e2191ca-17de-4fb4-ad8d-efd9dcd70b0e
        :description: log in as a user whose primary group is local group
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748881
        :steps:
        3. Create user with membership of a group with gid of 100
        4. Restart SSSD with cleared cache
        5. Confirm user is able to log in via ssh
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        4. Should succeed
        5. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        num = random.randint(9999, 99999)
        usr = f'user{num}'
        usr_info = {'cn': usr, 'uid': usr,
                    'uidNumber': f'{num}',
                    'gecos': f'{num}',
                    'gidNumber': '100'}
        usr_grp(multihost, usr_info, 'user', 'add')
        memberdn = f'uid={usr},ou=People,{ds_suffix}'
        group_info = {'cn': f'grp_{usr}',
                      'gidNumber': f'{num}',
                      'memberUid': f'{usr}',
                      'uniqueMember': memberdn}
        usr_grp(multihost, group_info, 'group', 'add')
        user = f'{usr}@{domain_name}'
        param = {'access_provider': 'simple',
                 'simple_allow_groups': f'grp_{usr}@{domain_name}'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        time.sleep(3)
        user = f'{usr}@{domain_name}'
        ssh1 = tools.auth_from_client(f'{user}', 'Secret123') == 3
        logfile = '/var/log/secure'
        pattern = re.compile(r'System error')
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        usr_grp(multihost, usr_info, 'user', 'del')
        usr_grp(multihost, group_info, 'group', 'del')
        assert not pattern.search(log)
        assert ssh1 != 0, 'User authentication failed'

    @staticmethod
    def test_0008_sssd_be_process_killed_by_signal_11(multihost,
                                                      backupsssdconf):
        """
        :title: rfc2307: sssd be process is killed by signal 11
         when ldap uri is misconfigured bz748836
        :id: 98938a7d-3ed1-4b01-986e-9dc0bce4e147
        :description: log in as a user whose primary group is local group
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748881
        :steps:
        3. Set ldap_uri value to non-existent or blank
        4. Restart SSSD with cleared cache
        5. Confirm there is no segfault in /var/log/messages
        6. Confirm that sssd domain log complains about absence of host
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        4. Should succeed
        5. Should succeed
        6. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        param = {'ldap_uri': 'ldap://'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        mesg_log = '/var/log/messages'
        segf_pat = re.compile(r'segfault at')
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        logfile = f'/var/log/sssd/sssd_{domain_name}.log'
        host_pat = re.compile(r'did not contain a host name')
        log1 = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        assert segf_pat.search(mesg_log), 'missing a segfault related log in /var/log/messages'
        assert not host_pat.search(log1), 'missing a hostname related log in domain log'

    #@staticmethod
    #def test_0009_asyn_resolver_tries_only_first_nameserver(multihost,
    #                                                        backupsssdconf):
    #    """
    #    :title: rfc2307: async resolver only tries first nameserver in resolv conf
    #     when ldap uri is misconfigured bz748836
    #    :id: 10c5ffac-71a0-41e4-be20-251e6b86f7e2
    #    :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748881
    #    :steps:
    #    1. In /etc/resolv.conf add first nameserver entry to 127.0.0.2
    #       and next nameserver should be working entry
    #    2. Restart SSSD with cleared cache
    #    3. Assert the users are able to log in
    #    4. Confirm that sssd domain log complains connectivity to DNS server
    #    :expectedresults:
    #    1. Should succeed
    #    2. Should succeed
    #    3. Should succeed
    #    4. Should succeed
    #    5. Should succeed
    #    6. Should succeed
    #    """
    #    tools = sssdTools(multihost.client[0])
    #    domain_name = tools.get_domain_section_name()
    #    num = random.randint(9999, 99999)
    #    usr = f'user{num}'
    #    usr_info = {'cn': usr, 'uid': usr,
    #                'uidNumber': f'{num}',
    #                'gidNumber': f'{num}'}
    #    usr_grp(multihost, usr_info, 'user', 'add')
    #    multihost.client[0].run_command('cp /etc/resolv.conf /etc/resolv.conf_bk', raiseonerr=False)
    #    cmd = "sed -i '1i nameserver 127.0.0.2' /etc/resolv.conf"
    #    multihost.client[0].run_command(cmd, raiseonerr=False)
    #    tools.clear_sssd_cache()
    #    user = f'{usr}@{domain_name}'
    #    client = pexpect_ssh(multihost.client[0].sys_hostname, user,
    #                         'Secret123', debug=False)
    #    try:
    #        client.login()
    #    except SSHLoginException:
    #        pytest.fail(f'{usr} failed to login')
    #    else:
    #        getent = f'getent -s sss passwd {user}'
    #        (opt, ret) = client.command(getent)
    #        assert f'{user}' in opt
    #        client.logout()
    #    usr_grp(multihost, usr_info, 'user', 'del')
    #    logfile = f'/var/log/sssd/sssd_{domain_name}.log'
    #    pattern = re.compile(r'Could not contact DNS', re.IGNORECASE)
    #    log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
    #    multihost.client[0].run_command('cp /etc/resolv.conf_bk /etc/resolv.conf', raiseonerr=False)
    #    assert pattern.search(log)

    @staticmethod
    def test_0010_enumerate_outof_range_uidNumber_user(multihost,
                                                       backupsssdconf):
        """
        :title: rfc2307: Enumerate user with uidNumber out of
         min id and max id range
        :id: 66058978-1832-4505-a355-e7855d62a681
        :setup:
        1. Create two user and groups with different uidNumber and gidNumbers
        2. In the domain section of sssd.conf, set min_id and max_id outside
           of uid,gidNumber set for users and groups
        3. Restart SSSD with cleared cache
        :steps:
        1. Assert the users and groups information is not returned
        2. sssd domain log complains about 'id out of range'
        :expectedresults:
        1. Should succeed
        2. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        param = {'min_id': '21000', 'max_id': '29000'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        id_list = ['20000', '30000']
        for num in id_list:
            usr_info = {'cn': f'user{num}', 'uid': f'user{num}',
                        'uidNumber': f'{num}',
                        'gidNumber': f'{num}'}
            usr_grp(multihost, usr_info, 'user', 'add')
            memberdn = f'uid=user{num},ou=People,{ds_suffix}'
            group_info = {'cn': f'grp{num}',
                          'gidNumber': f'{num}',
                          'memberUid': usr_info['uid'],
                          'uniqueMember': memberdn}
            usr_grp(multihost, group_info, 'group', 'add')
            cmd1 = multihost.client[0].run_command(f'getent passwd -s sss user{num}@{domain_name}', raiseonerr=False)
            cmd2 = multihost.client[0].run_command(f'getent group -s sss grp{num}@{domain_name}', raiseonerr=False)
            time.sleep(2)
            logfile = f'/var/log/sssd/sssd_{domain_name}.log'
            multihost.client[0].run_command(f'cp -f {logfile} /tmp/log1', raiseonerr=False)
            multihost.client[0].run_command('cp /etc/sssd/sssd.conf /tmp/sssd.conf', raiseonerr=False)
            log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
            pattern = re.compile(r'Group.*id out of range', re.IGNORECASE)
            pattern1 = re.compile(r'User.*id out of range', re.IGNORECASE)
            assert cmd1.returncode != 0, 'user information was fetched'
            assert cmd2.returncode != 0, 'group information was fetched'
            assert pattern.search(log), 'Expected log for out-of-range gid is absent'
            assert pattern1.search(log), 'Expected log for out-of-range uid is absent'

    @staticmethod
    def test_0011_lookup_authentication_over_starttls(multihost,
                                                      backupsssdconf):
        """
        :title: rfc2307: Lookup and authentication over STARTTLS
        :id: d33e7f71-1571-4570-9848-3777a6321aa4
        :setup:
        1. Enable 'ldap_id_use_start_tls' and related options in domain section
        :steps:
        1. Confirm user information is fetched and authentication of user
           is working
        2. Disable 'ldap_tls_cacert' option and set 'ldap_tls_reqcert'
           to 'never'
        3. Assert the users information is not fetched
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        """
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        param = {'ldap_id_use_start_tls': 'true',
                 'ldap_uri': f'{ldap_uri}'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        user = f'foo1@{domain_name}'
        get_cmd = multihost.client[0].run_command(f'getent -s sss passwd foo1@{domain_name}', raiseonerr=False)
        logfile = f'/var/log/sssd/sssd_{domain_name}.log'
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        pattern1 = re.compile(r'Executing START TLS')
        client = pexpect_ssh(multihost.client[0].sys_hostname, f'foo1@{domain_name}',
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'foo1@{domain_name} failed to login')
        else:
            getent = f'getent -s sss passwd foo1@{domain_name}'
            (opt, ret) = client.command(getent)
            assert f'foo1@{domain_name}' in opt, 'user authentication failed'
            client.logout()
        param = {'ldap_tls_reqcert': 'never'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        param = {'ldap_tls_cacert': '/etc/openldap/certs/cacert.asc'}
        tools.sssd_conf(f'domain/{domain_name}', param, action='delete')
        tools.clear_sssd_cache()
        cmd = multihost.client[0].run_command(f'getent -s sss passwd foo1@{domain_name}', raiseonerr=False)
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{usr} failed to login')
        else:
            getent = f'getent -s sss passwd {user}'
            (opt, ret) = client.command(getent)
            assert f'{user}' in opt
            client.logout()
        assert get_cmd.returncode == 0, 'failed to fetch foo1 user info'
        assert pattern1.search(log), 'Expected START_TLS pattern missing in log'
        assert cmd.returncode == 0, 'failed to fetch foo1 user info'

    @staticmethod
    def test_0012_lookup_rfc2307_nst_groups(multihost,
                                            create_nested_usersgroups,
                                            backupsssdconf):
        """
        :title: rfc2307: Lookup and authentication over STARTTLS
        :id: d33e7f71-1571-4570-9848-3777a6321aa4
        :setup:
        1. Create user and two-level nested groups
        2. Create a first-level-nested(level-1) group which has a primary group of user as a member
        3. Create a top-level(level-2) nested group which has a first-level-group as member
        :steps:
        1. Fetch primary group information of user
        2. Fetch first-level-nested group information of user
        3. Fetch second-level-nested group information of user
        4. Fetch user information
        5. Authenticate as User
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        4. Should succeed
        5. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        tools.clear_sssd_cache()
        num = create_nested_usersgroups
        user = f'usr_{num}@{domain_name}'
        cmd1 = multihost.client[0].run_command(f'getent group ng{num}@{domain_name}', raiseonerr=False)
        cmd2 = multihost.client[0].run_command(f'getent group ng{int(num)+1}@{domain_name}', raiseonerr=False)
        cmd3 = multihost.client[0].run_command(f'getent group ng{int(num)+2}@{domain_name}', raiseonerr=False)
        cmd4 = multihost.client[0].run_command(f'id {user}', raiseonerr=False)
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail(f'{user} failed to login')
        else:
            getent = f'getent -s sss passwd {user}'
            (opt, ret) = client.command(getent)
            assert f'{user}' in opt
            client.logout()
        assert f'{user}' in cmd1.stdout_text, 'User is not returned in group'
        assert f'ng{num}' in cmd2.stdout_text, 'level-1 nested group is not returned'
        assert f'ng{int(num)+1}' in cmd3.stdout_text, 'level-2 nested group is not returned'
        assert f'ng{num}' in cmd4.stdout_text, 'User information not returned group membership'
        assert f'ng{int(num)+1}' not in cmd4.stdout_text, 'Incorrect nested group information returned for user'
        assert f'ng{int(num)+2}' not in cmd4.stdout_text, 'Incorrect nested group information returned for user'

    @staticmethod
    def test_0013_rfc2307_case_sensitive_usergroup(multihost,
                                                   backupsssdconf):
        """
        :title: rfc2307: Lookup and authentication over STARTTLS
        :id: d33e7f71-1571-4570-9848-3777a6321aa4
        :setup:
        1. Create user and groups with different cases(uppercase,lowercase, mixed)
        :steps:
        1. User with upper and lowercase name is fetched
        2. group with upper and lowercase name is fetched
        3. Authentication of all user
        :expectedresults:
        1. Should succeed
        2. Should succeed
        2. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        tools.clear_sssd_cache()
        usr_info = {'cn': f'Test user 1', 'uid': f'testuser1',
                    'uidNumber': f'11111',
                    'gidNumber': f'11111'}
        usr_grp(multihost, usr_info, 'user', 'add')
        usr_info = {'cn': f'TEST USER 2', 'uid': f'TESTUSER2',
                    'uidNumber': f'22222',
                    'gidNumber': f'22222'}
        usr_grp(multihost, usr_info, 'user', 'add')
        memberdn = f'uid=testuser1,ou=People,{ds_suffix}'
        group_info = {'cn': f'grp1_testuser1',
                      'gidNumber': f'11111',
                      'memberUid': f'TESTUSER1'
                      }
        usr_grp(multihost, group_info, 'group', 'add')
        memberdn = f'uid=TESTuser2,ou=People,{ds_suffix}'
        group_info = {'cn': f'GRP2_testuser2',
                      'gidNumber': f'22222',
                      'memberUid': f'TESTuser2'
                      }
        usr_grp(multihost, group_info, 'group', 'add')
        cmd = multihost.client[0].run_command(f'getent -s sss passwd testuser1@{domain_name}', raiseonerr=False)
        cmd1 = multihost.client[0].run_command(f'getent -s sss passwd TESTUSER2@{domain_name}', raiseonerr=False)
        cmd2 = multihost.client[0].run_command(f'getent -s sss group grp1_testuser1@{domain_name}', raiseonerr=False)
        cmd3 = multihost.client[0].run_command(f'getent -s sss group GRP2_testuser2@{domain_name}', raiseonerr=False)
        ssh = tools.auth_from_client(f'testuser1@{domain_name}', 'Secret123') == 3
        ssh1 = tools.auth_from_client(f'TESTUSER2@{domain_name}', 'Secret123') == 3
        assert cmd.returncode == 0, 'Failed to fetch testuser1 user info'
        assert cmd1.returncode == 0, 'Failed to fetch TESTUSER2 user info'
        assert cmd2.returncode == 0, 'Failed to fetch grp1_testuser1 group info'
        assert cmd3.returncode == 0, 'Failed to fetch GRP2_testuser2 group info'
        assert ssh != 0, 'testuesr1 Authentication failed'
        assert ssh1 != 0, 'TESTUSER2 Authentication failed'

    @staticmethod
    def test_0014_lookup_user_with_multi_uid(multihost,
                                               backupsssdconf):
        """
        :title: rfc2307: Lookup fails for non primary usernames with multi valued uid
        :id: 5516c28a-f490-44f2-922a-cd8a44f84a8a
        :setup:
        1. Create user with multi valued uids
        2. Create a group and add previously created user as it's member
        :steps:
        1. Fetch user information is fetched
        2. Fetch user information with additional uid value
        3. Fetch group information
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        """
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        tools.sssd_conf(f'domain/{domain_name}', {'ldap_id_use_start_tls': 'true'})
        tools.clear_sssd_cache()
        usr = 'testuser6'
        usr_info = {'cn': 'Test_user_6',
                    'uid': f'{usr}',
                    'uidNumber': '16111',
                    'gidNumber': '16111'}
        usr_grp(multihost, usr_info, 'user', 'add')
        memberdn = f'uid=testuser6,ou=People,{ds_suffix}'
        grp = 'grp1_6'
        group_info = {'cn': f'{grp}',
                      'gidNumber': '16111',
                      'memberUid': 'testuser6',
                      'uniqueMember': memberdn}
        usr_grp(multihost, group_info, 'group', 'add')
        u_ou = f'ou=People,{ds_suffix}'
        usr_dn = f'uid={usr},{u_ou}'
        extra_uid = 'testuser_6'
        add_extra = [(ldap.MOD_ADD, 'uid',
                     extra_uid.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(usr_dn, add_extra)
        u_g = {f'{usr}': 'passwd',
                f'{extra_uid}': 'passwd',
                f'{grp}': 'group'}
        for obj in u_g:
            cmd = multihost.client[0].run_command(f'getent -s sss {u_g[obj]} {obj}@{domain_name}', raiseonerr=False)
            assert cmd.returncode == 0, f'SSSD failed to return "{obj}"'

    @staticmethod
    def test_0015_correct_default_autofs_schema(multihost,
                                                backupsssdconf):
        """
        :title: rfc2307: Default values of autofs schema should
                be set by sssd
        :id: 5516c28a-f490-44f2-922a-cd8a44f84a8a
        :steps:
        1. Start the sssd with default configuration
        2. Confirm the default autofs schema values are set correctly
           is working
        :expectedresults:
        1. Should succeed
        2. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        logfile = f'/var/log/sssd/sssd_{domain_name}.log'
        tools.clear_sssd_cache()
        time.sleep(3)
        log = multihost.client[0].get_file_contents(f'{logfile}').decode('utf-8')
        pat = re.compile(r'ldap_autofs_map_object_class has value nisMap')
        assert pat.search(log), 'expected nisMap log missing'
        pat1 = re.compile(r'ldap_autofs_map_name has value nisMapName')
        assert pat1.search(log), 'expected nisMapName log missing'
        pat2 = re.compile(r'ldap_autofs_entry_object_class has value nisObject')
        assert pat2.search(log), 'expected nisObject log missing'

    @staticmethod
    def test_0016_disable_anonymous_bind_on_server(multihost,
                                                   disable_anonymous_bind,
                                                   backupsssdconf):
        """
        :title: rfc2307: Disable anonymous bind on the server
        :id: 5516c28a-f490-44f2-922a-cd8a44f84a8a
        :setup:
        1. Disable anonymous bind on ldap-server
        :steps:
        1. Confirm user information is fetched and authentication of user
           is working
        :expectedresults:
        1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        param = {'ldap_default_bind_dn': f'{ds_rootdn}',
                 'ldap_default_authtok': f'{ds_rootpw}'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        cmd = multihost.client[0].run_command(f'getent -s sss passwd foo1@{domain_name}', raiseonerr=False)
        ssh1 = tools.auth_from_client(f'foo1@{domain_name}', 'Secret123') == 3
        assert cmd.returncode == 0, 'failed to fetch user info'
        assert ssh1 != 0, 'Authentication failed'


    @staticmethod
    def test_0017_enumerate_with_disabled_annon_bind(multihost,
                                                     disable_anonymous_bind,
                                                     backupsssdconf):
        """
        :title: rfc2307: Disable anonymous bind on the server and
         enumerate set to true bz872683
        :id: d009597b-4196-4b83-8c6c-c07979d66929
        :steps:
        1. Disable anonymous bind on the ldap server
        2. Set enumerate to true in the domain section
        3. Confirm user information is fetched and authentication of user
           is working
        :expectedresults:
        1. Should succeed
        2. Should succeed
        3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        param = {'ldap_default_bind_dn': f'{ds_rootdn}',
                 'enumerate': 'true',
                 'ldap_default_authtok': f'{ds_rootpw}'}
        tools.sssd_conf(f'domain/{domain_name}', param)
        tools.clear_sssd_cache()
        ssh1 = tools.auth_from_client(f'foo1@{domain_name}', 'Secret123') == 3
        assert cmd.returncode == 0, 'failed to fetch user info'
        assert ssh1 != 0, 'Authentication failed'
