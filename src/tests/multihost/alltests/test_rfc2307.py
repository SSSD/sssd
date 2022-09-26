""" Automation of proxy provider suite

:requirement: IDM-SSSD-REQ : Proxy Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
from __future__ import print_function
import pytest
import subprocess
import time
from sssd.testlib.common.utils import sssdTools, LdapOperations
from sssd.testlib.common.exceptions import SSHLoginException
from sssd.testlib.common.expect import pexpect_ssh
from constants import ds_suffix, ds_instance_name


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.fixture(scope='class')
def ldap_objects_sssd_client(multihost, request):
    """
        Configure sssd.conf
        Create a dedicated user with
        a DN starting e.g. with cn=...
        Create a local user foo12
    """
    ldap_uri = 'ldap://%s' % multihost.master[0].sys_hostname
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    user_info = {'objectClass': [b'top', b'organizationalUnit'],
                 'ou': 'Users'.encode('utf-8')}
    users_dn = 'ou=Users,dc=example,dc=test'
    (_, _) = ldap_inst.add_entry(user_info, users_dn)
    user_info = {'cn': 'User_CS1'.encode('utf-8'),
                 'homeDirectory': '/home/User_CS1'.encode('utf-8'),
                 'objectClass': [b'account',
                                 b'posixAccount'],
                 'uidNumber': '111111'.encode('utf-8'),
                 'gidNumber': '111111'.encode('utf-8'),
                 'loginShell': '/bin/bash'.encode('utf-8'),
                 'userPassword': 'Secret123'.encode('utf-8'),
                 'uid': ['User_CS1'.encode('utf-8'),
                         'User_CS1_Alias'.encode('utf-8')] }
    user_dn = f'uid=User_CS1,ou=Users,{ds_suffix}'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)
    grop_info = {'cn': ['User_CS1_grp1'.encode('utf-8'),
                        'User_CS1_grp1_Alias'.encode('utf-8')],
                 'objectClass': b'posixGroup',
                 'gidNumber': '111111'.encode('utf-8'),
                 'memberUid': 'User_CS1'.encode('utf-8')}
    group_dn = f'cn=User_CS1_grp1,ou=Groups,{ds_suffix}'
    (_, _) = ldap_inst.add_entry(grop_info, group_dn)
    execute_cmd(multihost, "> /etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'base {ds_suffix}' > "
                                   f"/etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'pam_password md5' >>"
                                   f" /etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'host {multihost.master[0].ip}' "
                                   f">> /etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'tls_cacertfile "
                                   f"/etc/openldap/certs/cacert.asc'"
                                   f" >> /etc/pam_ldap.conf")
    if '9' in execute_cmd(multihost, "cat /etc/redhat-release").stdout_text:
        execute_cmd(multihost, "echo 'validnames /^[a-z0-9._@$()]([a-z0-9._@$()"
                               " \\~-]*[a-z:0-9._@$()~-])?$/i' >> /etc/nslcd.conf")
    execute_cmd(multihost, 'systemctl restart nslcd')

    def restoresssdconf():
        """ Restore sssd.conf """
        for cn in ['User_CS1',
                   'newuser',
                   'user1',
                   'user2']:
            ldap_inst.del_dn(f'uid={cn},ou=Users,{ds_suffix}')
        for cn in ['User_CS1_grp1',
                   'newgroup',
                   'childgroup',
                   'middlegroup',
                   'topgroup']:
            ldap_inst.del_dn(f'cn={cn},ou=Groups,{ds_suffix}')
        ldap_inst.del_dn(users_dn)
        execute_cmd(multihost, "rm -vf /etc/pam_ldap.conf")

    request.addfinalizer(restoresssdconf)


@pytest.mark.usefixtures('setupds',
                         'default_sssd',
                         'sssdproxyldap',
                         'install_nslcd',
                         'ldap_objects_sssd_client')
@pytest.mark.tier1_3
class TestProxyMisc(object):
    """
    This is test case class for proxy provider suite
    """
    def test_lookup_user_group(self, multihost, backupsssdconf):
        """
        :title: case sensitive is true lookup user group
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive = true, lookup user group
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["id User_CS1 | grep User_CS1_grp1",
                  "id User_CS1_Alias | grep User_CS1_grp1",
                  "getent passwd User_CS1 | grep User_CS1",
                  "getent passwd User_CS1_Alias | grep User_CS1",
                  "getent group User_CS1_grp1 | grep User_CS1_grp1",
                  "getent group User_CS1_grp1 | grep User_CS1",
                  "getent group User_CS1_grp1_Alias | grep User_CS1_grp1",
                  "getent group User_CS1_grp1_Alias | grep User_CS1"]:
            execute_cmd(multihost, i)
        client_hostip = multihost.client[0].ip
        for user in ['User_CS1', 'User_CS1_Alias']:
            client = pexpect_ssh(client_hostip, user, 'Secret123', debug=False)
            try:
                client.login(login_timeout=30, sync_multiplier=5,
                             auto_prompt_reset=False)
            except SSHLoginException:
                pytest.fail("%s failed to login" % user)
            else:
                client.logout()
        for i in ["getent passwd user_cs1",
                  "getent passwd user_cs1_alias",
                  "getent group user_cs1_grp1",
                  "getent group user_cs1_grp1"]:
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, i)

    def test_enumerate_users_groups(self, multihost, backupsssdconf):
        """
        :title: enumerate users groups
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While enumerate=True, lookup user group
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'enumerate': 'true'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent -s sss passwd | grep User_CS1",
                  "getent -s sss group | grep User_CS1_grp1"]:
            execute_cmd(multihost, i)

    def test_simple_deny_groups_user_cs1_grp1(self, multihost, backupsssdconf):
        """
        :title: simple deny groups is User CS1 grp1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=True, simple deny groups is User CS1 grp1
        :expectedresults:
          1. Should not succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'true',
                         'access_provider': 'simple',
                         'simple_deny_groups': 'User_CS1_grp1,User_CS1_grp1_Alias' }
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent group User_CS1_grp1",
                  "id User_CS1",
                  "> /var/log/secure"]:
            execute_cmd(multihost, i)
        client_hostip = multihost.client[0].ip
        client = pexpect_ssh(client_hostip, "User_CS1", 'Secret123', debug=False)
        with pytest.raises(Exception):
            client.login(login_timeout=10, sync_multiplier=1,
                         auto_prompt_reset=False)
        time.sleep(3)
        execute_cmd(multihost, 'cat /var/log/secure | grep "Access denied for user User_CS1"')

    def test_simple_deny_groups_user_cs_grp1(self, multihost, backupsssdconf):
        """
        :title: simple deny groups is user cs1 grp1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=True, simple deny groups is user cs1 grp1
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'true',
                         'access_provider': 'simple',
                         'simple_deny_groups': "user_cs1_grp1" }
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent passwd User_CS1", "id User_CS1"]:
            execute_cmd(multihost, i)
        client_hostip = multihost.client[0].ip
        client = pexpect_ssh(client_hostip, "User_CS1", 'Secret123', debug=False)
        try:
            client.login(login_timeout=30, sync_multiplier=5,
                         auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % "User_CS1")
        else:
            client.logout()

    def test_simple_deny_users_user_CS1(self, multihost, backupsssdconf):
        """
        :title: simple deny users is User CS1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=True, simple deny users is User CS1
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'true',
                         'access_provider': 'simple',
                         'simple_deny_users': 'User_CS1,User_CS1_Alias'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent group User_CS1_grp1",
                  "id User_CS1",
                  "> /var/log/secure"]:
            execute_cmd(multihost, i)
        client_hostip = multihost.client[0].ip
        client = pexpect_ssh(client_hostip, "User_CS1", 'Secret123', debug=False)
        with pytest.raises(Exception):
            client.login(login_timeout=10, sync_multiplier=1,
                         auto_prompt_reset=False)
        time.sleep(3)
        execute_cmd(multihost, 'cat /var/log/secure | grep "Access denied for user User_CS1"')

    def test_simple_deny_users_user_cs1(self, multihost, backupsssdconf):
        """
        :title: simple deny users is user cs1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=True, simple deny users is user cs1
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'true',
                         'simple_deny_users': 'user_cs1'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        client_hostip = multihost.client[0].ip
        client = pexpect_ssh(client_hostip, "User_CS1", 'Secret123', debug=False)
        try:
            client.login(login_timeout=30, sync_multiplier=5,
                         auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % "User_CS1")
        else:
            client.logout()

    def test_bz1007381(self, multihost, backupsssdconf):
        """
        :title: proxy provider: id lookup shows "Memory buffer error" in domain log
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1007381
        :steps:
          1. id lookup shows "Memory buffer error" in domain log
        :expectedresults:
          1. Should not succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        execute_cmd(multihost, "id User_CS1")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "grep 'Memory buffer' /var/log/sssd/*")

    def test_negative_cache(self, multihost):
        """
        :title: negative cache test
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. Wait for negative cache to expire - default 15 seconds
        :expectedresults:
          1. Should succeed
        """
        for command in ["getent -s sss passwd newuser",
                        "getent -s sss group newgroup"]:
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, command)
        ldap_uri = 'ldap://%s' % multihost.master[0].sys_hostname
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_info = {'cn': 'newuser'.encode('utf-8'),
                     'homeDirectory': '/home/newuser'.encode('utf-8'),
                     'objectClass': [b'account',
                                     b'posixAccount'],
                     'uidNumber': '123456'.encode('utf-8'),
                     'gidNumber': '123456'.encode('utf-8'),
                     'userPassword': 'Secret123'.encode('utf-8'),
                     'uid': 'newuser'.encode('utf-8')}
        user_dn = f'uid=newuser,ou=Users,{ds_suffix}'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        grop_info = {'cn': 'newgroup'.encode('utf-8'),
                     'objectClass': b'posixGroup',
                     'gidNumber': '123456'.encode('utf-8'),
                     'memberUid': 'newuser'.encode('utf-8')}
        group_dn = f'cn=newgroup,ou=Groups,{ds_suffix}'
        (_, _) = ldap_inst.add_entry(grop_info, group_dn)
        for command in ["getent -s sss passwd newuser",
                        "getent -s sss group newgroup"]:
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, command)
        # Waiting for negative cache to expire - default 15 seconds
        time.sleep(16)
        for command in ["getent -s sss passwd newuser",
                        "getent -s sss group newgroup"]:
            execute_cmd(multihost, command)

    def test_nested_group(self, multihost, backupsssdconf):
        """
        :title: nested group
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. Look for nested group/user
        :expectedresults:
          1. Should succeed
        """
        ldap_uri = 'ldap://%s' % multihost.master[0].sys_hostname
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        for (cn, uid) in [('user1', '111112'), ('user2', '111113')]:
            user_info = {'cn': cn.encode('utf-8'),
                         'homeDirectory': f'/export/{cn}'.encode('utf-8'),
                         'objectClass': [b'account',
                                         b'posixAccount'],
                         'uidNumber': uid.encode('utf-8'),
                         'gidNumber': uid.encode('utf-8'),
                         'uid': cn.encode('utf-8')}
            user_dn = f'uid={cn},ou=Users,{ds_suffix}'
            (_, _) = ldap_inst.add_entry(user_info, user_dn)

        for (cn, uid, memberUid) in [('childgroup', '111113', 'user2'.encode('utf-8')),
                                     ('middlegroup', '111114', 'childgroup'.encode('utf-8')),
                                     ('topgroup', '111115', ['middlegroup'.encode('utf-8'),
                                                             'user1'.encode('utf-8')])]:
            grop_info = {'cn': cn.encode('utf-8'),
                         'objectClass': b'posixGroup',
                         'gidNumber': uid.encode('utf-8'),
                         'memberUid': memberUid}
            group_dn = f'cn={cn},ou=Groups,{ds_suffix}'
            (_, _) = ldap_inst.add_entry(grop_info, group_dn)
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for command in ["id user1 | grep topgroup",
                        "id user2 | grep childgroup",
                        "getent group middlegroup",
                        "getent group topgroup | grep user1",
                        "getent group childgroup | grep user2"]:
            execute_cmd(multihost, command)

    def test_fully_qualified_names(self, multihost, backupsssdconf):
        """
        :title: fully qualified names
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. Look for fully qualified names
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'use_fully_qualified_names': 'true',
                         'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for command in ["getent passwd User_CS1@example1",
                        "getent group User_CS1_grp1@example1",
                        "id User_CS1@example1"]:
            execute_cmd(multihost, command)
        client_hostip = multihost.client[0].ip
        client = pexpect_ssh(client_hostip, "User_CS1@example1", 'Secret123', debug=False)
        try:
            client.login(login_timeout=30, sync_multiplier=5,
                         auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % "User_CS1@example1")
        else:
            client.logout()

    def test_min_id_max_id(self, multihost, backupsssdconf):
        """
        :title: min id max id
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. Tests for min id max id
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'min_id': '111112',
                         'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for command in ["getent passwd User_CS1",
                        "getent group User_CS1_grp1"]:
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, command)
        execute_cmd(multihost, "sed -i '/min_id/d' /etc/sssd/sssd.conf")
        execute_cmd(multihost, 'echo "max_id=111110" >> /etc/sssd/sssd.conf')
        tools.clear_sssd_cache()
        for command in ["getent passwd User_CS1",
                        "getent group User_CS1_grp1"]:
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, command)
        execute_cmd(multihost, "sed -i '/max_id/d' /etc/sssd/sssd.conf")
        execute_cmd(multihost, 'echo "min_id=111110" >> /etc/sssd/sssd.conf')
        execute_cmd(multihost, 'echo "max_id=111112" >> /etc/sssd/sssd.conf')
        tools.clear_sssd_cache()
        for command in ["getent passwd User_CS1",
                        "getent group User_CS1_grp1",
                        "id User_CS1"]:
            execute_cmd(multihost, command)
        execute_cmd(multihost, "sed -i '/min_id/d' /etc/sssd/sssd.conf")
        execute_cmd(multihost, "sed -i '/max_id/d' /etc/sssd/sssd.conf")

    def test_case_sensitive_false_lookup_user_group(self, multihost, backupsssdconf):
        """
        :title: case sensitive is false simple deny users is user cs1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=false, simple deny users is user cs1
        :expectedresults:
          1. Should succeed
        """
        execute_cmd(multihost, 'echo "ignorecase yes" >> /etc/nslcd.conf')
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'case_sensitive': 'false',
                         'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        execute_cmd(multihost, 'systemctl restart nslcd')
        tools.clear_sssd_cache()
        for command in ["getent passwd user_cs1 | grep user_cs1",
                        "getent passwd User_CS1 | grep user_cs1",
                        "getent passwd user_cs1_alias | grep user_cs1",
                        "getent passwd User_CS1_Alias | grep user_cs1",
                        "getent group User_CS1_grp1 | grep user_cs1_grp1",
                        "getent group user_cs1_grp1 | grep user_cs1",
                        "getent group User_CS1_grp1_Alias | grep user_cs1_grp1",
                        "getent group user_cs1_grp1_alias | grep user_cs1",
                        "id User_cs1 | grep user_cs1_grp1",
                        "id user_cs1_Alias | grep user_cs1_grp1"]:
            execute_cmd(multihost, command)
        client_hostip = multihost.client[0].ip
        for user in ['user_cs1', 'user_cs1_alias']:
            client = pexpect_ssh(client_hostip, user, 'Secret123', debug=False)
            try:
                client.login(login_timeout=30, sync_multiplier=5,
                             auto_prompt_reset=False)
            except SSHLoginException:
                pytest.fail("%s failed to login" % user)
            else:
                client.logout()

    def test_case_sensitive_false_deny_users_user_cs1(self, multihost, backupsssdconf):
        """
        :title: case sensitive is false simple deny groups is user cs1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=false, simple deny groups is user cs1
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        client_hostip = multihost.client[0].ip
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'false',
                         'access_provider': 'simple',
                         'simple_deny_users': 'user_cs1'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for user in ['User_cs1', 'user_cs1_alias']:
            execute_cmd(multihost, "> /var/log/secure")
            client = pexpect_ssh(client_hostip, user, 'Secret123', debug=False)
            with pytest.raises(Exception):
                client.login(login_timeout=10, sync_multiplier=1,
                             auto_prompt_reset=False)
            time.sleep(3)
            execute_cmd(multihost, f'cat /var/log/secure | grep "Access denied for user {user}"')
        execute_cmd(multihost, "> /var/log/secure")
        execute_cmd(multihost, "sed -i 's/user_cs1/user_cs1_alias/' /etc/sssd/sssd.conf")
        tools.clear_sssd_cache()
        for user in ['user_cs1', 'user_cs1_alias']:
            client = pexpect_ssh(client_hostip, user, 'Secret123', debug=False)
            try:
                client.login(login_timeout=30, sync_multiplier=5,
                             auto_prompt_reset=False)
            except SSHLoginException:
                pytest.fail("%s failed to login" % user)
            else:
                client.logout()

    def test_case_sensitive_false_deny_groups_user_cs1_grp1(self, multihost, backupsssdconf):
        """
        :title: case sensitive is false simple deny groups grp1
        :id: b35a6a2e-0ce5-11ed-b2dc-845cf3eff344
        :steps:
          1. While case_sensitive=false, simple deny groups grp1
        :expectedresults:
          1. Should succeed
        """
        client_hostip = multihost.client[0].ip
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'false',
                         'access_provider': 'simple',
                         'simple_deny_groups': 'user_cs1_grp1'
                         }
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for user in ['User_cs1', 'user_cs1_alias']:
            execute_cmd(multihost, "> /var/log/secure")
            client = pexpect_ssh(client_hostip, user, 'Secret123', debug=False)
            with pytest.raises(Exception):
                client.login(login_timeout=10, sync_multiplier=1,
                             auto_prompt_reset=False)
            time.sleep(3)
            execute_cmd(multihost, f'cat /var/log/secure | grep "Access denied for user {user}"')
        execute_cmd(multihost, "> /var/log/secure")
        execute_cmd(multihost, "sed -i 's/user_cs1_grp1/user_cs1_grp1_alias/' /etc/sssd/sssd.conf")
        tools.clear_sssd_cache()
        for user in ['user_cs1', 'user_cs1_alias']:
            client = pexpect_ssh(client_hostip, user, 'Secret123', debug=False)
            try:
                client.login(login_timeout=30, sync_multiplier=5,
                             auto_prompt_reset=False)
            except SSHLoginException:
                pytest.fail("%s failed to login" % user)
            else:
                client.logout()
