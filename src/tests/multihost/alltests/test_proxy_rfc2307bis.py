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
from sssd.testlib.common.ssh2_python import check_login_client
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
    user_info = {'cn': 'User_CS2'.encode('utf-8'),
                 'homeDirectory': '/home/User_CS2'.encode('utf-8'),
                 'objectClass': [b'account',
                                 b'posixAccount',
                                 b'extensibleObject'],
                 'uidNumber': '1111112'.encode('utf-8'),
                 'gidNumber': '1111112'.encode('utf-8'),
                 'loginShell': '/bin/bash'.encode('utf-8'),
                 'userPassword': 'Secret123'.encode('utf-8'),
                 'uid': ['User_CS2'.encode('utf-8'),
                         'User_CS2_Alias'.encode('utf-8')]}
    user_dn = f'uid=User_CS2,ou=Users,{ds_suffix}'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)
    group_info = {'cn': ['User_CS2_grp1'.encode('utf-8'),
                         'User_CS2_grp1_Alias'.encode('utf-8')],
                  'objectClass': [b'extensibleObject', b'groupOfNames'],
                  'gidNumber': '1111112'.encode('utf-8'),
                  'member': f'uid=User_CS2,ou=Users,{ds_suffix}'.encode('utf-8')}
    group_dn = f'cn=User_CS2_grp1,ou=Groups,{ds_suffix}'
    (_, _) = ldap_inst.add_entry(group_info, group_dn)
    execute_cmd(multihost, "> /etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'base {ds_suffix}' > "
                           f"/etc/pam_ldap.conf")
    execute_cmd(multihost, "echo 'pam_password md5' >>"
                           " /etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'host {multihost.master[0].ip}' "
                           f">> /etc/pam_ldap.conf")
    execute_cmd(multihost, "echo 'tls_cacertfile "
                           "/etc/openldap/certs/cacert.asc' >>"
                           " /etc/pam_ldap.conf")
    execute_cmd(multihost, "echo 'filter group  "
                           "(objectClass=groupOfNames)'>> "
                           "/etc/nslcd.conf")
    """
        Interaction between nss-pam-ldapd and a feature of pam_usertype.
        pam_usertype might send a lookup for a user called
        'pam_usertype_non_existent:' and nss-pam-ldapd does not like the ':' in
        the username.

        To fix this we need to add following for RHEL9
    """
    if '9' or "Fedora" in execute_cmd(multihost, "cat /etc/redhat-release").stdout_text:
        execute_cmd(multihost, "echo 'validnames /^[a-z0-9._@$()]([a-z0-9._@$()"
                               " \\~-]*[a-z:0-9._@$()~-])?$/i' >> /etc/nslcd.conf")
    execute_cmd(multihost, 'systemctl restart nslcd')

    def del_user_grp():
        """ Restore sssd.conf """
        ldap_inst.del_dn(user_dn)
        ldap_inst.del_dn(group_dn)
        ldap_inst.del_dn(users_dn)
        execute_cmd(multihost, "rm -vf /etc/pam_ldap.conf")

    request.addfinalizer(del_user_grp)


@pytest.mark.usefixtures('setupds',
                         'default_sssd',
                         'sssdproxyldap',
                         'install_nslcd',
                         'ldap_objects_sssd_client')
@pytest.mark.tier1_4
class TestProxyrfc2307bis(object):
    """
    This is test case class for proxy provider suite
    """
    def test_lookup_user_group_netgroup(self, multihost, backupsssdconf):
        """
        :title: case sensitive is true lookup user group
        :id: d0531f56-43e8-11ed-9742-845cf3eff344
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
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'true',
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["id User_CS2 | grep User_CS2_grp1",
                  "id User_CS2_Alias | grep User_CS2_grp1",
                  "getent passwd User_CS2 | grep User_CS2",
                  "getent passwd User_CS2_Alias | grep User_CS2",
                  "getent group User_CS2_grp1 | grep User_CS2_grp1",
                  "getent group User_CS2_grp1 | grep User_CS2",
                  "getent group User_CS2_grp1_Alias | grep User_CS2_grp1",
                  "getent group User_CS2_grp1_Alias | grep User_CS2"]:
            execute_cmd(multihost, i)
        for user in ['User_CS2', 'User_CS2_Alias']:
            check_login_client(multihost, user, 'Secret123')
        for i in ["getent passwd user_cs2",
                  "getent passwd user_cs2_alias",
                  "getent group user_cs2_grp1",
                  "getent group user_cs2_grp1"]:
            with pytest.raises(subprocess.CalledProcessError):
                execute_cmd(multihost, i)

    def test_allow_groups_User_CS2_grp1(self, multihost, backupsssdconf):
        """
        :title: simple allow groups is User CS2 grp1
        :id: d798c644-43e8-11ed-bfd5-845cf3eff344
        :steps:
          1. While case_sensitive = true, allow groups User CS2 grp1
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
                         'simple_allow_groups': 'User_CS2_grp1,User_CS2_grp1_Alias',
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent group User_CS2_grp1", "id User_CS2"]:
            execute_cmd(multihost, i)
        check_login_client(multihost, "User_CS2", 'Secret123')

    def test_allow_groups_user_cs2_grp1(self, multihost, backupsssdconf):
        """
        :title: simple allow groups is user cs2 grp1
        :id: de49b3cc-43e8-11ed-a35c-845cf3eff344
        :caseposneg: negative
        :steps:
          1. While case_sensitive = true, allow groups  user cs2 grp1
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
                         'simple_allow_groups': 'user_cs2_grp1',
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent group User_CS2_grp1",
                  "id User_CS2",
                  "> /var/log/secure"]:
            execute_cmd(multihost, i)
        with pytest.raises(Exception):
            check_login_client(multihost, "User_CS2", 'Secret123')
        time.sleep(3)
        execute_cmd(multihost, 'cat /var/log/secure | grep "Access denied for user User_CS2"')

    def test_allow_groups_User_CS2(self, multihost, backupsssdconf):
        """
        :title: simple allow users is User CS2
        :id: e3cd00ce-43e8-11ed-97b6-845cf3eff344
        :steps:
          1. While case_sensitive = true, allow users User CS2
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
                         'simple_allow_users': "User_CS2,User_CS2_Alias",
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent passwd User_CS2", "id User_CS2"]:
            execute_cmd(multihost, i)
        check_login_client(multihost, "User_CS2", 'Secret123')

    def test_allow_groups_user_cs2(self, multihost, backupsssdconf):
        """
        :title: simple allow users is user cs2
        :id: e9ffc58a-43e8-11ed-8df5-845cf3eff344
        :caseposneg: negative
        :steps:
          1. While case_sensitive = true, allow users user cs2
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
                         'simple_allow_groups': 'user_cs2',
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for i in ["getent group User_CS2_grp1",
                  "id User_CS2",
                  "> /var/log/secure"]:
            execute_cmd(multihost, i)
        with pytest.raises(Exception):
            check_login_client(multihost, "User_CS2", 'Secret123')
        time.sleep(3)
        execute_cmd(multihost, 'cat /var/log/secure | grep "Access denied for user User_CS2"')

    def test_case_sensitive(self, multihost, backupsssdconf):
        """
        :title: case sensitive is false lookup user group
        :id: f0389800-43e8-11ed-af2a-845cf3eff344
        :steps:
          1. While case_sensitive = false, lookup user group
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
                         'case_sensitive': 'false',
                         'simple_allow_users': 'user_cs2',
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        execute_cmd(multihost, 'echo "ignorecase yes" >> /etc/nslcd.conf')
        execute_cmd(multihost, 'systemctl restart nslcd')
        tools.clear_sssd_cache()
        for i in ["getent passwd user_cs2 | grep user_cs2",
                  "getent passwd User_CS2 | grep user_cs2",
                  "getent passwd user_cs2_alias | grep user_cs2",
                  "getent passwd User_CS2_Alias | grep user_cs2",
                  "getent group User_CS2_grp1 | grep user_cs2_grp1",
                  "getent group user_cs2_grp1 | grep user_cs2",
                  "getent group User_CS2_grp1_Alias | grep user_cs2_grp1",
                  "getent group user_cs2_grp1_alias | grep user_cs2",
                  "id User_cs2 | grep user_cs2_grp1",
                  "id user_cs2_Alias | grep user_cs2_grp1"]:
            execute_cmd(multihost, i)
        client_hostip = multihost.client[0].ip
        for user in ['user_cs2', 'user_cs2_alias']:
            check_login_client(multihost, user, 'Secret123')

    def test_simple_deny_users_user_cs2(self, multihost, backupsssdconf):
        """
        :title: case sensitive is false simple deny users is user cs2
        :id: f60de2ee-43e8-11ed-96e6-845cf3eff344
        :steps:
          1. While case_sensitive = false, deny users user cs2
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
                         'simple_deny_users': 'user_cs2',
                         'use_fully_qualified_names': 'False'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for user in ['User_cs2', 'user_cs2_alias']:
            execute_cmd(multihost, "> /var/log/secure")
            with pytest.raises(Exception):
                check_login_client(multihost, user, 'Secret123')
            time.sleep(3)
            execute_cmd(multihost, f'cat /var/log/secure | grep "Access denied for user {user}"')
        execute_cmd(multihost, "> /var/log/secure")
        execute_cmd(multihost, "sed -i 's/user_cs2/user_cs2_alias/' /etc/sssd/sssd.conf")
        tools.clear_sssd_cache()
        for user in ['user_cs2_alias', 'User_cs2']:
            check_login_client(multihost, user, 'Secret123')

    def test_simple_deny_groups_user_cs2_grp1(self, multihost, backupsssdconf):
        """
        :title: case sensitive is false simple deny groups is user cs2 grp1
        :id: fbd57926-43e8-11ed-a640-845cf3eff344
        :steps:
          1. While case_sensitive = false, deny groups user cs2 grp1
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
                         'simple_deny_groups': 'user_cs2_grp1',
                         'use_fully_qualified_names': 'false'}
        tools.sssd_conf('domain/' + domain_name, domain_params)
        tools.clear_sssd_cache()
        for user in ['User_cs2', 'user_cs2_alias']:
            execute_cmd(multihost, "> /var/log/secure")
            with pytest.raises(Exception):
                check_login_client(multihost, user, 'Secret123')
            time.sleep(3)
            execute_cmd(multihost, f'cat /var/log/secure | grep "Access denied for user {user}"')
        execute_cmd(multihost, "> /var/log/secure")
        execute_cmd(multihost, "sed -i 's/user_cs2_grp1/user_cs2_grp1_alias/' /etc/sssd/sssd.conf")
        tools.clear_sssd_cache()
        for user in ['user_cs2_alias', 'User_cs2']:
            check_login_client(multihost, user, 'Secret123')
