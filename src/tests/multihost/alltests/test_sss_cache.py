""" Automation of sss_cache tests
:requirement: :IDM-SSSD-REQ:: sss_cache improvements
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
import ldap
from sssd.testlib.common.utils import sssdTools, LdapOperations


@pytest.mark.usefixtures('setup_sssd_krb', 'create_posix_usersgroups')
@pytest.mark.sss_cache
class TestSssCache(object):
    @pytest.mark.converted('test_sssctl.py', 'test_sssctl__reset_cached_timestamps')
    @pytest.mark.tier1_2
    def test_sss_cache_reset(self, multihost, backupsssdconf):
        """
        :title: fix sss_cache to also reset cached timestamp
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1902280
        :customerscenario: True
        :id: c310f1b4-e89b-11eb-84ce-845cf3eff344
        :steps:
            1. Make a change to group entry in LDAP
            2. Run 'sss_cache -E' on clients
            3. Check with 'getent group' on clients to see if correct\
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_schema': 'rfc2307bis',
                         'ldap_group_member': 'uniquemember',
                         'debug_level': '9'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        multihost.client[0].service_sssd('restart')
        get_ent = multihost.client[0].run_command("getent group "
                                                  "ldapusers@example1")
        assert "foo9@example1" in get_ent.stdout_text
        user_dn = 'uid=foo9,ou=People,dc=example,dc=test'
        group_dn = 'cn=ldapusers,ou=Groups,dc=example,dc=test'
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        del_member = [(ldap.MOD_DELETE, 'uniqueMember',
                       user_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(group_dn, del_member)
        assert ret == 'Success'
        multihost.client[0].run_command("sss_cache -G")
        multihost.client[0].run_command("sss_cache -E")
        get_ent1 = multihost.client[0].run_command("getent group "
                                                   "ldapusers@example1")
        assert "foo9@example1" not in get_ent1.stdout_text
        assert get_ent.stdout_text != get_ent1.stdout_text
