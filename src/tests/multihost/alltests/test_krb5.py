""" Automation of Krb5 tests

:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.exceptions import SSHLoginException


@pytest.mark.usefixtures('setup_sssd_krb', 'create_posix_usersgroups')
@pytest.mark.krb5
class TestKrbWithLogin(object):
    @pytest.mark.tier1
    def test_0001_krb5_not_working_based_on_k5login(self,
                                                    multihost,
                                                    localusers,
                                                    backupsssdconf):
        """
        :title: krb5: access_provider = krb5 is not
         working in RHEL8 while restricting logins
         based on .k5login file
        :id: dfc177ff-58a7-4697-8d23-e444928c7092
        :casecomponent: authselect
        :customerscenario: True
        :requirement: IDM-SSSD-REQ :: Authselect replaced authconfig
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1734094
        """
        multihost.client[0].run_command('authselect select sssd '
                                        'with-files-access-provider')
        multihost.client[0].service_sssd('stop')
        client_tool = sssdTools(multihost.client[0])
        domain_params = {'id_provider': 'files',
                         'access_provider': 'krb5'}
        client_tool.sssd_conf('domain/example1', domain_params)
        dmain_delete = {"ldap_user_home_directory": "/home/%u",
                        "ldap_uri": multihost.master[0].sys_hostname,
                        "ldap_search_base": "dc=example,dc=test",
                        "ldap_tls_cacert": "/etc/openldap/cacerts/cacert.pem",
                        "use_fully_qualified_names": "True"}
        client_tool.sssd_conf('domain/example1', dmain_delete, action='delete')
        multihost.client[0].service_sssd('start')
        user = 'user5000'
        client_hostname = multihost.client[0].sys_hostname
        multihost.client[0].run_command(f'touch /home/{user}/.k5login')
        multihost.client[0].run_command(f'chown {user} /home/{user}/.k5login')
        multihost.client[0].run_command(f'chgrp {user} /home/{user}/.k5login')
        multihost.client[0].run_command(f'chmod 664 /home/{user}/.k5login')
        multihost.client[0].service_sssd('restart')
        client = pexpect_ssh(client_hostname, user, 'Secret123', debug=False)
        with pytest.raises(Exception):
            client.login(login_timeout=10, sync_multiplier=1,
                         auto_prompt_reset=False)
        multihost.client[0].run_command(f'rm -vf /home/{user}/.k5login')
        multihost.client[0].service_sssd('restart')
        client = pexpect_ssh(client_hostname, user, 'Secret123', debug=False)
        try:
            client.login(login_timeout=30, sync_multiplier=5,
                         auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()
        multihost.client[0].run_command('authselect select sssd')

    @pytest.mark.tier1_2
    def test_0002_generating_lot_of(self, multihost, backupsssdconf):
        """
        :title: SSSD is generating lot of LDAP
         queries in a very large environment
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1772513
        :id: 74a60320-e48b-11eb-ba19-845cf3eff344
        :requirement: IDM-SSSD-REQ : LDAP Provider
        :steps:
          1. Start SSSD with any configuration
          2. Call 'getent passwd username@domain'
          3. Check the entry is present in data and timestamp cache
          4. Now stop SSSD and remove the timestamp cache
          5. Start SSSD and call 'sss_cache -E'
          6. Call 'getent passwd username@domain'
          7. Do the ldbsearch checks again
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        multihost.client[0].service_sssd('restart')
        cmd = multihost.client[0].run_command('getent passwd '
                                              'foo1@example1')
        assert 'foo1@example1' in cmd.stdout_text
        multihost.client[0].run_command("yum install -y ldb-tools")
        sssd_client = multihost.client[0]
        cmd_search1 = sssd_client.run_command("ldbsearch "
                                              "-H /var/lib/sss/db/"
                                              "cache_example1.ldb  -b "
                                              "name=foo1@example1,"
                                              "cn=users,cn=example1,"
                                              "cn=sysdb")
        assert 'name=foo1@example1,cn=users,cn=example1,cn=sysdb' \
               in cmd_search1.stdout_text
        cmd_search2 = sssd_client.run_command('ldbsearch -H '
                                              '/var/lib/sss/db/'
                                              'timestamps_example1.ldb '
                                              '-b name=foo1@example1,'
                                              'cn=users,cn=example1,'
                                              'cn=sysdb')
        assert "dn: name=foo1@example1,cn=users,cn=example1,cn=sysdb" in \
               cmd_search2.stdout_text
        multihost.client[0].run_command("rm -vf /var/lib/sss/db/"
                                        "timestamps_example1.ldb")
        multihost.client[0].service_sssd('restart')
        multihost.client[0].run_command("sss_cache -E")
        cmd = multihost.client[0].run_command('getent passwd '
                                              'foo1@example1')
        assert 'foo1@example1' in cmd.stdout_text
        cmd_search1 = multihost.client[0].run_command(
            "ldbsearch -H /var/lib/sss/db/cache_example1.ldb -b "
            "name=foo1@example1,cn=users,cn=example1,cn=sysdb")
        assert 'name=foo1@example1,cn=users,cn=example1,cn=sysdb' in \
               cmd_search1.stdout_text
        cmd_search2 = multihost.client[0].run_command(
            'ldbsearch -H /var/lib/sss/db/timestamps_example1.ldb -b '
            'name=foo1@example1,cn=users,cn=example1,cn=sysdb')
        assert "dn: name=foo1@example1,cn=users,cn=example1,cn=sysdb" \
               in cmd_search2.stdout_text
