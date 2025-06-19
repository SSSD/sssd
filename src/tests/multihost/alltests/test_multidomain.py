"""Test cases for Multidomain

:requirement: multiple_domains
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import re
import datetime
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client


@pytest.mark.usefixtures('posix_users_multidomain', 'sssdproxyldap',
                         'nslcd', 'template_sssdconf')
@pytest.mark.multidomain
class TestMultiDomain(object):
    @staticmethod
    @pytest.mark.ticket(jira="RHEL-87352")
    @pytest.mark.tier2
    def test_ldap_referrals(multihost, multidomain_sssd):
        """
        :title: Ldap referrals feature of two ldap server with
            sssd option True and False.
        :id: ad937dc4-2fbc-11ee-97b0-845cf3eff344
        :setup:
            1. Set 'proxy_ldap2' domain in the SSSD configuration.
            2. The SSSD service is started on the client.
        :steps:
          1. Get the id of 'puser19'.
          2. Set sssd domain to ldap2.
          3. Try to get puser19 which only present master1 server.
          4. Set nsslapd-referral for master2 server.
          5. Set ldap_search_base for ldap2 domain matching with
            ldap_search_base of master1.
          6. Get the id of 'puser19'.
          7. Set 'ldap_referrals': False for ldap2 domain.
          8. Get the id of 'puser19'.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should not succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
          8. Should not succeed
        """
        multidomain_sssd(domains='proxy_ldap2')
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('start')
        multihost.client[0].run_command("id puser19")
        client = sssdTools(multihost.client[0])
        domain_params = {'domains': 'ldap2'}
        client.sssd_conf('sssd', domain_params)
        multihost.client[0].service_sssd('restart')
        cmd0 = multihost.client[0].run_command("id puser19", raiseonerr=False)
        multihost.master[1].run_command(f'dsconf'
                                        f' -D "cn=Directory Manager"'
                                        f' -w Secret123 ldap://{multihost.master[1].sys_hostname} '
                                        f'config replace nsslapd-referral='
                                        f'"ldap://{multihost.master[0].sys_hostname}/"')
        params = {'ldap_search_base': 'dc=example0,dc=test',
                  'ldap_referrals': True}
        tools.sssd_conf('domain/ldap2', params)
        multihost.client[0].service_sssd('restart')
        cmd1 = multihost.client[0].run_command("id puser19")
        params = {'ldap_referrals': False}
        tools.sssd_conf('domain/ldap2', params)
        tools.clear_sssd_cache()
        cmd2 = multihost.client[0].run_command("id puser19", raiseonerr=False)
        multihost.master[1].run_command(f'dsconf -D '
                                        f'"cn=Directory Manager" -w Secret123 ldap://{multihost.master[1].sys_hostname} '
                                        f'config replace nsslapd-referral=""')
        assert cmd0.returncode != 0
        assert cmd2.returncode != 0
        assert cmd1

    @pytest.mark.tier2
    def test_0001_proxyldap2(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check config
         ldb filter users per domain for puser10 in proxy domain
        :id: aeed42e2-5b9b-4b04-b5f2-ea832250c38e
        """
        multidomain_sssd(domains='proxy_ldap2')
        tools = sssdTools(multihost.client[0])
        proxy_params = {'filter_users': 'puser10'}
        tools.sssd_conf('domain/proxy', proxy_params)
        multihost.client[0].service_sssd('start')
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/config.ldb '\
                  '-b cn=proxy,cn=domain,cn=config'
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        if cmd.returncode == 0:
            find = re.compile(r'filter_users:\spuser10.*')
            if not find.search(cmd.stdout_text):
                pytest.fail('puser10 user not found in cache')

    @pytest.mark.tier2
    def test_0002_proxyldap2(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check config
         ldb filter users per domain for puser10 in ldap domain
        :id: 847490b5-0687-4443-bbf5-96c5a7dd2c9f
        """
        multidomain_sssd(domains='proxy_ldap2')
        tools = sssdTools(multihost.client[0])
        ldap_params = {'filter_users': 'puser10'}
        tools.sssd_conf('domain/ldap1', ldap_params)
        multihost.client[0].service_sssd('start')
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/config.ldb '\
                  '-b cn=ldap1,cn=domain,cn=config'
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        if cmd.returncode == 0:
            find = re.compile(r'filter_users:\spuser10.*')
            if not find.search(cmd.stdout_text):
                pytest.fail('puser10 user not found in cache')

    @staticmethod
    @pytest.mark.tier2
    def test_0003_proxyldap2(multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain:
         checking lookup and authentication for proxy domain with filter_users
        :id: fb7d6f18-1c47-48f6-852f-824850b9f2d2
        """
        multidomain_sssd(domains='proxy_ldap2')
        tools = sssdTools(multihost.client[0])
        proxy_params = {'filter_users': 'puser10',
                        'use_fully_qualified_names': 'True'}
        tools.sssd_conf('domain/proxy', proxy_params)
        multihost.client[0].service_sssd('start')
        users = ['puser10', 'puser10@proxy', 'puser11@proxy', 'quser10']
        for user in users:
            cmd = 'getent passwd %s' % user
            getent = multihost.client[0].run_command(cmd, raiseonerr=False)
            if 'puser10' in user:
                assert getent.returncode == 2
            else:
                assert getent.returncode == 0
        for user in ['puser11@proxy', 'quser10']:
            check_login_client(multihost, user, 'Secret123')

    @staticmethod
    @pytest.mark.tier2
    def test_0004_proxyldap2(multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain:
         checking lookup and authentication for ldap domain with filter_users
        :id: 7aa98ea5-1790-4407-b897-a15e8ebcf775
        """
        multidomain_sssd(domains='proxy_ldap2')
        tools = sssdTools(multihost.client[0])
        ldap_params = {'filter_users': 'quser10',
                       'use_fully_qualified_names': 'True'}
        tools.sssd_conf('domain/ldap2', ldap_params)
        multihost.client[0].service_sssd('start')
        users = ['quser10', 'quser10@ldap2', 'quser11@ldap2', 'puser11']
        for user in users:
            cmd = 'getent passwd %s' % user
            getent = multihost.client[0].run_command(cmd, raiseonerr=False)
            if 'quser10' in user:
                assert getent.returncode == 2
            else:
                assert getent.returncode == 0
        for user in ['puser11', 'quser11@ldap2']:
            check_login_client(multihost, user, 'Secret123')

    @pytest.mark.tier2
    def test_0005_proxyldap2(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: proxy
         provider is not working with enumerate=true when trying to fetch
         all groups
        :id: d6e5958d-e719-4aab-b4a4-705f97191dfe
        """
        # Automation of BZ1665867
        multidomain_sssd(domains='proxy_ldap2')
        tools = sssdTools(multihost.client[0])
        timer = []
        for _ in range(5):
            multihost.client[0].service_sssd('stop')
            tools.remove_sss_cache('/var/lib/sss/db')
            multihost.client[0].service_sssd('start')
            t1 = datetime.datetime.now()
            starttime = t1.second
            grp_lk = 'getent group'
            multihost.client[0].run_command(grp_lk, raiseonerr=False)
            t2 = datetime.datetime.now()
            endtime = t2.second
            timer.append(endtime - starttime)
        print(timer)

    @pytest.mark.tier2
    def test_0006_filesproxy_ldapproxy(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: lookup
         and ldbsearch with filesproxy and ldapproxy domain
        :id: 01b34e45-d291-41f3-b54b-3364ce63e079
        """
        multidomain_sssd(domains='local_proxy')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for idx in range(10):
            user = 'puser%d' % idx
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 0
        provider = 'proxy'
        ldb = f'ldbsearch -H /var/lib/sss/db/config.ldb -b ' \
              f'cn={provider},cn=domain,cn=config'
        cmd = multihost.client[0].run_command(ldb, raiseonerr=False)
        if cmd.returncode == 0:
            checks = ['enumerate: True', f'id_provider: {provider}',
                      'max_id: [0-5]010', 'min_id: [0-5]000']
            for str1 in checks:
                find = re.compile(str1)
                result = find.search(cmd.stdout_text)
                assert result is not None

    @pytest.mark.tier2
    def test_0007_filesproxy_ldapproxy(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: lookup for
         localusers with domain filesproxy and ldapproxy
        :id: 33cd81a6-26a1-4235-8ef7-ebb52f6b6db2
        """
        multidomain_sssd(domains='local_proxy')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for idx in range(10):
            user = 'puser%d' % idx
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 0
        users = localusers
        for key, _ in users.items():
            l_user = 'getent passwd -s sss %s' % key
            cmd = multihost.client[0].run_command(l_user, raiseonerr=False)
            assert cmd.returncode == 0
            l_group = 'getent group -s sss %s' % key
            cmd = multihost.client[0].run_command(l_group, raiseonerr=False)
            assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_0008_filesproxy_ldapproxy(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         modify LDAP domain User with domain filesproxy and ldapproxy
        :id: ecabce85-b620-45b9-a08a-d975952766a5
        """
        multidomain_sssd(domains='local_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "usermod: user 'puser1' does not exist in /etc/passwd"
        usermod = 'usermod -g 5000 puser1'
        cmd = multihost.client[0].run_command(usermod, raiseonerr=False)
        assert cmd.returncode != 0
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0009_filesproxy_ldapproxy(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         delete LDAP domain User with domain filesproxy and ldapproxy
        :id: 327f75fc-d4f8-4d51-b140-117edf5f55eb
        """
        multidomain_sssd(domains='local_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "userdel: user 'puser1' does not exist"
        userdel = 'userdel -r puser1'
        cmd = multihost.client[0].run_command(userdel, raiseonerr=False)
        assert cmd.returncode != 0
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0010_filesproxy_ldapproxy(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         modify group with domain filesproxy and ldapproxy
        :id: 662aaa9b-de83-4e43-8c9f-b8910e96644e
        """
        multidomain_sssd(domains='local_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "groupmod: GID '5000' already exists"
        groupmod = 'groupmod -g 5000 pgroup0'
        cmd = multihost.client[0].run_command(groupmod, raiseonerr=False)
        assert cmd.returncode != 0
        print(cmd.stderr_text.strip().split('\n'))
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0011_filesproxy_ldapproxy(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain:  Attempt to
         delete group with domain filesproxy and ldapproxy
        :id: 28ecf278-b5bd-4d87-a63e-051010e55c5e
        """
        multidomain_sssd(domains='local_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "groupdel: cannot remove the primary group of user 'puser0'"
        groupdel = 'groupdel pgroup0'
        cmd = multihost.client[0].run_command(groupdel, raiseonerr=False)
        assert cmd.returncode != 0
        print(cmd.stderr_text.strip().split('\n'))
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0012_filesldap(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: ldbsearch
         for local and ldap domain
        :id: bfb68697-9365-49ed-b277-1fef5cf0569b
        """
        multidomain_sssd(domains='local_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for idx in range(10):
            user = 'quser%d' % idx
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 0
        provider = 'ldap1'
        ldb = f'ldbsearch -H /var/lib/sss/db/config.ldb -b cn={provider},cn=domain,cn=config'
        cmd = multihost.client[0].run_command(ldb, raiseonerr=False)
        if cmd.returncode == 0:
            if provider == 'ldap1':
                provider = 'ldap'
            checks = ['enumerate: True', f'id_provider: {provider}',
                      'max_id: [0-5]010', 'min_id: [0-5]000']
            for str1 in checks:
                find = re.compile(str1)
                result = find.search(cmd.stdout_text)
                assert result is not None

    @pytest.mark.tier2
    def test_0013_proxyldap(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: User and
         group lookup for local and ldap domain
        :id: 50cc738c-d522-426f-a2cb-6e2ee37db86b
        """
        multidomain_sssd(domains='local_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for idx in range(10):
            user = 'quser%d' % idx
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 0
        users = localusers
        for key, _ in users.items():
            l_user = f'getent passwd {key}'
            cmd = multihost.client[0].run_command(l_user, raiseonerr=False)
            assert cmd.returncode == 0
            l_group = f'getent group {key}'
            cmd = multihost.client[0].run_command(l_group, raiseonerr=False)
            assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_0014_filesldap(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         modify ldap user with local group id
        :id: 399362ee-ad63-4679-9409-6b15db3b6f63
        """
        multidomain_sssd(domains='local_ldap')
        multihost.client[0].service_sssd('start')
        err_str = "usermod: user 'quser1@ldap1' does not exist in /etc/passwd"
        usermod = 'usermod -g 5000 quser1@ldap1'
        cmd = multihost.client[0].run_command(usermod, raiseonerr=False)
        assert cmd.returncode != 0
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0015_filesldap(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         delete ldap user
        :id: 51db041b-880d-4b4b-a68c-fec92cdee291
        """
        multidomain_sssd(domains='local_ldap')
        multihost.client[0].service_sssd('start')
        err_str = "userdel: user 'quser1@ldap1' does not exist"
        userdel = 'userdel -r quser1@ldap1'
        cmd = multihost.client[0].run_command(userdel, raiseonerr=False)
        assert cmd.returncode != 0
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0016_filesldap(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         modify ldap group
        :id: cc3242cf-876e-4f58-bcd1-1532551bedf2
        """
        multidomain_sssd(domains='local_ldap')
        multihost.client[0].service_sssd('start')
        err_str = "groupmod: GID '5000' already exists"
        groupmod = 'groupmod -g 5000 qgroup0@ldap1'
        cmd = multihost.client[0].run_command(groupmod, raiseonerr=False)
        assert cmd.returncode != 0
        print(cmd.stderr_text.strip().split('\n'))
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0017_filesldap(self, multihost, multidomain_sssd, localusers):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
         delete ldap domain group
        :id: 1a7a5a67-13a9-48d7-bf67-29238d5056fd
        """
        multidomain_sssd(domains='local_ldap')
        multihost.client[0].service_sssd('start')
        err_str1 = "groupdel: cannot remove entry 'qgroup0' from /etc/group"
        err_str2 = "groupdel: cannot remove the primary group of user 'quser0'"
        groupdel = 'groupdel qgroup0'
        cmd = multihost.client[0].run_command(groupdel, raiseonerr=False)
        assert cmd.returncode != 0
        print(cmd.stderr_text.strip().split('\n'))
        err_list = cmd.stderr_text.strip().split('\n')
        assert err_str1 in err_list or err_str2 in err_list

    @pytest.mark.tier2
    def test_0019_ldapldap(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: ldb search
         for users from two ldap domains
        :id: d00b674b-1f5a-4c72-ab5e-fe091a12c42c
        """
        multidomain_sssd(domains='ldap_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for provider in ['ldap1', 'ldap2']:
            ldb = 'ldbsearch -H /var/lib/sss/db/config.ldb -b '\
                  'cn=%s,cn=domain,cn=config' % (provider)
            cmd = multihost.client[0].run_command(ldb, raiseonerr=False)
            if cmd.returncode == 0:
                if 'ldap' in provider:
                    provider = 'ldap'
                checks = ['enumerate: True', 'id_provider: %s' % provider,
                          'max_id: [0-5]020', 'min_uid: [0-5]000',
                          'cache_credentials: False',
                          'use_fully_qualified_names: True']
                for str1 in checks:
                    find = re.compile(r'%s' % str1)
                    result = find.search(cmd.stdout_text)
                    assert result is not None

    @pytest.mark.tier2
    def test_0020_ldapldap(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: checking
         users and groups lookup for two ldap domains
        :id: db99d818-ca66-45df-9b3e-2167cc50fab7
        """
        multidomain_sssd(domains='ldap_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        suffix = ['p', 'q']
        for dom in range(2):
            for idx in range(20):
                user = '%suser%d@ldap%d' % (suffix[dom], idx, dom + 1)
                group = '%sgroup%d@ldap%d' % (suffix[dom], idx, dom + 1)
                lookup_u = 'getent passwd -s sss %s' % user
                lookup_g = 'getent group -s sss %s' % group
                cmd = multihost.client[0].run_command(lookup_u)
                assert cmd.returncode == 0
                cmd = multihost.client[0].run_command(lookup_g)
                assert cmd.returncode == 0

    @staticmethod
    @pytest.mark.tier2
    def test_0022_ldapldap(multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: User
         information not updated on login for secondary domains bz678593
        :id: df54756c-b141-4127-8e51-75ead63df10c
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        suffix = ['p', 'q']
        for dom in range(2):
            for idx in range(5):
                user = '%suser%d@ldap%d' % (suffix[dom], idx, dom + 1)
                check_login_client(multihost, user, 'Secret123')
        pamlogfile = '/var/log/sssd/sssd_pam.log'
        find1 = re.compile(r'\[puser0\@ldap1\]')
        find2 = re.compile(r'\[quser0\@ldap2\]')
        log = multihost.client[0].get_file_contents(pamlogfile).decode('utf-8')
        assert find1.search(log) and find2.search(log)

    @staticmethod
    @pytest.mark.tier2
    def test_0023_ldapldap(multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Login time
         increases strongly while authenticating against a user from second
         domain
        :id: 29bdabfd-49ca-4040-a08d-b2b6adbde2cd
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=694905
         """
        multidomain_sssd(domains='ldap_ldap')
        client_tools = sssdTools(multihost.client[0])
        for idx in range(2):
            params = {'ldap_search_base': 'dc=example%d,dc=test' % idx,
                      'ldap_tls_reqcert': 'demand'}
            domain_section = 'domain/ldap%d' % (idx + 1)
            client_tools.sssd_conf(domain_section, params)
        domains = ['ldap1, ldap2', 'ldap2, ldap1']
        for domain in domains:
            sssd_params = {'domains': domain}
            client_tools.sssd_conf('sssd', sssd_params)
            multihost.client[0].service_sssd('stop')
            client_tools.remove_sss_cache('/var/lib/sss/db')
            ret = multihost.client[0].service_sssd('start')
            assert ret == 0
            suffix = ['p', 'q']
            timer = []
            for dom in range(2):
                t1 = datetime.datetime.now()
                starttime = t1.second
                print("start time = ", starttime)
                user = '%suser1@ldap%d' % (suffix[dom], dom + 1)
                print("user =", user)
                check_login_client(multihost, user, 'Secret123')
                t2 = datetime.datetime.now()
                endtime = t2.second
                print("end time = ", endtime)
                timer.append(endtime - starttime)
            print(timer)

    @pytest.mark.tier2
    def test_0024_bz1884196(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check
         lookup of user when enabled option is True in ldap1 domain
         and False in second ldap2 domain
        :id: a7ce3941-ba2c-407a-bed0-468aaab51fdb
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1884196
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
        ldap_params1 = {'enabled': 'True'}
        tools.sssd_conf('domain/ldap1', ldap_params1)
        ldap_params2 = {'enabled': 'False'}
        tools.sssd_conf('domain/ldap2', ldap_params2)
        tools.clear_sssd_cache()
        multihost.client[0].service_sssd('restart')
        for idx in range(10):
            user1 = 'puser%d@ldap%d' % (idx, 1)
            lookup_u1 = 'getent passwd %s' % user1
            cmd1 = multihost.client[0].run_command(lookup_u1)
            if cmd1.returncode == 0:
                status = 'PASS'
            else:
                status = 'FAIL'
        for idm in range(10):
            user2 = 'quser%d@ldap%d' % (idm, 2)
            try:
                lookup_u2 = 'getent passwd %s' % user2
                cmd2 = multihost.client[0].run_command(lookup_u2)
                print(cmd2.returncode)
                cmd2.returncode == 0
                status = 'FAIL'
            except Exception:
                status = 'PASS'
        assert status == 'PASS'

    @pytest.mark.tier2
    def test_0025_bz1884196(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check user
         when domains parameter has single domain but enabled True in both ldap
         domain
        :id: 33b9c044-3eef-472b-b9f9-d5de9f718c94
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1884196
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
        domain_params = {'domains': 'ldap1'}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf('sssd', domain_params, action='update')
        ldap_params1 = {'enabled': 'True'}
        tools.sssd_conf('domain/ldap1', ldap_params1)
        ldap_params2 = {'enabled': 'True'}
        tools.sssd_conf('domain/ldap2', ldap_params2)
        tools.clear_sssd_cache()
        multihost.client[0].service_sssd('restart')
        suffix = ['p', 'q']
        for domain in range(2):
            for idx in range(10):
                user1 = '%suser%d@ldap%d' % (suffix[domain], idx, domain + 1)
                lookup_u1 = 'getent passwd %s' % user1
                cmd1 = multihost.client[0].run_command(lookup_u1)
                if cmd1.returncode == 0:
                    status = 'PASS'
                else:
                    status = 'FAIL'
        assert status == 'PASS'

    @pytest.mark.tier2
    def test_0026_bz1884196(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check
         enabled option with snippet file
        :id: 6fd1e9af-4039-49a1-bf4b-9925b042add5
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1884196
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
        domain_params = {'enable_files_domain': 'true'}
        tools.sssd_conf('sssd', domain_params, action='update')
        domain_params = {'domains': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf('sssd', domain_params, action='update')
        ldap_params1 = {'enabled': 'True'}
        tools.sssd_conf('domain/ldap1', ldap_params1)
        ldap_params2 = {'enabled': 'False'}
        tools.sssd_conf('domain/ldap2', ldap_params2)
        file_content = "[domain/ldap2]\nenabled = True"
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, file_content)
        cmd_chmod = 'chmod 600 %s' % snippet_file
        multihost.client[0].run_command(cmd_chmod, raiseonerr=False)
        tools.clear_sssd_cache()
        multihost.client[0].service_sssd('restart')
        suffix = ['p', 'q']
        for domain in range(2):
            for idx in range(10):
                user1 = '%suser%d@ldap%d' % (suffix[domain], idx, domain + 1)
                lookup_u1 = 'getent passwd %s' % user1
                cmd1 = multihost.client[0].run_command(lookup_u1)
                if cmd1.returncode == 0:
                    status = 'PASS'
                else:
                    status = 'FAIL'
        delete_snip = 'rm -f /etc/sssd/conf.d/01_snippet.conf'
        multihost.client[0].run_command(delete_snip, raiseonerr=False)
        assert status == 'PASS'

    @pytest.mark.tier2
    def test_0027_bz1884196(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check
         enabled option with snippet file and empty value of domains
         parameter in sssd section
        :id: bf65b8c7-f3ab-4ac1-a9a4-ad3377625a39
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1884196
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
        domain_params = {'enable_files_domain': 'true'}
        tools.sssd_conf('sssd', domain_params, action='update')
        domain_params = {'domains': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf('sssd', domain_params, action='update')
        ldap_params1 = {'enabled': 'True'}
        tools.sssd_conf('domain/ldap1', ldap_params1)
        file_content = "[domain/ldap2]\nenabled = True"
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, file_content)
        cmd_chmod = 'chmod 600 %s' % snippet_file
        multihost.client[0].run_command(cmd_chmod, raiseonerr=False)
        tools.clear_sssd_cache()
        multihost.client[0].service_sssd('restart')
        suffix = ['p', 'q']
        for domain in range(2):
            for idx in range(10):
                user1 = '%suser%d@ldap%d' % (suffix[domain], idx, domain + 1)
                lookup_u1 = 'getent passwd %s' % user1
                cmd1 = multihost.client[0].run_command(lookup_u1)
                if cmd1.returncode == 0:
                    status = 'PASS'
                else:
                    status = 'FAIL'
        delete_snip = 'rm -f /etc/sssd/conf.d/01_snippet.conf'
        multihost.client[0].run_command(delete_snip, raiseonerr=False)
        assert status == 'PASS'
