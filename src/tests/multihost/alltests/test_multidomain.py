"""Test cases for Multidomain"""
from __future__ import print_function
import re
import datetime
import pytest
import paramiko
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSHClient


@pytest.mark.usefixtures('posix_users_multidomain', 'sssdproxyldap',
                         'nslcd', 'template_sssdconf')
@pytest.mark.multidomain
class TestMultiDomain(object):

    @pytest.mark.tier2
    def test_0001_proxyldap2(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check config
        ldb filter users per domain for puser10 in proxy domain

        multidomain_sssd(domains='proxy_ldap2')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check config
        ldb filter users per domain for puser10 in ldap domain

        multidomain_sssd(domains='proxy_ldap2')
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

    @pytest.mark.tier2
    def test_0003_proxyldap2(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain:
        checking lookup and authentication for proxy domain with filter_users

        multidomain_sssd(domains='proxy_ldap2')
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
            ssh = SSHClient(multihost.client[0].external_hostname,
                            username=user,
                            password='Secret123')
            assert ssh.connect
            ssh.close()

    @pytest.mark.tier2
    def test_0004_proxyldap2(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain:
        checking lookup and authentication for ldap domain with filter_users

        multidomain_sssd(domains='proxy_ldap2')
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
            ssh = SSHClient(multihost.client[0].external_hostname,
                            username=user,
                            password='Secret123')
            assert ssh.connect
            ssh.close()

    @pytest.mark.tier2
    def test_0005_proxyldap2(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: proxy
        provider is not working with enumerate=true when trying to fetch
        all groups

        multidomain_sssd(domains='proxy_ldap2')
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
    def test_0006_filesproxy(self, multihost, multidomain_sssd):
        """
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: lookup
        and ldbsearch with files and proxy domain

        multidomain_sssd(domains='files_proxy')
        """
        multidomain_sssd(domains='files_proxy')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for idx in range(10):
            user = 'puser%d' % idx
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 0
        for provider in ['files', 'proxy']:
            ldb = 'ldbsearch -H /var/lib/sss/db/config.ldb -b '\
                  'cn=%s,cn=domain,cn=config' % provider
            cmd = multihost.client[0].run_command(ldb, raiseonerr=False)
            if cmd.returncode == 0:
                checks = ['enumerate: True', 'id_provider: %s' % provider,
                          'max_id: [0-5]010', 'min_id: [0-5]000']
                for str1 in checks:
                    find = re.compile(r'%s' % str1)
                    result = find.search(cmd.stdout_text)
                    assert result is not None

    @pytest.mark.tier2
    def test_0007_filesproxy(self, multihost, multidomain_sssd, localusers):
        """
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: lookup for
        localusers with domain files and proxy

        multidomain_sssd(domains='files_proxy')
        """
        multidomain_sssd(domains='files_proxy')
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
    def test_0008_filesproxy(self, multihost, multidomain_sssd, localusers):
        """
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        modify LDAP domain User with domain files and proxy

        multidomain_sssd(domains='files_proxy')
        """
        multidomain_sssd(domains='files_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "usermod: user 'puser1' does not exist in /etc/passwd"
        usermod = 'usermod -g 5000 puser1'
        cmd = multihost.client[0].run_command(usermod, raiseonerr=False)
        assert cmd.returncode != 0
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0009_filesproxy(self, multihost, multidomain_sssd, localusers):
        """
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        delete LDAP domain User with domain files and proxy

        multidomain_sssd(domains='files_proxy')
        """
        multidomain_sssd(domains='files_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "userdel: user 'puser1' does not exist"
        userdel = 'userdel -r puser1'
        cmd = multihost.client[0].run_command(userdel, raiseonerr=False)
        assert cmd.returncode != 0
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0010_filesproxy(self, multihost, multidomain_sssd, localusers):
        """
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        modify group with domain files and proxy

        multidomain_sssd(domains='files_proxy')
        """
        multidomain_sssd(domains='files_proxy')
        multihost.client[0].service_sssd('start')
        err_str = "groupmod: GID '5000' already exists"
        groupmod = 'groupmod -g 5000 pgroup0'
        cmd = multihost.client[0].run_command(groupmod, raiseonerr=False)
        assert cmd.returncode != 0
        print(cmd.stderr_text.strip().split('\n'))
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0011_filesproxy(self, multihost, multidomain_sssd, localusers):
        """
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain:  Attempt to
        delete group with domain files and proxy

        multidomain_sssd(domains='files_proxy')
        """
        multidomain_sssd(domains='files_proxy')
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
        :Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: ldbsearch
        for local and ldap domain

        multidomain_sssd(domains='local_ldap')
        """
        multidomain_sssd(domains='local_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        for idx in range(10):
            user = 'quser%d' % idx
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 0
        for provider in ['files', 'ldap1']:
            ldb = 'ldbsearch -H /var/lib/sss/db/config.ldb -b '\
                  'cn=%s,cn=domain,cn=config' % (provider)
            cmd = multihost.client[0].run_command(ldb, raiseonerr=False)
            if cmd.returncode == 0:
                if provider == 'ldap1':
                    provider = 'ldap'
                checks = ['enumerate: True', 'id_provider: %s' % provider,
                          'max_id: [0-5]010', 'min_id: [0-5]000']
                for str1 in checks:
                    find = re.compile(r'%s' % str1)
                    result = find.search(cmd.stdout_text)
                    assert result is not None

    @pytest.mark.tier2
    def test_0013_filesldap(self, multihost, multidomain_sssd, localusers):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: User and
        group lookup for local and ldap domain

        multidomain_sssd(domains='local_ldap')
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
            l_user = 'getent passwd -s sss %s' % key
            cmd = multihost.client[0].run_command(l_user, raiseonerr=False)
            assert cmd.returncode == 0
            l_group = 'getent group -s sss %s' % key
            cmd = multihost.client[0].run_command(l_group, raiseonerr=False)
            assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_0014_filesldap(self, multihost, multidomain_sssd, localusers):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        modify ldap user with local group id

        multidomain_sssd(domains='local_ldap')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        delete ldap user

        multidomain_sssd(domains='local_ldap')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        modify ldap group

        multidomain_sssd(domains='local_ldap')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Attempt to
        delete ldap domain group

        multidomain_sssd(domains='local_ldap')
        """
        multidomain_sssd(domains='local_ldap')
        multihost.client[0].service_sssd('start')
        err_str = "groupdel: cannot remove the primary group of user 'quser0'"
        groupdel = 'groupdel qgroup0'
        cmd = multihost.client[0].run_command(groupdel, raiseonerr=False)
        assert cmd.returncode != 0
        print(cmd.stderr_text.strip().split('\n'))
        assert err_str in cmd.stderr_text.strip().split('\n')

    @pytest.mark.tier2
    def test_0018_filesfiles(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: sssd fails
        to start with two local domain

        multidomain_sssd(domains='files_files')
        """
        multidomain_sssd(domains='files_files')
        result = multihost.client[0].service_sssd('start')
        print(" result = ", result)

    @pytest.mark.tier2
    def test_0019_ldapldap(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: ldb search
        for users from two ldap domains

        multidomain_sssd(domains='ldap_ldap')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: checking
        users and groups lookup for two ldap domains

        multidomain_sssd(domains='ldap_ldap')
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

    @pytest.mark.tier2
    def test_0021_ldapldap(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: User
        information not updated on login for secondary domains bz678593

        multidomain_sssd(domains='ldap_ldap')
        """
        multidomain_sssd(domains='ldap_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        suffix = ['p', 'q']
        for dom in range(2):
            for idx in range(5):
                user = '%suser%d@ldap%d' % (suffix[dom], idx, dom + 1)
                ssh = SSHClient(multihost.client[0].external_hostname,
                                username=user,
                                password='Secret123')
                assert ssh.connect
                ssh.close()

    @pytest.mark.tier2
    def test_0022_ldapldap(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: User
        information not updated on login for secondary domains bz678593

        multidomain_sssd(domains='ldap_ldap')
        """
        multidomain_sssd(domains='ldap_ldap')
        ret = multihost.client[0].service_sssd('start')
        assert ret == 0
        suffix = ['p', 'q']
        for dom in range(2):
            for idx in range(5):
                user = '%suser%d@ldap%d' % (suffix[dom], idx, dom + 1)
                ssh = SSHClient(multihost.client[0].external_hostname,
                                username=user,
                                password='Secret123')
                assert ssh.connect
                ssh.close()
        pamlogfile = '/var/log/sssd/sssd_pam.log'
        find1 = re.compile(r'\[puser0\@ldap1\]')
        find2 = re.compile(r'\[quser0\@ldap2\]')
        log = multihost.client[0].get_file_contents(pamlogfile).decode('utf-8')
        assert find1.search(log) and find2.search(log)

    @pytest.mark.tier2
    def test_0023_ldapldap(self, multihost, multidomain_sssd):
        """
         @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Login time
        increases strongly while authenticating against a user from second
        domain
        Automation of BZ694905

         multidomain_sssd(domains='ldap_ldap')
         """
        multidomain_sssd(domains='ldap_ldap')
        client_tools = sssdTools(multihost.client[0])
        for idx in range(2):
            params = {'ldap_search_base': 'dc=example%d,dc=test' % idx,
                      'ldap_tls_reqcert': 'demand'}
            domain_section = 'domain/ldap%d' % (idx + 1)
            client_tools.sssd_conf(domain_section, params)
        domains = ['ldap1, ldap2', 'ldap2, ldap1']
        sssd_params = {'reconnection_retries': '3',
                       'sbus_timeout': '30'}
        client_tools.sssd_conf('sssd', sssd_params)
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
                try:
                    ssh = SSHClient(multihost.client[0].external_hostname,
                                    username=user, password='Secret123')
                except paramiko.ssh_exception.AuthenticationException:
                    pytest.fail('%s failed to login' % user)
                else:
                    ssh.close()
                    t2 = datetime.datetime.now()
                    endtime = t2.second
                    print("end time = ", endtime)
                    timer.append(endtime - starttime)
            print(timer)

    @pytest.mark.tier2
    def test_0024_bz1884196(self, multihost, multidomain_sssd):
        """
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check
        lookup of user when enabled option is True in ldap1 domain
        and False in second ldap2 domain

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1884196

        multidomain_sssd(domains='ldap_ldap')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check user
        when domains parameter has single domain but enabled True in both ldap
        domain

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1884196

        multidomain_sssd(domains='ldap_ldap')
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check
        enabled option with snippet file

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1884196

        multidomain_sssd(domains='ldap_ldap')
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
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
        @Title: IDM-SSSD-TC: ldap_provider: test_for_multidomain: Check
        enabled option with snippet file and empty value of domains
        parameter in sssd section

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1884196

        multidomain_sssd(domains='ldap_ldap')
        """
        multidomain_sssd(domains='ldap_ldap')
        tools = sssdTools(multihost.client[0])
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
