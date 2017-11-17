Examples of for testing KCM
===========================


Design
------
* For testing KCM ccache, minimal requirements is to have a kerberos
  server. sssd-testlib provides `libkrb5` module to setup kerberos servier.

* `sssd-testlib` now contains `utils` module which now contains functions to
  enable `sssd-kcm`

* Below are some of the examples of using it in pytest


Example1: Using Single Host to test sssd-kcm
---------------------------------------------
* Create a single host running Directory Server, krb5 server and configure
  client to authenticate to ldap and kerberos server using sssd and enable KCM

  * create a multihost config file mhc.yaml as below::

         root_password: 'redhat'
         domains:
         - name: testrelm.test
           type: sssd
           hosts:
             - name: idm1.example.test
               external_hostname: idm1.example.test
               role: master

  * create a conftest.py to specify namespace hook::

         from sssd.testlib.common.qe_class import session_multihost,
         from sssd.testlib.common.qe_class import create_testdir
         import pytest

         def pytest_namespace():
             return { 'num_masters': 0, 'num_ad':0, 'num_atomic': 0,
             num_replicas': 0, 'num_clients':1, 'num_others': 0}

  * Create fixture to run Authconfig to authenticate to sssd::

         @pytest.fixture(scope="session")
         def config_authconfig(session_multihost, request):
              """ Run authconfig to configure kerberos and
                  sssd auth on remote host
              """
              authconfig = RedHatAuthConfig(session_multihost.master[0])
              session_multihost.master[0].log.info("Take backup of current authconfig")
              authconfig.backup('/root/authconfig_backup')
              krbrealm = 'EXAMPLE.TEST'
              kerberos_server = session_multihost.master[0].sys_hostname
              authconfig.enable("sssd")
              authconfig.enable("sssdauth")
              authconfig.add_parameter("krb5kdc", kerberos_server)
              authconfig.add_parameter("krb5adminserver", kerberos_server)
              authconfig.add_parameter("krb5realm", krbrealm)
              authconfig.execute()

          def restore_authconfig():
             """ Restore authconfig """
             authconfig.restore('/root/authconfig_backup')

          request.addfinalizer(restore_authconfig)


  * Add a fixture to configure Directory Serverr::

        from sssd.testlib.common.libdirsrv import DirSrvWrap
        from sssd.testlib.common.utils import sssdTools, PkiTools
        from sssd.testlib.common.exceptions import PkiLibException

        @pytest.fixture(scope=session)
        def setup_ldap(session_multihost, request):
            serverList = [session_multihost.master[0].sys_hostname]
            pki_inst = PkiTools()
            try:
               certdb = pki_inst.createselfsignedcerts(serverList)
            except PkiLibException as err:
               return (err.msg, err.rval)
            else:
               ds_obj = DirSrvWrap(session_multihost.master[0], ssl=True,
                                   ssldb=certdb)
               ds_obj.create_ds_instance('example1', 'dc=example,dc=test')

             def remove_ldap():
                 ds_obj.remove_ds_instance('example1')
             request.addfinalizer(remove_ldap)

  * Add a fixture to configure kerberos server::

       @pytest.fixture(scope='class')
       def setup_kerberos(session_multihost, request):
           tools = sssdTools(session_multihost.master[0])
           tools.config_etckrb5('EXAMPLE.TEST')
           krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
           krb.krb_setup_new()

           def remove_kerberos():
               krb.destroy_krb5serer()
           request.addfinalizer(remove_kerberos)

  * Add a fixture to setup sssd conf::

       @pytest.fixture(scope='class', autouse=True)
       def setup_sssd(session_multihost, request):
            domain_section = 'domain/EXAMPLE.TEST'
            ldap_uri = 'ldap://%s' %
                       (session_multihost.master[0].sys_hostname)
            krb5_server = session_multihost.master[0].sys_hostname
            cacert_loc = '/etc/openldap/cacerts/cacert.pem'
            sssdConfig = ConfigParser.SafeConfigParser()
            sssdConfig.optionxform = str
            sssdConfig.add_section('sssd')
            sssdConfig.set('sssd', 'domains', 'EXAMPLE.TEST')
            sssdConfig.set('sssd', 'config_file_version', '2')
            sssdConfig.set('sssd', 'services', 'nss, pam, ifp')
            sssdConfig.add_section(domain_section)
            sssdConfig.set(domain_section, 'enumerate', 'false')
            sssdConfig.set(domain_section, 'id_provider', 'ldap')
            sssdConfig.set(domain_section, 'ldap_uri', ldap_uri)
            sssdConfig.set(domain_section, 'ldap_search_base',
                           'dc=example,dc=test')
            sssdConfig.set(domain_section, 'ldap_tls_cacert', cacert_loc)
            sssdConfig.set(domain_section, 'auth_provider', 'krb5')
            sssdConfig.set(domain_section, 'krb5_server', krb5_server)
            sssdConfig.set(domain_section, 'krb5_kpasswd', krb5_server)
            sssdConfig.set(domain_section, 'krb5_realm', 'EXAMPLE.TEST')
            sssdConfig.set(domain_section, 'debug_level', '9')
            temp_fd, temp_file_path = tempfile.mkstemp(suffix='conf',
                                                       prefix='sssd')
            with open(temp_file_path, "wb") as outfile:
                 sssdConfig.write(outfile)
            session_multihost.master[0].run_command(['cp', '-f',
                                                    paths.SSSD_CONF,
                                                    '%s.orig' %
                                                    paths.SSSD_CONF])
            session_multihost.master[0].transport.put_file(temp_file_path,
                                                           paths.SSSD_CONF)

            os.close(temp_fd)
            try:
               session_multihost.master[0].service_sssd('restart')
            except Exception:
               journalctl_cmd = "journalctl -x -n 50 --no-pager"
               session_multihost.master[0].run_command(journalctl_cmd)
               assert False


  * Add fixture to create some posix users and also create kerberos users with
    same names::

            @pytest.fixture(scope='class', autouse=True)
            def create_posix_usersgroups(session_multihost):
                ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
                ds_rootdn = 'cn=Directory Manager'
                ds_rootpw = 'Secret123'
                ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
                krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
                for i in range(10):
                     user_info = {'cn': 'foo%d' % i,
                                  'uid': 'foo%d' % i,
                                  'uidNumber': '1458310%d' % i,
                                  'gidNumber': '14564100'}
               if ldap_inst.posix_user("ou=People", "dc=example,dc=test", user_info):
                   krb.add_principal('foo%d' % i, 'user', 'Secret123')
               else:
                   print("Unable to add ldap User %s" % (user_info))
                   assert False
               memberdn = 'uid=%s,ou=People,dc=example,dc=test' % ('foo0')
               group_info = {'cn': 'ldapusers',
                             'gidNumber': '14564100',
                             'uniqueMember': memberdn}
               try:
                  ldap_inst.posix_group("ou=Groups", "dc=example,dc=test", group_info)
               except Exception:
                  assert False
               group_dn = 'cn=ldapusers,ou=Groups,dc=example,dc=test'
               for i in range(1, 11):
                   user_dn = 'uid=foo%d,ou=People,dc=example,dc=test' % i
                   add_member = [(ldap.MOD_ADD, 'uniqueMember',user_dn)]
                   (ret, return_value) = ldap_inst.modify_ldap(group_dn, add_member)
                   assert ret == 'Success'

  * Create a session fixture which calls config_authconfig, setup_ldap,
    setup_kerber, fixture::

       @pytest.fixture(scope="session", autouse=True)
       def setup_session(request, session_multihost,
                         config_authconfig,
                         setup_ldap,
                         setup_kerberos):
           print("\n............Session Setup...............")
           def teardown():
               print("\n............Session teardown...............")
            request.addfinalizer(teardown)


  * Create a test suite file called test1.py, To test kcm as user, or
    to check if the kerbeors user can ssh to the system, we can use
    `SSHClient` module from `sssd.testlib.common.utils` module::

        from sssd.testlib.common.utils import SSHClient
        from sssd.testlib.common.uilts import sssdTools

        class TestBasicSSSD:

            def test_kcm_sock(self, mulithost):
                tools = sssdTools(session_multihost.master[0])
                tools.enable_kcm()
                multihost.master[0].run_command(['systemctl', 'start',
                                                 'sssd-kcm'])
                kcm_sock_link = '/var/run/.heim_org.h5l.kcm-socket'
                cmd = multihost.master[0].run_command(['ls', '-l', kcm_sock_link],
                                                      raiseonerr=False)
                assert cmd.returncode == 0

            def test_ssh_user_login(self, multihost):
               """ Check ssh login as ldap user with kerberos credentials """
               ssh = SSHClient(multihost.master[0].sys_hostname,
                               username='foo1', password='Secret123')
               assert ssh.connstatus
               ssh.close()

            def test_kinit(self, multihost):
               """ Run kinit after user login """
               ssh = SSHClient(multihost.master[0].sys_hostname,
                               username='foo2', password='Secret123')
               assert ssh.connstatus
               (stdout, stderr, exit_status) = ssh.execute_cmd(args='kinit',
                                                               stdin='Secret123')
               assert exit_status == 0
               (stdout, stderr, exit_status) = ssh.execute_cmd('klist')
               for line in stdout.readlines():
                   print(line)
               assert exit_status == 0
               ssh.close()

            def test_kinit_kcm(self, multihost):
               """ Run kinit with KRB5CCNAME=KCM: """
               ssh = SSHClient(multihost.master[0].sys_hostname,
                     username='foo3', password='Secret123')
               assert ssh.connstatus
               (out, err, status) = ssh.execute_cmd('KRB5CCNAME=KCM:; kinit',
                                                    stdin='Secret123')
               assert status == 0
               (out, err, status) = ssh.execute_cmd('KRB5CCNAME=KCM:; klist')
               for line in stdout.readlines():
                    if 'Ticket cache: KCM:14583103' in str(line.strip()):
                        assert True
                        break
                    else:
                        assert False
               assert exit_status == 0
               ssh.close()



