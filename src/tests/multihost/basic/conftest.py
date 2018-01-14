from sssd.testlib.common.qe_class import session_multihost, create_testdir
from sssd.testlib.common.libkrb5 import krb5srv
from sssd.testlib.common.utils import sssdTools, PkiTools
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException
from sssd.testlib.common.authconfig import RedHatAuthConfig
from sssd.testlib.common.utils import LdapOperations
import pytest
import ConfigParser
import os
import tempfile
import ldap


def pytest_namespace():
    return {'num_masters': 1,
            'num_ad': 0,
            'num_atomic': 0,
            'num_replicas': 0,
            'num_clients': 0,
            'num_others': 0}


@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    return session_multihost


@pytest.fixture(scope="session")
def config_authconfig(session_multihost, request):
    """ Run authconfig to configure Kerberos and SSSD auth on remote host """
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


@pytest.fixture(scope="session")
def nssdir(session_multihost, request):
    serverList = [session_multihost.master[0].sys_hostname]
    pki_inst = PkiTools()
    try:
        certdb = pki_inst.createselfsignedcerts(serverList)
    except PkiLibException as err:
        return (err.msg, err.rval)
    else:
        return certdb


@pytest.fixture(scope="session")
def setup_ldap(session_multihost, nssdir, request):
    ds_obj = DirSrvWrap(session_multihost.master[0], ssl=True, ssldb=nssdir)
    ds_obj.create_ds_instance('example1', 'dc=example,dc=test')

    def remove_ldap():
        ds_obj.remove_ds_instance('example1')
    request.addfinalizer(remove_ldap)


@pytest.fixture(scope="session")
def setup_kerberos(session_multihost, request):
    tools = sssdTools(session_multihost.master[0])
    tools.config_etckrb5('EXAMPLE.TEST')
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    krb.krb_setup_new()

    def remove_kerberos():
        krb.destroy_krb5server()
    request.addfinalizer(remove_kerberos)


@pytest.fixture(scope='class', autouse=True)
def setup_sssd(session_multihost, request):
    domain_section = 'domain/EXAMPLE.TEST'
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
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
    sssdConfig.set(domain_section, 'ldap_search_base', 'dc=example,dc=test')
    sssdConfig.set(domain_section, 'ldap_tls_cacert', cacert_loc)
    sssdConfig.set(domain_section, 'auth_provider', 'krb5')
    sssdConfig.set(domain_section, 'krb5_server', krb5_server)
    sssdConfig.set(domain_section, 'krb5_kpasswd', krb5_server)
    sssdConfig.set(domain_section, 'krb5_realm', 'EXAMPLE.TEST')
    sssdConfig.set(domain_section, 'debug_level', '9')
    sssdConfig.add_section('nss')
    sssdConfig.set('nss', 'debug_level', '9')
    sssdConfig.add_section('pam')
    sssdConfig.set('pam', 'debug_level', '9')
    sssdConfig.add_section('secrets')
    sssdConfig.set('secrets', 'debug_level', '9')
    sssdConfig.add_section('kcm')
    sssdConfig.set('kcm', 'debug_level', '9')
    temp_fd, temp_file_path = tempfile.mkstemp(suffix='conf', prefix='sssd')
    with open(temp_file_path, "wb") as outfile:
        sssdConfig.write(outfile)
    session_multihost.master[0].transport.put_file(temp_file_path,
                                                   '/etc/sssd/sssd.conf')
    chg_perm = 'chmod 600 /etc/sssd/sssd.conf'
    session_multihost.master[0].run_command(chg_perm)
    os.close(temp_fd)
    try:
        session_multihost.master[0].service_sssd('restart')
    except Exception:
        journalctl_cmd = "journalctl -x -n 50 --no-pager"
        session_multihost.master[0].run_command(journalctl_cmd)
        assert False
    tools = sssdTools(session_multihost.master[0])
    tools.enable_kcm()
    session_multihost.master[0].run_command(['systemctl', 'start', 'sssd-kcm'])

    def stop_sssd():
        session_multihost.master[0].service_sssd('stop')
        session_multihost.master[0].run_command(['systemctl',
                                                 'stop',
                                                 'sssd-kcm'])
        sssd_cache = ['cache_%s.ldb' % ('EXAMPLE.TEST'), 'config.ldb',
                      'sssd.ldb', 'timestamps_%s.ldb' % ('EXAMPLE.TEST')]
        for cache_file in sssd_cache:
            db_file = '/var/lib/sss/db/%s' % (cache_file)
            session_multihost.master[0].run_command(['rm', '-f', db_file])
        secrets_db = '/var/lib/sss/secrets/secrets.ldb'
        session_multihost.master[0].run_command(['rm', '-f', secrets_db])
    request.addfinalizer(stop_sssd)


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
    for i in range(1, 10):
        user_dn = 'uid=foo%d,ou=People,dc=example,dc=test' % i
        add_member = [(ldap.MOD_ADD, 'uniqueMember', user_dn)]
        (ret, _) = ldap_inst.modify_ldap(group_dn, add_member)
        assert ret == 'Success'


@pytest.fixture(scope="session", autouse=True)
def setup_session(request, session_multihost,
                  config_authconfig,
                  setup_ldap,
                  setup_kerberos):
    tp = TestPrep(session_multihost)
    tp.setup()

    def teardown_session():
        tp.teardown()
    request.addfinalizer(teardown_session)


class TestPrep(object):
    def __init__(self, multihost):
        self.multihost = multihost

    def setup(self):
        print("\n............Session Setup...............")
        reqd_packages = '389-ds-base authconfig krb5-server krb5-workstation '\
                        'sssd-kcm openldap-clients'
        install_cmd = 'dnf -y  install %s' % reqd_packages
        self.multihost.master[0].run_command(install_cmd)

    def teardown(self):
        print("\n............Session Ends.................")
