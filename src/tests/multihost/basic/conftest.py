from sssd.testlib.common.qe_class import session_multihost, create_testdir
from sssd.testlib.common.libkrb5 import krb5srv
from sssd.testlib.common.utils import sssdTools, PkiTools
from sssd.testlib.common.utils import LdapOperations
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException
from sssd.testlib.common.exceptions import LdapException
from sssd.testlib.common.exceptions import LdapException
from sssd.testlib.common.exceptions import SSSDException
import pytest
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
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
def multihost(session_multihost):
    """ multihost fixture """
    return session_multihost


@pytest.fixture(scope="session")
def package_install(session_multihost):
    """ Install required packages """
    distro = session_multihost.master[0].distro
    pkg_list = 'authselect nss-tools 389-ds-base krb5-server '\
               'openldap-clients krb5-workstation '\
               '389-ds-base-legacy-tools sssd sssd-dbus sssd-kcm'
    if 'Fedora' in distro:
        cmd = 'dnf install -y %s' % (pkg_list)
    elif '8.' in distro.split()[5]:
        cmd = 'dnf module -y install 389-ds:1.4'
    session_multihost.master[0].run_command(cmd)


@pytest.fixture(scope="session")
def run_authselect(session_multihost):
    """ Run authconfig to configure Kerberos and SSSD auth on remote host """
    authselect_cmd = 'authselect select sssd --force'
    session_multihost.master[0].run_command(authselect_cmd)


@pytest.fixture(scope="session")
def nssdir(session_multihost):
    """ Setup Self signed CA """
    server_list = [session_multihost.master[0].sys_hostname]
    pki_inst = PkiTools()
    try:
        certdb = pki_inst.createselfsignedcerts(server_list)
    except PkiLibException as err:
        return (err.msg, err.rval)
    else:
        return certdb


@pytest.fixture(scope="session")
def setup_ldap(session_multihost, nssdir, request):
    """ Setup Directory Server """
    ds_obj = DirSrvWrap(session_multihost.master[0], ssl=True, ssldb=nssdir)
    ds_obj.create_ds_instance('example1', 'dc=example,dc=test')

    def remove_ldap():
        """ Remove ldap server instance """
        ds_obj.remove_ds_instance('example1')
    request.addfinalizer(remove_ldap)


@pytest.fixture(scope="session")
def setup_kerberos(session_multihost, request):
    """ Setup kerberos """
    tools = sssdTools(session_multihost.master[0])
    tools.config_etckrb5('EXAMPLE.TEST')
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    krb.krb_setup_new()

    def remove_kerberos():
        """ Remove kerberos instance """
        krb.destroy_krb5server()
    request.addfinalizer(remove_kerberos)


@pytest.fixture(scope='class', autouse=True)
def setup_sssd(session_multihost, request):
    """ Configure sssd.conf """
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
    with open(temp_file_path, "w") as outfile:
        sssdConfig.write(outfile)
    session_multihost.master[0].transport.put_file(temp_file_path,
                                                   '/etc/sssd/sssd.conf')
    chg_perm = 'chmod 600 /etc/sssd/sssd.conf'
    session_multihost.master[0].run_command(chg_perm)
    os.close(temp_fd)
    try:
        session_multihost.master[0].service_sssd('restart')
    except SSSDException:
        journalctl_cmd = "journalctl -x -n 50 --no-pager"
        session_multihost.master[0].run_command(journalctl_cmd)
        assert False

    def stop_sssd():
        """ Stop sssd service """
        session_multihost.master[0].service_sssd('stop')
        sssd_cache = ['cache_%s.ldb' % ('EXAMPLE.TEST'), 'config.ldb',
                      'sssd.ldb', 'timestamps_%s.ldb' % ('EXAMPLE.TEST')]
        for cache_file in sssd_cache:
            db_file = '/var/lib/sss/db/%s' % (cache_file)
            session_multihost.master[0].run_command(['rm', '-f', db_file])
        secrets_db = '/var/lib/sss/secrets/secrets.ldb'
        session_multihost.master[0].run_command(['rm', '-f', secrets_db])
    request.addfinalizer(stop_sssd)


@pytest.fixture
def enable_kcm(session_multihost, request):
    """ Enable sssd kcm """
    backup_krb5_conf = 'cp /etc/krb5.conf /etc/krb5.conf.nokcm'
    session_multihost.master[0].run_command(backup_krb5_conf)
    session_multihost.master[0].service_sssd('stop')
    tools = sssdTools(session_multihost.master[0])
    tools.enable_kcm()
    start_kcm = 'systemctl start sssd-kcm'
    session_multihost.master[0].service_sssd('start')
    session_multihost.master[0].run_command(start_kcm)

    def disable_kcm():
        """ Disable sssd kcm """
        restore_krb5_conf = 'cp /etc/krb5.conf.nokcm /etc/krb5.conf'
        session_multihost.master[0].run_command(restore_krb5_conf)
        stop_kcm = 'systemctl stop sssd-kcm'
        session_multihost.master[0].run_command(stop_kcm)
    request.addfinalizer(disable_kcm)


@pytest.fixture(scope='class', autouse=True)
def create_posix_usersgroups(session_multihost):
    """ Create posix user and groups """
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
    except LdapException:
        assert False
    group_dn = 'cn=ldapusers,ou=Groups,dc=example,dc=test'
    for i in range(1, 10):
        user_dn = 'uid=foo%d,ou=People,dc=example,dc=test' % i
        add_member = [(ldap.MOD_ADD, 'uniqueMember', user_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(group_dn, add_member)
        assert ret == 'Success'


@pytest.fixture(scope="session", autouse=True)
def setup_session(request, session_multihost,
                  package_install,
                  run_authselect,
                  setup_ldap,
                  setup_kerberos):
    """ Run all session scoped fixtures """
    # pylint: disable=unused-argument
    _pytest_fixture = [package_install, run_authselect,
                       setup_ldap, setup_kerberos]
    tp = TestPrep(session_multihost)
    tp.setup()

    def teardown_session():
        """ Run teardown session scoped fixtures """
        tp.teardown()
    request.addfinalizer(teardown_session)


class TestPrep(object):
    """ Initialize Session """
    def __init__(self, multihost):
        self.multihost = multihost

    def setup(self):
        """ Start session """
        print("\n............Session Setup...............")

    def teardown(self):
        """ End session """
        print("\n............Session Ends.................")
