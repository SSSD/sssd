from sssd.testlib.common.libkrb5 import krb5srv
from sssd.testlib.common.utils import sssdTools, PkiTools
from sssd.testlib.common.utils import LdapOperations
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException
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


pytest_plugins = (
    'sssd.testlib.common.fixtures',
    'pytest_importance',
    'pytest_ticket',
    'sssd.testlib.common.custom_log',
)


def pytest_configure():
    pytest.num_masters = 1
    pytest.num_ad = 0
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 0
    pytest.num_others = 0


@pytest.fixture(scope="class")
def multihost(session_multihost):
    """ multihost fixture """
    return session_multihost


@pytest.fixture(scope="session")
def package_install(session_multihost):
    """ Install required packages """
    distro = session_multihost.master[0].distro
    pkg_list = 'acl authselect nss-tools 389-ds-base krb5-server '\
               'openldap-clients krb5-workstation '\
               'sssd sssd-dbus sssd-kcm ' \
               'expect ldb-tools sssd-tools'
    cmd = 'yum install -y %s' % (pkg_list)
    if '8.' in distro:
        enableidm = 'yum -y module enable idm:DL1'
        session_multihost.master[0].run_command(enableidm)
    session_multihost.master[0].run_command(cmd)


@pytest.fixture(scope="session")
def run_authselect(session_multihost):
    """ Run authconfig to configure Kerberos and SSSD auth on remote host """
    authselect_cmd = 'authselect select sssd with-mkhomedir --force'
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
        remove_keytab = 'rm -f /etc/krb5.keytab'
        session_multihost.master[0].run_command(remove_keytab)
    request.addfinalizer(remove_kerberos)


@pytest.fixture(scope='class', autouse=True)
def setup_sssd(session_multihost, request):
    """ Configure sssd.conf """
    domain_section = 'domain/EXAMPLE.TEST'
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    krb5_server = session_multihost.master[0].sys_hostname
    cacert_loc = '/etc/openldap/cacerts/cacert.pem'
    sssdConfig = ConfigParser.ConfigParser()
    sssdConfig.optionxform = str
    sssdConfig.add_section('sssd')
    sssdConfig.set('sssd', 'domains', 'EXAMPLE.TEST')
    sssdConfig.set('sssd', 'services', 'nss, pam, sudo, ifp')
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
    sssdConfig.set(domain_section, 'ldap_sudo_random_offset', '0')
    sssdConfig.add_section('nss')
    sssdConfig.set('nss', 'debug_level', '9')
    sssdConfig.add_section('pam')
    sssdConfig.set('pam', 'debug_level', '9')
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


@pytest.fixture(scope='session')
def enable_oddjob(session_multihost, request):
    """Enables and starts oddjob service"""
    check_enabled = session_multihost.master[0].run_command(
        'systemctl is-enabled oddjobd.service', raiseonerr=False)
    enabled = "enabled" in check_enabled.stdout_text
    check_active = session_multihost.master[0].run_command(
        'systemctl is-active oddjobd.service', raiseonerr=False)
    active = "inactive" not in check_active.stdout_text
    if not enabled:
        session_multihost.master[0].run_command(
            'systemctl enable oddjobd.service', raiseonerr=False)
    if not active:
        session_multihost.master[0].run_command(
            'systemctl start oddjobd.service', raiseonerr=False)

    def revert_odjob():
        """Reverts changes to oddjob service."""
        if not enabled:
            session_multihost.master[0].run_command(
                'systemctl disable oddjobd.service', raiseonerr=False)
        if not active:
            session_multihost.master[0].run_command(
                'systemctl stop oddjobd.service', raiseonerr=False)

    request.addfinalizer(revert_odjob)


@pytest.fixture
def create_casesensitive_posix_user(session_multihost):
    """ Create a case sensitive posix user """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    username = 'CAPSUSER-1'
    user_info = {'cn': username,
                 'uid': username,
                 'uidNumber': '24583100',
                 'gidNumber': '14564100'}
    ldap_inst.posix_user("ou=People", "dc=example,dc=test", user_info)
    krb.add_principal('CAPSUSER-1', 'user', 'Secret123')


@pytest.fixture
def set_case_sensitive_false(session_multihost, request):
    """ Set case_sensitive to false in sssd domain section """
    bkup_sssd = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
    session_multihost.master[0].run_command(bkup_sssd)
    session_multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                                   '/tmp/sssd.conf')
    sssdconfig = ConfigParser.ConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    domain_section = "%s/%s" % ('domain', 'EXAMPLE.TEST')
    if domain_section in sssdconfig.sections():
        sssdconfig.set(domain_section, 'case_sensitive', 'false')
        with open('/tmp/sssd.conf', "w") as sssconf:
            sssdconfig.write(sssconf)
    session_multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                                   '/etc/sssd/sssd.conf')
    session_multihost.master[0].service_sssd('restart')

    def restore_sssd():
        """ Restore sssd.conf """
        restore_sssd = 'cp -f /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        session_multihost.master[0].run_command(restore_sssd)
        session_multihost.master[0].service_sssd('restart')
    request.addfinalizer(restore_sssd)


@pytest.fixture
def set_entry_cache_sudo_timeout(session_multihost, request):
    """ Set entry cache sudo timeout in sssd.conf """
    bkup_sssd = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
    session_multihost.master[0].run_command(bkup_sssd)
    session_multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                                   '/tmp/sssd.conf')
    sssdconfig = ConfigParser.ConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    domain_section = "%s/%s" % ('domain', 'EXAMPLE.TEST')
    if domain_section in sssdconfig.sections():
        sssdconfig.set(domain_section, 'entry_cache_sudo_timeout', '30')
        with open('/tmp/sssd.conf', "w") as sssconf:
            sssdconfig.write(sssconf)
    session_multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                                   '/etc/sssd/sssd.conf')
    session_multihost.master[0].service_sssd('restart')

    def restore_sssd():
        """ Restore sssd.conf """
        restore_sssd = 'cp -f /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        session_multihost.master[0].run_command(restore_sssd)
        session_multihost.master[0].service_sssd('restart')
    request.addfinalizer(restore_sssd)


@pytest.fixture
def generic_sudorule(session_multihost, request):
    """ Create a generic sudo rule """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    ldap_inst.org_unit('sudoers', 'dc=example,dc=test')
    sudo_ou = 'ou=sudoers,dc=example,dc=test'
    rule_dn1 = "%s,%s" % ('cn=lessrule', sudo_ou)
    sudo_options = ["!requiretty", "!authenticate"]
    try:
        ldap_inst.add_sudo_rule(rule_dn1, 'ALL',
                                '/usr/bin/less', 'foo1',
                                sudo_options)
    except LdapException:
        pytest.fail("Failed to add sudo rule %s" % rule_dn1)

    def del_sudo_rule():
        """ Delete sudo rule """
        (ret, _) = ldap_inst.del_dn(rule_dn1)
        assert ret == 'Success'
        (ret, _) = ldap_inst.del_dn(sudo_ou)
        assert ret == 'Success'
    request.addfinalizer(del_sudo_rule)


@pytest.fixture
def enable_files_domain(session_multihost):
    """
    Enable the implicit files domain
    """
    session_multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                                   '/tmp/sssd.conf')
    sssdconfig = ConfigParser.RawConfigParser(delimiters=('='))
    sssdconfig.read('/tmp/sssd.conf')
    sssd_section = 'sssd'
    if sssd_section in sssdconfig.sections():
        sssdconfig.set(sssd_section, 'enable_files_domain', 'true')
        with open('/tmp/sssd.conf', "w") as sssconf:
            sssdconfig.write(sssconf)
    session_multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                                   '/etc/sssd/sssd.conf')
    session_multihost.master[0].service_sssd('restart')


@pytest.fixture(scope="class")
def files_domain_users_class(request, session_multihost):
    users = ('lcl1', 'lcl2', 'lcl3')
    for user in users:
        useradd_cmd = "useradd %s" % (user)
        session_multihost.master[0].run_command(useradd_cmd)

    no_home_users = ('no_home_user', )
    for user in no_home_users:
        useradd_cmd = "useradd --no-create-home %s" % (user)
        session_multihost.master[0].run_command(useradd_cmd)
        usermod_cmd = "usermod -d /tmp %s" % (user)
        session_multihost.master[0].run_command(usermod_cmd)

    def teardown_files_domain_users():
        for user in users + no_home_users:
            userdel_cmd = "userdel %s" % (user)
            session_multihost.master[0].run_command(userdel_cmd)
    request.addfinalizer(teardown_files_domain_users)


@pytest.fixture
def case_sensitive_sudorule(session_multihost,
                            create_casesensitive_posix_user,
                            request):
    """ Create posix user and groups """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    ldap_inst.org_unit('sudoers', 'dc=example,dc=test')
    sudo_ou = 'ou=sudoers,dc=example,dc=test'
    rule_dn1 = "%s,%s" % ('cn=lessrule', sudo_ou)
    rule_dn2 = "%s,%s" % ('cn=morerule', sudo_ou)
    sudo_options = ["!requiretty", "!authenticate"]
    try:
        ldap_inst.add_sudo_rule(rule_dn1, 'ALL',
                                '/usr/bin/less', 'capsuser-1',
                                sudo_options)
    except LdapException:
        pytest.fail("Failed to add sudo rule %s" % rule_dn1)
    try:
        ldap_inst.add_sudo_rule(rule_dn2, 'ALL',
                                '/usr/bin/more', 'CAPSUSER-1',
                                sudo_options)
    except LdapException:
        pytest.fail("Failed to add sudo rule %s" % rule_dn2)

    def del_sensitive_sudo_rule():
        """ Delete sudo rule """
        (ret, _) = ldap_inst.del_dn(rule_dn1)
        assert ret == 'Success'
        (ret, _) = ldap_inst.del_dn(rule_dn2)
        assert ret == 'Success'
        (ret, _) = ldap_inst.del_dn(sudo_ou)
        assert ret == 'Success'
    request.addfinalizer(del_sensitive_sudo_rule)


@pytest.fixture
def enable_sss_sudo_nsswitch(session_multihost, tmpdir, request):
    """Enable sss backend for sudoers in nsswitch.conf """
    conf = '/etc/nsswitch.conf'
    local_conf = tmpdir.mkdir("tmpdir").join('nsswitch.conf')
    backup_cmd = "cp -f /etc/nsswitch.conf /etc/nsswitch.conf.backup"
    session_multihost.master[0].run_command(backup_cmd)
    content = '\nsudoers: sss\n'
    session_multihost.master[0].transport.get_file(conf, str(local_conf))

    local_conf.write(content, mode='a')
    session_multihost.master[0].transport.put_file(str(local_conf),
                                                   '/etc/nsswitch.conf')

    def restore_nsswitch():
        """ Restore nsswitch.conf """
        restore_cmd = 'cp -f /etc/nsswitch.conf.backup /etc/nsswitch.conf'
        session_multihost.master[0].run_command(restore_cmd)
    request.addfinalizer(restore_nsswitch)


@pytest.fixture(scope='session')
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
                     'gidNumber': '14564100',
                     'userPassword': 'Secret123'}
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


@pytest.fixture(scope='session')
def create_many_user_principals(session_multihost):
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    for i in range(1, 65):
        username = "user%04d" % i
        krb.add_principal(username, 'user', 'Secret123')


@pytest.fixture(scope="session", autouse=True)
def setup_session(request, session_multihost,
                  package_install,
                  run_authselect,
                  setup_ldap,
                  setup_kerberos,
                  create_posix_usersgroups,
                  enable_oddjob,
                  create_testdir):
    """ Run all session scoped fixtures """
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
