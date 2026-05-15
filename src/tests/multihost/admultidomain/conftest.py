
""" Common AD Fixtures """
from __future__ import print_function
import subprocess
import random
import pytest
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from sssd.testlib.common.utils import sssdTools


pytest_plugins = (
    'sssd.testlib.common.fixtures',
    'pytest_importance',
    'pytest_ticket',
    'sssd.testlib.common.custom_log',
)


def pytest_configure():
    """ Namespace hook, Adds below dict to pytest namespace """
    pytest.num_masters = 0
    pytest.num_ad = 4
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0


# ######## Function scoped Fixtures ####################
@pytest.fixture(scope="function")
def newhostname(session_multihost, request):
    """ Change client hostname to a truncated version in the AD domain"""
    cmd = session_multihost.client[0].run_command(
        'hostname', raiseonerr=False)
    ad_domain = session_multihost.ad[0].domainname
    old_hostname = cmd.stdout_text.rstrip()
    hostname = f'client{random.randint(1,99)}.{ad_domain}'
    session_multihost.client[0].run_command(
        f'hostname {hostname}', raiseonerr=False)

    def restore():
        """ Restore hostname """
        session_multihost.client[0].run_command(
            f'hostname {old_hostname}',
            raiseonerr=False
        )
    request.addfinalizer(restore)


@pytest.fixture(scope="function")
def adjoin(session_multihost, request):
    """ Join to AD using net ads command """
    ad_realm = session_multihost.ad[0].realm
    ad_ip = session_multihost.ad[0].ip
    ad_host = session_multihost.ad[0].sys_hostname
    client_ad = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    client_ad.update_resolv_conf(session_multihost.ad[0])
    client_ad.update_resolv_conf(session_multihost.ad[len(session_multihost.ad)-1])
    client_ad.systemsssdauth(ad_realm, ad_host)
    client_ad.disjoin_ad(raiseonerr=False)  # Make sure system is disjoined from AD
    client_ad.create_kdcinfo(ad_realm, ad_ip)
    kinit = f'kinit Administrator@{ad_realm}'
    ad_password = session_multihost.ad[0].ssh_password
    try:
        session_multihost.client[0].run_command(kinit, stdin_text=ad_password)
    except subprocess.CalledProcessError:
        pytest.fail("kinit failed")

    def _join(membersw=None):
        """ Join AD """
        if membersw == 'samba':
            client_ad.join_ad(ad_realm, ad_password, mem_sw='samba')
        else:
            client_ad.join_ad(ad_realm, ad_password)

    def adleave():
        """ Disjoin AD """
        client_ad.disjoin_ad(raiseonerr=False)
        remove_keytab = 'rm -f /etc/krb5.keytab'
        kdestroy_cmd = 'kdestroy -A'
        session_multihost.client[0].run_command(kdestroy_cmd)
        session_multihost.client[0].run_command(remove_keytab)
    request.addfinalizer(adleave)
    return _join


@pytest.fixture(autouse=True)
def capture_sssd_logs(session_multihost, request):
    """This will print sssd logs in case of test failure"""
    yield
    if request.session.testsfailed:
        client = session_multihost.client[0]
        print(f"\n\n===Logs for {request.node.name}===\n\n")
        for data_d in client.run_command("ls /var/log/sssd/").stdout_text.split():
            client.run_command(f'echo "--- {data_d} ---"; '
                               f'cat /var/log/sssd/{data_d}')


@pytest.fixture(scope="function")
def adchildjoin(session_multihost, request):
    """ Join to AD using net ads command """
    ad_realm = session_multihost.ad[1].realm
    ad_ip = session_multihost.ad[1].ip
    client_ad = sssdTools(session_multihost.client[0], session_multihost.ad[1])
    client_ad.disjoin_ad(raiseonerr=False)
    client_ad.create_kdcinfo(ad_realm, ad_ip)
    kinit = "kinit Administrator@%s" % ad_realm
    ad_password = session_multihost.ad[1].ssh_password
    try:
        session_multihost.client[0].run_command(kinit, stdin_text=ad_password)
    except subprocess.CalledProcessError:
        pytest.fail("kinit failed")

    def _join(membersw=None):
        """ Join AD """
        if membersw == 'samba':
            client_ad.join_ad(ad_realm, ad_password, mem_sw='samba')
        else:
            client_ad.join_ad(ad_realm, ad_password)

    def adleave():
        """ Disjoin AD """
        client_ad.disjoin_ad(raiseonerr=False)
        remove_keytab = 'rm -f /etc/krb5.keytab'
        kdestroy_cmd = 'kdestroy -A'
        session_multihost.client[0].run_command(kdestroy_cmd)
        session_multihost.client[0].run_command(remove_keytab)
    request.addfinalizer(adleave)
    return _join


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    bkup = 'cp -f %s %s.orig' % (SSSD_DEFAULT_CONF,
                                 SSSD_DEFAULT_CONF)
    session_multihost.client[0].run_command(bkup)
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        restore = 'cp -f %s.orig %s' % (SSSD_DEFAULT_CONF, SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(restore)
    request.addfinalizer(restoresssdconf)


# ############## class scoped Fixtures ##############################
@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests
    :param obj session_multihost: multihost object
    :return obj session_multihost: return multihost object
    :Exceptions: None
    """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope="class")
def clear_sssd_cache(session_multihost):
    """ Clear sssd cache """
    client = sssdTools(session_multihost.client[0])
    client.clear_sssd_cache()


# ################### Session scoped fixtures #########################
@pytest.fixture(scope="session", autouse=True)
def setup_session(request, session_multihost, create_testdir):
    """ Setup Session """
    client = sssdTools(session_multihost.client[0])
    realm = session_multihost.ad[1].realm
    ad_host = session_multihost.ad[1].sys_hostname
    try:
        master = sssdTools(session_multihost.master[0])
    except IndexError:
        pass
    else:
        master.server_install_pkgs()
        master.update_resolv_conf(session_multihost.ad[1].ip)
    client.client_install_pkgs()
    client.update_resolv_conf(session_multihost.ad[1].ip)
    client.clear_sssd_cache()
    client.systemsssdauth(realm, ad_host)

    def teardown_session():
        """ Teardown session """
        session_multihost.client[0].service_sssd('stop')
        remove_sssd_conf = 'rm -f /etc/sssd/sssd.conf'
        session_multihost.client[0].run_command(remove_sssd_conf)
    request.addfinalizer(teardown_session)
