
""" Common AD Fixtures """
from __future__ import print_function
import subprocess
import time
import pytest
import os
import posixpath
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from sssd.testlib.common.exceptions import SSSDException
from sssd.testlib.common.samba import sambaTools
from sssd.testlib.common.utils import sssdTools

pytest_plugins = (
    'sssd.testlib.common.fixtures',
    'pytest_importance',
    'pytest_ticket',
)


def pytest_configure():
    """ Namespace hook, Adds below dict to pytest namespace """
    pytest.num_masters = 0
    pytest.num_ad = 2
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0

# ######## Function scoped Fixtures ####################


@pytest.fixture(scope="function")
def smbconfig(session_multihost, request):
    """ Configure smb.conf """
    sambaclient = sambaTools(session_multihost.client[0],
                             session_multihost.ad[0])
    sambaclient.smbadsconf()

    def restore():
        """ Restore smb.conf """
        restoresmb = 'cp -f /etc/samba/smb.conf.orig /etc/samba/smb.conf'
        session_multihost.client[0].run_command(restoresmb, raiseonerr=False)
        removebkup = 'rm -f /etc/samba/smb.conf.orig'
        session_multihost.client[0].run_command(removebkup, raiseonerr=False)
    request.addfinalizer(restore)


@pytest.fixture(scope='function')
def run_powershell_script(session_multihost, request):
    """ Run Powershell script """
    cwd = os.path.dirname(os.path.abspath(__file__))
    split_cwd = cwd.split('/')
    idx = split_cwd.index('pytest')
    path_list = split_cwd[:idx + 1]
    sssd_qe_path = '/'.join(path_list)
    data_path = "%s/data" % sssd_qe_path

    def _script(name):
        """ Run powershell script """
        filename = name
        remote_file_path = posixpath.join('/home/administrator', filename)
        source_file_path = posixpath.join(data_path, filename)
        session_multihost.ad[0].transport.put_file(source_file_path,
                                                   remote_file_path)
        pwrshell_cmd = 'powershell.exe -inputformat '\
                       'none -noprofile ./%s' % filename
        cmd = session_multihost.ad[0].run_command(pwrshell_cmd,
                                                  raiseonerr=False)
        return cmd
    return _script


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
def adjoin(session_multihost, request):
    """ Join to AD using net ads command """
    ad_realm = session_multihost.ad[0].realm
    ad_ip = session_multihost.ad[0].ip
    client_ad = sssdTools(session_multihost.client[0], session_multihost.ad[0])

    client_ad.disjoin_ad()  # Make sure system is disjoined from AD
    client_ad.create_kdcinfo(ad_realm, ad_ip)
    kinit = "kinit Administrator"
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
        client_ad.disjoin_ad()
        remove_keytab = 'rm -f /etc/krb5.keytab'
        kdestroy_cmd = 'kdestroy -A'
        session_multihost.client[0].run_command(kdestroy_cmd)
        session_multihost.client[0].run_command(remove_keytab)
    request.addfinalizer(adleave)
    return _join


@pytest.fixture(scope="function")
def get_rid(session_multihost, create_aduser_group):
    """
    Find Relative ID from object SID
    :param obj session_multihost: multihost object
    :Return: RID value
    """
    (user, _) = create_aduser_group
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    client.clear_sssd_cache()
    ad_user = '{}@{}'.format(user, session_multihost.ad[0].domainname)
    getent = 'getent passwd %s' % ad_user
    cmd = session_multihost.client[0].run_command(getent, raiseonerr=False)
    if cmd.returncode == 0:
        rid = client.find_rid(ad_user)
        return (ad_user, rid)
    else:
        pytest.fail("%s User lookup failed" % ad_user)


@pytest.fixture(scope="function")
def keytab_sssd_conf(session_multihost, request, adjoin):
    """ Add parameters required for keytab rotation in sssd.conf """
    adjoin(membersw='samba')
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    client.backup_sssd_conf()
    sssd_params = {'ad_maximum_machine_account_password_age': '1',
                   'ad_machine_account_password_renewal_opts': '300:15',
                   'debug_level': '9'}
    domain_name = client.get_domain_section_name()
    domain_section = 'domain/{}'.format(domain_name)
    client.sssd_conf(domain_section, sssd_params,)

    def restore_sssd_conf():
        """ Restore original sssd.conf """
        client.restore_sssd_conf()
    request.addfinalizer(restore_sssd_conf)


@pytest.fixture(scope="function")
def cifsmount(session_multihost, request):
    """ Mount cifs share and create files with
    different permissions
    """
    ad_user = 'idmfoouser1'
    kinit = 'kinit %s' % ad_user
    server = session_multihost.master[0].sys_hostname.strip().split('.')[0]
    session_multihost.client[0].run_command(kinit, stdin_text='Secret123')
    mountcifs = "mount -t cifs -o cifsacl "\
                "-o sec=krb5 -o username=%s //%s/share1"\
                " /mnt/samba/share1" % (ad_user, server)
    cmd = session_multihost.client[0].run_command(mountcifs, raiseonerr=False)
    time.sleep(5)
    if cmd.returncode != 0:
        journalctl = 'journalctl -x -n 50 --no-pager'
        session_multihost.client[0].run_command(journalctl)

    def cifsunmount():
        """ Umount the cifs shares """
        umount = "umount /mnt/samba/share1"
        cmd = session_multihost.client[0].run_command(umount, raiseonerr=False)
        assert cmd.returncode == 0
        kdestroy = 'kdestroy -A'
        session_multihost.client[0].run_command(kdestroy, raiseonerr=False)
    request.addfinalizer(cifsunmount)


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


@pytest.fixture(scope='function')
def create_site(session_multihost, request):
    ad2_hostname = session_multihost.ad[1].hostname
    ad2_shostname = ad2_hostname.strip().split('.')[0]
    site = "Raleigh"

    cmd_create_site = "powershell.exe -inputformat none -noprofile " \
                      "'(New-ADReplicationSite -Name \"%s\" " \
                      "-Confirm:$false)'" % site
    cmd_move_ad2 = "powershell.exe -inputformat none -noprofile " \
                   "'(Move-ADDirectoryServer -Identity \"%s\" -Site \"%s\" " \
                   "-Confirm:$false)'" % (ad2_shostname, site)

    session_multihost.ad[0].run_command(cmd_create_site)
    session_multihost.ad[0].run_command(cmd_move_ad2)

    def teardown_site():
        cmd_move_ad2back = "powershell.exe -inputformat none -noprofile " \
                           "'(Move-ADDirectoryServer -Identity \"%s\" " \
                           "-Site \"Default-First-Site-Name\" " \
                           "-Confirm:$false)'" % ad2_shostname
        cmd_remove_site2 = "powershell.exe -inputformat none -noprofile " \
                           "'(Remove-ADReplicationSite \"%s\" " \
                           "-Confirm:$false)'" % site
        session_multihost.ad[0].run_command(cmd_move_ad2back)
        session_multihost.ad[0].run_command(cmd_remove_site2)

    request.addfinalizer(teardown_site)


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


@pytest.fixture(scope="class")
def joinad(session_multihost, request):
    """ class fixture to join AD using realm """
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    client.disjoin_ad()  # Make sure system is disjoined from AD
    kinit = "kinit Administrator"
    ad_password = session_multihost.ad[0].ssh_password
    client.join_ad()
    try:
        session_multihost.client[0].service_sssd('restart')
    except SSSDException:
        cmd = 'cat /etc/sssd/sssd.conf'
        session_multihost.client[0].run_command(cmd)
        journal = 'journalctl -x -n 150 --no-pager'
        session_multihost.client[0].run_command(journal)
    retry = 0
    while (retry != 5):
        cmd = session_multihost.client[0].run_command(kinit,
                                                      stdin_text=ad_password,
                                                      raiseonerr=False)
        if cmd.returncode == 0:
            break
        else:
            retry += 1
            time.sleep(5)

    def disjoin():
        """ Disjoin system from Windows AD """
        client.disjoin_ad()
        stop_sssd = 'systemctl stop sssd'
        remove_keytab = 'rm -f /etc/krb5.keytab'
        kdestroy_cmd = 'kdestroy -A'
        session_multihost.client[0].run_command(stop_sssd)
        session_multihost.client[0].run_command(remove_keytab)
        session_multihost.client[0].run_command(kdestroy_cmd)
    request.addfinalizer(disjoin)

# ################### Session scoped fixtures #########################


@pytest.fixture(scope="session", autouse=True)
def setup_session(request, session_multihost, create_testdir):
    """ Setup Session """
    client = sssdTools(session_multihost.client[0])
    realm = session_multihost.ad[0].realm
    ad_host = session_multihost.ad[0].sys_hostname
    try:
        master = sssdTools(session_multihost.master[0])
    except IndexError:
        pass
    else:
        master.server_install_pkgs()
        master.update_resolv_conf(session_multihost.ad[0].ip)
    client.client_install_pkgs()
    client.update_resolv_conf(session_multihost.ad[0].ip)
    client.clear_sssd_cache()
    client.systemsssdauth(realm, ad_host)

    def teardown_session():
        """ Teardown session """
        session_multihost.client[0].service_sssd('stop')
        remove_sssd_conf = 'rm -f /etc/sssd/sssd.conf'
        session_multihost.client[0].run_command(remove_sssd_conf)
    request.addfinalizer(teardown_session)
