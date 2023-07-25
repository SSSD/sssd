
""" Common AD Fixtures """
from __future__ import print_function
import random
import subprocess
import time
import pytest
import ldap
import os
import posixpath
import pathlib
# pylint: disable=unused-import
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF, NSSWITCH_DEFAULT_CONF
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.qe_class import create_testdir
from sssd.testlib.common.exceptions import SSSDException
from sssd.testlib.common.utils import ADOperations
from sssd.testlib.common.exceptions import LdapException
from sssd.testlib.common.samba import sambaTools
from sssd.testlib.common.utils import sssdTools


def pytest_configure():
    """ Namespace hook, Adds below dict to pytest namespace """
    pytest.num_masters = 1
    pytest.num_ad = 1
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


@pytest.fixture(scope="function")
def create_adgrp(session_multihost, request, run_powershell_script):
    """ fixture to create AD Groups using powershell """
    ret = run_powershell_script(name='adgroup.ps1')
    if ret.returncode == 0:
        grp = ret.stdout_text.strip()
    else:
        raise SSSDException("powershell script failed to execute")

    def delete_adgrp():
        """ Delete AD group """
        dn_entry = session_multihost.ad[0].domain_basedn_entry
        grp_dn_entry = '{},{}'.format('CN=users', dn_entry)
        ad_group_dn = 'cn={},{}'.format(grp, grp_dn_entry)
        dsrm_exe = "dsrm.exe %s -noprompt" % ad_group_dn
        session_multihost.ad[0].run_command(dsrm_exe)
        rm_ps = "rm adgroup.ps1"
        session_multihost.ad[0].run_command(rm_ps, raiseonerr=False)
    request.addfinalizer(delete_adgrp)


@pytest.fixture(scope="function")
def fetch_ca_cert(session_multihost, request, run_powershell_script):
    """ fixture to fetch CA Certificate and store in client """
    ret = run_powershell_script(name='getadcacert.ps1')
    'openssl x509 -inform der -in adca.der -out certificate.pem'
    ca_crt = session_multihost.ad[0].get_file_contents('adca.der')
    session_multihost.client[0].put_file_contents('/tmp/adca.der', ca_crt)
    openssl_cmd = 'openssl x509 -inform der -in /tmp/adca.der '\
                  '-out /etc/openldap/certs/cacert.pem'
    cmd = session_multihost.client[0].run_command(openssl_cmd,
                                                  raiseonerr=False)
    if cmd.returncode != 0:
        pytest.fail("Failed to convert cert to ascii format")

    def remove_cert():
        """ Remove AD CA certificate """
        # remove /etc/openldap/certs/cacert.pem
        remove_client_ad_cacert = 'rm -f /etc/openldap/certs/cacert.pem'
        session_multihost.client[0].run_command(remove_client_ad_cacert)
    request.addfinalizer(remove_cert)


@pytest.fixture(scope="function")
def create_aduser_group(session_multihost, request):
    """ create AD user group """
    uid = random.randint(9999, 999999)
    ad = ADOperations(session_multihost.ad[0])
    ad_user = 'testuser%d' % uid
    ad_group = 'testgroup%d' % uid
    ad.create_ad_unix_user_group(ad_user, ad_group)

    def remove_ad_user_group():
        """ Remove windows AD user and group """
        ad.delete_ad_user_group(ad_group)
        ad.delete_ad_user_group(ad_user)

    request.addfinalizer(remove_ad_user_group)
    return (ad_user, ad_group)


@pytest.fixture(scope="function")
def create_domain_local_group(session_multihost, request):
    """ Add user in domain local AD group"""
    ad_client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    for i in range(1, 6):
        ad_group = 'ltestgroup%d' % i
        ad_client.create_ad_unix_group(ad_group)

    def remove_ad_group():
        """ Remove AD user group """
        for i in range(1, 6):
            ad_group = 'ltestgroup%d' % i
            ad_client.remove_ad_user_group(ad_group)
    request.addfinalizer(remove_ad_group)


@pytest.fixture(scope="function")
def add_nisobject(session_multihost, request):
    """ Add nisobject to auto.direct map """
    share_list = [request.param]
    nfs_server = session_multihost.master[0].external_hostname
    client_ip = session_multihost.client[0].ip
    server = sssdTools(session_multihost.master[0])
    bkup = 'cp -af /etc/exports /etc/exports.backup'
    session_multihost.master[0].run_command(bkup)
    session_multihost.master[0].package_mgmt('nfs-utils', action='install')
    server.export_nfs_fs(share_list, client_ip)
    start_nfs = 'systemctl start nfs-server'
    try:
        session_multihost.master[0].run_command(start_nfs)
    except subprocess.CalledProcessError:
        pytest.fail("Unable to start nfs server")
    ad = ADOperations(session_multihost.ad[0])
    ret = ad.add_map(request.param, nfs_server)
    assert ret == 'Success'

    def remove_project():
        """ Remove the nisproject from map """
        stop_autofs = 'systemctl stop autofs'
        session_multihost.client[0].run_command(stop_autofs)
        ret = ad.delete_map(request.param)
        assert ret == 'Success'
        remove_share = 'rm -rf %s' % request.param
        session_multihost.master[0].run_command(remove_share)
        restore = 'cp -f /etc/exports.backup /etc/exports'
        session_multihost.master[0].run_command(restore)
        stop_nfs = "systemctl stop nfs-server"
        try:
            session_multihost.master[0].run_command(stop_nfs)
        except subprocess.CalledProcessError:
            pytest.fail("failed to stop nfs-server")
    request.addfinalizer(remove_project)


@pytest.fixture(scope="function")
def set_autofs_search_base(session_multihost, request):
    """ Enable autofs service """
    client = sssdTools(session_multihost.client[0])
    client.backup_sssd_conf()
    domain_name = client.get_domain_section_name()
    domain_section = 'domain/{}'.format(domain_name)
    domain_basedn_entry = session_multihost.ad[0].domain_basedn_entry
    autofs_dn = "ou=automount,%s" % (domain_basedn_entry)
    sssd_params = {'ldap_autofs_search_base': autofs_dn}
    client.sssd_conf(domain_section, sssd_params)

    def remove_autofs_search_base():
        """ Remove autofs search base """
        client.restore_sssd_conf()
        client.clear_sssd_cache()
    request.addfinalizer(remove_autofs_search_base)


@pytest.fixture(scope="function")
def add_user_in_domain_local_group(request, session_multihost,
                                   create_aduser_group):
    """ Add user in domain local AD group"""
    (ad_user, ad_group) = create_aduser_group

    ad_client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    for i in range(1, 6):
        ad_group = 'ltestgroup%d' % i
        ad_client.add_aduser_member_group(ad_group, ad_user)

    def remove_user_group():
        """ Remove Windows AD user and group """
        for i in range(1, 6):
            ad_group = 'ltestgroup%d' % i
            ad_client.remove_ad_user_group(ad_group)

    request.addfinalizer(remove_user_group)
    return ad_group


@pytest.fixture(scope="function")
def add_principals(session_multihost, request):
    """ Adds Service HTTPS and NFS principal to existing Host """
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    spn_list = ['HTTP', 'NFS']
    client.add_service_principals(spn_list)

    def remove_principals():
        """ Remove service principals """
        client.remove_service_principals(spn_list)
    request.addfinalizer(remove_principals)


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
    ad_group = 'idmfoogroup1'
    kinit = 'kinit %s' % ad_user
    server = session_multihost.master[0].sys_hostname.strip().split('.')[0]
    share_path = '/mnt/samba/share1'
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
def enable_autofs_schema(session_multihost, request):
    """ Enable autofs schema(rfc2307) to Windows AD.
    :param obj session_multihost: multihost object
    :param obj request: pytest request object
    """
    ad_realm = session_multihost.ad[0].realm
    ad_password = session_multihost.ad[0].ssh_password
    ad_client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    basedn = session_multihost.ad[0].domain_basedn_entry
    automount_ou = 'ou=automount,%s' % basedn
    try:
        ad_client.remove_automount()
    except subprocess.CalledProcessError:
        print("Automount entry not found")
    else:
        print("Existing automount entry deleted")
    realm_output = ad_client.join_ad(ad_realm, ad_password)
    ad_client.autofs_ad_schema()

    def remove_automount_entries():
        """ Remove autofs schema from Windows AD """
        ad_client.disjoin_ad(realm_output)
        ad_client.remove_automount()
    request.addfinalizer(remove_automount_entries)


@pytest.fixture(scope="class")
def enable_autofs_service(session_multihost,
                          request):  # pylint: disable=unused-argument
    """ Enable autofs service """
    client = sssdTools(session_multihost.client[0])
    client.backup_sssd_conf()
    services = {'services': 'nss, pam, autofs'}
    client.sssd_conf('sssd', services)
    domain_name = client.get_domain_section_name()
    domain_section = 'domain/{}'.format(domain_name)
    sssd_params = {'autofs_provider': 'ad',
                   'debug_level': '9'}
    client.sssd_conf(domain_section, sssd_params)

    def disable_autofs_service():
        """ Disable autofs service in sssd.conf """
        services = {'services': 'nss, pam'}
        client.sssd_conf('sssd', services)
        client.clear_sssd_cache()
        stop_autofs = 'systemctl stop autofs'
        session_multihost.client[0].run_command(stop_autofs)
    request.addfinalizer(disable_autofs_service)


@pytest.fixture(scope="class")
def enable_ad_sudoschema(session_multihost):
    """ Enable AD Sudo schema """
    basedn = session_multihost.ad[0].domain_basedn_entry
    ldapuri = 'ldap://%s' % (session_multihost.ad[0].ip)
    print(session_multihost.ad[0].ip)
    password = session_multihost.ad[0].ssh_password
    user = 'cn=Administrator,cn=Users,%s' % (basedn)
    searchbase = 'CN=sudoRole,CN=Schema,CN=Configuration,%s' % basedn
    ldapsearch = 'ldapsearch -x -LLL -b %s -D %s -w %s'\
                 ' -H %s cn=SudoRole' % (searchbase, user, password, ldapuri)
    cmd = session_multihost.client[0].run_command(ldapsearch, raiseonerr=False)
    if cmd.returncode == 0:
        print("Schema already added")
    else:
        cwd = os.path.dirname(os.path.abspath(__file__))
        split_cwd = cwd.split('/')
        idx = split_cwd.index('pytest')
        path_list = split_cwd[:idx + 1]
        sssd_qe_path = '/'.join(path_list)
        data_path = "%s/data" % sssd_qe_path
        filename = 'schema.ActiveDirectory'
        remote_file_path = posixpath.join('/home/administrator', filename)
        source_file_path = posixpath.join(data_path, filename)
        session_multihost.ad[0].transport.put_file(source_file_path,
                                                   remote_file_path)
        ldifde = 'ldifde.exe -i -f schema.ActiveDirectory'\
                 ' -c dc=X %s' % basedn
        session_multihost.ad[0].run_command(ldifde, raiseonerr=False)

@pytest.fixture(scope="class")
def create_ad_sudousers(session_multihost, request):
    """ create Ad sudo users and groups """
    ad = ADOperations(session_multihost.ad[0])
    for idx in range(1, 10):
        ad_user = 'sudo_idmuser%d' % idx
        ad_group = 'sudo_idmgroup%d' % idx
        ad.delete_ad_user_group(ad_group)
        ad.delete_ad_user_group(ad_user)
        ad.create_ad_unix_user_group(ad_user, ad_group)

    def remove_ad_sudousers():
        """ Remove AD sudo users and groups """
        for idx in range(1, 10):
            ad_user = 'sudo_idmuser%d' % idx
            ad_group = 'sudo_idmgroup%d' % idx
            ad.delete_ad_user_group(ad_group)
            ad.delete_ad_user_group(ad_user)
    request.addfinalizer(remove_ad_sudousers)


@pytest.fixture(scope="class")
def sudorules(session_multihost, request):
    """ Create AD Sudo rules """
    basedn = session_multihost.ad[0].domain_basedn_entry
    ad_password = session_multihost.ad[0].ssh_password
    realm = session_multihost.ad[0].realm
    winad = ADOperations(session_multihost.ad[0])
    win_ldap = winad.ad_conn()
    ad_ip = session_multihost.ad[0].ip
    sudo_ou = 'ou=Sudoers,%s' % basedn
    remove_sudo = "powershell.exe -inputformat none -noprofile "\
                  "'(Remove-ADOrganizationalUnit -Identity \"%s\" "\
                  "-Recursive -Confirm:$false)'" % (sudo_ou)
    session_multihost.ad[0].run_command(remove_sudo, raiseonerr=False)
    def_command = '/usr/bin/less'
    win_ldap.org_unit('Sudoers', basedn)
    for item in ['user', 'group']:
        for idx in range(1, 10):
            rule_dn = 'cn=less_%s_rule%d,%s' % (item, idx, sudo_ou)
            sudo_identity = 'sudo_idm%s%d@%s' % (item, idx, realm)
            sudo_options = ["!requiretty", "!authenticate"]
            try:
                win_ldap.add_sudo_rule(rule_dn, 'ALL',
                                       def_command, sudo_identity,
                                       sudo_options)
            except LdapException:
                pytest.fail("Failed to add sudo rule %s" % rule_dn)
            if item == 'user':
                user = 'sudo_idmuser%d' % idx
                extra_sudo_user = [(ldap.MOD_ADD, 'sudoUser',
                                    user.encode('utf-8'))]
                (ret, _) = win_ldap.modify_ldap(rule_dn, extra_sudo_user)
                assert ret == 'Success'
    cmd = "ldapsearch -x -LLL -b '%s' -D cn=Administrator"\
          ",cn=Users,%s -w %s -H ldap://%s" % (sudo_ou, basedn,
                                               ad_password, ad_ip)
    session_multihost.client[0].run_command(cmd, raiseonerr=False)

    def delete_sudorule():
        """ Delete sudo rule """
        for item in ['user', 'group']:
            for idx in range(1, 10):
                rule_dn = 'cn=less_%s_rule%d,%s' % (item, idx, sudo_ou)
                (ret, _) = win_ldap.del_dn(rule_dn)
                assert ret == 'Success'
        session_multihost.ad[0].run_command(remove_sudo)
    request.addfinalizer(delete_sudorule)


@pytest.fixture(scope="class")
def joinad(session_multihost, request):
    """ class fixture to join AD using realm """
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    client.disjoin_ad()  # Make sure system is disjoined from AD
    kinit = "kinit Administrator"
    ad_password = session_multihost.ad[0].ssh_password
    realm_output = client.join_ad()
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


@pytest.fixture(scope="class")
def winbind_server(session_multihost, request):
    """ Winbind Server """
    master = sssdTools(session_multihost.master[0], session_multihost.ad[0])
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    master.server_install_pkgs()
    smb_master = sambaTools(session_multihost.master[0],
                            session_multihost.ad[0])
    smb_master.enable_winbind()
    smb_client = sambaTools(session_multihost.client[0],
                            session_multihost.ad[0])
    smb_client.enable_winbind()

    def disable():
        """ Disable winbind """
        print("we are disabling winbind")
        master.disjoin_ad()
        client.disjoin_ad()
        smb_master.disable_winbind()
        smb_master.clear_samba_cache()
        smb_master.remove_smbconf()
        smb_client.disable_winbind()
        smb_client.clear_samba_cache()
        smb_client.remove_smbconf()
    request.addfinalizer(disable)


@pytest.fixture(scope='class')
def configure_samba(session_multihost, request):
    """ samba server """
    master = sambaTools(session_multihost.master[0], session_multihost.ad[0])
    adops = ADOperations(session_multihost.ad[0])
    share_name = 'share1'
    share_path = '/mnt/samba/%s' % share_name
    master.add_share_definition('share1', '/mnt/samba/share1')
    master.service_smb(action='restart')
    time.sleep(20)

    def stop_samba_server():
        """ Stop samba server """
        print("we are stopping samba server")
        master.service_smb(action='stop')
        master.clear_samba_cache()
        master.remove_smbconf()
    request.addfinalizer(stop_samba_server)


@pytest.fixture(scope='class')
def samba_share_permissions(session_multihost, request):
    """ Set permissions on samba share """
    smbTools = sambaTools(session_multihost.master[0], session_multihost.ad[0])
    adops = ADOperations(session_multihost.ad[0])
    share_name = 'share1'
    share_path = '/mnt/samba/%s' % share_name
    smbTools.create_samba_share(share_path)
    realm = session_multihost.ad[0].realm
    for idx in range(1, 3):
        ad_user = 'idmfoouser%d' % idx
        ad_group = 'idmfoogroup%d' % idx
        all_group = 'idmfooallgroup'
        adops.delete_ad_user_group(ad_group)
        adops.delete_ad_user_group(ad_user)
    adops.delete_ad_user_group(all_group)
    adops.create_ad_unix_group(all_group)
    for idx in range(1, 3):
        ad_user = 'idmfoouser%d' % idx
        ad_group = 'idmfoogroup%d' % idx
        adops.create_ad_unix_user_group(ad_user, ad_group)
        adops.add_user_member_of_group(all_group, ad_user)
    session_multihost.master[0].service_sssd('restart')
    time.sleep(30)

    for idx in range(1, 3):
        ad_user = 'idmfoouser%d' % idx
        ad_group = 'idmfoogroup%d' % idx
        directory = '/mnt/samba/share1/idmfoogroup%d' % idx
        create_dir = 'mkdir -p %s' % directory
        session_multihost.master[0].run_command(create_dir)
        chmod = 'chmod 2770 %s' % directory
        session_multihost.master[0].run_command(chmod)
        chgrp = "chgrp '%s@%s' %s " % (ad_group, realm, directory)
        session_multihost.master[0].run_command(chgrp)

    all_group = 'idmfooallgroup'
    common_dir = 'mkdir -p /mnt/samba/share1/allgroup'
    session_multihost.master[0].run_command(common_dir)
    chgrp = "chgrp '%s@%s' /mnt/samba/share1/allgroup " % (all_group, realm)
    chmod = "chmod 2770 /mnt/samba/share1/allgroup"
    session_multihost.master[0].run_command(chgrp)
    session_multihost.master[0].run_command(chmod)

    # create mount point on client
    mount_point = 'mkdir -p %s' % share_path
    session_multihost.client[0].run_command(mount_point)

    def delete_share_directory():
        """ Delete share directory """
        print("we are deleting samba share directory")
        smbTools.delete_samba_share(share_path)
        remove_mount_point = "rm -rf %s" % share_path
        session_multihost.client[0].run_command(remove_mount_point)
        for idx in range(1, 3):
            ad_user = 'idmfoouser%d' % idx
            ad_group = 'idmfoogroup%d' % idx
            all_group = 'idmfooallgroup'
            adops.delete_ad_user_group(ad_group)
            adops.delete_ad_user_group(all_group)
            adops.delete_ad_user_group(ad_user)
    request.addfinalizer(delete_share_directory)

# ################### Session scoped fixtures #########################


@pytest.fixture(scope="session", autouse=True)
def setup_session(request, session_multihost):
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
