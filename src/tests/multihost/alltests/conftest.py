"""conftest.py for all tests"""

from __future__ import print_function
import os
import time
import posixpath
import ldap
import pytest
import re
import subprocess
import random
from datetime import datetime, timedelta
from constants import ds_instance_name, ds_suffix, krb_realm, ds_rootdn, ds_rootpw
from sssd.testlib.common.libkrb5 import krb5srv
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF, NSSWITCH_DEFAULT_CONF
from sssd.testlib.common.utils import PkiTools, sssdTools, LdapOperations
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException, LdapException

pytest_plugins = (
    'sssd.testlib.common.fixtures',
    'pytest_importance',
    'pytest_ticket',
    'sssd.testlib.common.custom_log',
)


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 2
    pytest.num_ad = 0
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0

# ==================== Function Scoped Fixtures ==============


@pytest.fixture(scope='function')
def multidomain_sssd(session_multihost, request):
    """ Multidomain sssd configuration """
    session_multihost.client[0].service_sssd('stop')
    tools = sssdTools(session_multihost.client[0])
    tools.backup_sssd_conf()
    tools.remove_sss_cache('/var/lib/sss/db')
    tools.remove_sss_cache('/var/lib/sss/mc')

    def _modifysssd(domains):
        """ Modify sssd.conf """
        if domains == 'proxy_ldap2':
            ds_host = session_multihost.master[1].sys_hostname
            sssd_params = {'domains': 'proxy, ldap2'}
            tools.sssd_conf('sssd', sssd_params)
            ldap_uri = 'ldaps://%s' % ds_host
            suffix = 'dc=example1,dc=test'
            domain_params = {'ldap_search_base': suffix, 'ldap_uri': ldap_uri}
            tools.sssd_conf('domain/ldap2', domain_params)

        if domains == 'local_proxy':
            sssd_params = {'domains': 'proxy, local'}
            tools.sssd_conf('sssd', sssd_params)
            proxy_params = {'min_id': '2000', 'max_id': '2010'}
            local_params = {'min_id': '5000', 'max_id': '5010'}
            tools.sssd_conf('domain/proxy', proxy_params)
            tools.sssd_conf('domain/local', local_params)

        if domains == 'local_ldap':
            ds_host = session_multihost.master[1].sys_hostname
            sssd_params = {'domains': 'local, ldap1'}
            tools.sssd_conf('sssd', sssd_params)
            ldap_uri = 'ldaps://%s' % (ds_host)
            suffix = 'dc=example1,dc=test'
            domain_params = {'ldap_search_base': suffix,
                             'ldap_uri': ldap_uri,
                             'min_id': '3000', 'max_id': '3010'}
            files_params = {'min_id': '2000', 'max_id': '2010'}
            tools.sssd_conf('domain/ldap1', domain_params)
            tools.sssd_conf('domain/local', files_params)

        if domains == 'ldap_ldap':
            sssd_params = {'domains': 'ldap1, ldap2'}
            tools.sssd_conf('sssd', sssd_params)
            id_suffix = ['20', '30']
            for idx in range(2):
                ds_host = session_multihost.master[idx].sys_hostname
                ldap_uri = 'ldaps://%s' % (ds_host)
                suffix = 'dc=example%d,dc=test' % idx
                u_search_base = 'ou=People,%s' % suffix
                g_search_base = 'ou=Groups,%s' % suffix
                ldap_params = {'ldap_search_base': suffix,
                               'ldap_uri': ldap_uri,
                               'min_uid': '%s00' % id_suffix[idx],
                               'max_id': '%s20' % id_suffix[idx],
                               'ldap_group_search_base': g_search_base,
                               'ldap_user_search_base': u_search_base,
                               'cache_credentials': 'False',
                               'use_fully_qualified_names': 'True'}
                domain_section = 'domain/ldap%d' % (idx + 1)
                tools.sssd_conf(domain_section, ldap_params)

    def removesssd():
        """ Remove sssd configuration """
        stop_sssd = 'systemctl stop sssd'
        session_multihost.client[0].run_command(stop_sssd)
        tools.restore_sssd_conf()
    request.addfinalizer(removesssd)
    return _modifysssd


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


@pytest.fixture(scope="function", autouse=True)
def setup_authselect(session_multihost):
    """
    Make sure to use sssd as authselect profile
    """
    # We should not overwrite nsswitch that is changed/pre-configured
    session_multihost.client[0].run_command(
        "test -L /etc/nsswitch.conf && authselect select sssd --force", raiseonerr=False
    )


@pytest.fixture(scope='function')
def ldap_posix_usergroup(session_multihost, request):
    """ Create single ldap posix user group """
    ldap_uri = f'ldap://{session_multihost.master[0].sys_hostname}'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    id = random.randint(9, 99)
    user_info = {'cn': f'usr_{id}',
                 'uid': f'usr_{id}',
                 'uidNumber': f'345831{id}',
                 'gidNumber': f'345641{id}'}
    if ldap_inst.posix_user("ou=People", "dc=example,dc=test", user_info):
        krb.add_principal(f'usr_{id}', 'user', 'Secret123')
    else:
        print(f"Unable to add ldap User {user_info}")
        assert False
    memberdn = f'uid=usr_{id},ou=People,dc=example,dc=test'
    group_info = {'cn': f'ldapgrp{id}',
                  'gidNumber': f'345641{id}',
                  'uniqueMember': memberdn}
    try:
        ldap_inst.posix_group("ou=Groups", "dc=example,dc=test", group_info)
    except LdapException:
        assert False

    def delposixobject():
        """ Delete ldap posix user and group """
        ldap_inst.del_dn(f'uid=usr_{id},ou=People,dc=example,dc=test')
        ldap_inst.del_dn(f'cn=ldapgrp{id},ou=Groups,dc=example,dc=test')
        krb.delete_principal(f'usr_{id}')
    request.addfinalizer(delposixobject)
    return f'usr_{id}'


@pytest.fixture(scope='function')
def localusers(session_multihost, request):
    """ Create local users """
    users = {'user5000': '5000', 'user5001': '5001'}
    for key, value in users.items():
        useradd = 'useradd -u %s %s' % (value, key)
        session_multihost.client[0].run_command(useradd, raiseonerr=False)
        passwd = 'passwd --stdin %s' % (key)
        session_multihost.client[0].run_command(passwd,
                                                stdin_text='Secret123',
                                                raiseonerr=False)

    def delusers():
        """ Delete local users """
        for key, _ in users.items():
            userdel = 'userdel -f -r %s' % key
            session_multihost.client[0].run_command(userdel)
    request.addfinalizer(delusers)
    return users


@pytest.fixture(scope='function')
def create_350_posix_users(session_multihost, request):
    """ Create posix user and groups """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    for i in range(1, 351):
        user_info = {'cn': 'doo%d' % i,
                     'uid': 'doo%d' % i,
                     'uidNumber': '145831%d' % i,
                     'gidNumber': f'145641{i}'}
        if ldap_inst.posix_user("ou=People",
                                "dc=example,dc=test",
                                user_info):
            krb.add_principal('doo%d' % i, 'user', 'Secret123')
        else:
            print("Unable to add ldap User %s" % (user_info))
            assert False

    def remove_users():
        """ Remove default sssd.conf """
        for i in range(1, 351):
            ldap_inst.del_dn(f'uid=doo{i},ou=People,dc=example,dc=test')
            krb.delete_principal(f'doo{i}')

    request.addfinalizer(remove_users)


@pytest.fixture(scope='function')
def enable_sss_sudo_nsswitch(session_multihost, request):
    """Enable sss backend for sudoers in nsswitch.conf """
    distro = session_multihost.client[0].distro
    if 'Fedora' or '8.' in distro:
        cmd = 'authselect select sssd with-sudo'
        session_multihost.client[0].run_command(cmd)
    else:
        backup = 'cp -af /etc/nsswitch.conf /etc/nsswitch.conf.backup'
        session_multihost.client[0].run_command(backup)
        content = '\nsudoers: files sss\n'
        session_multihost.client[0].put_file_contents(content,
                                                      NSSWITCH_DEFAULT_CONF)

    def restore_nsswitch():
        """ Restore nsswitch.conf """
        if 'Fedora' or '8.' in distro:
            cmd = 'authselect select sssd'
            session_multihost.client[0].run_command(cmd)
        else:
            restore = 'cp -f /etc/nsswitch.conf.backup /etc/nsswitch.conf'
            session_multihost.client[0].run_command(restore)
    request.addfinalizer(restore_nsswitch)


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    tools = sssdTools(session_multihost.client[0])
    tools.backup_sssd_conf()
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        tools.restore_sssd_conf()
    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope='function')
def delete_groups_users(session_multihost, request):
    """Fixture for bz1817122"""
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)

    def restoresssdconf():
        """Delete users, ous and groups"""
        for i in range(1, 9):
            ldap_inst.del_dn(f'cn=user-{i},ou=posix_groups,ou=Unit2,'
                             f'ou=Unit1,dc=example,dc=test')
        for i in range(1, 3):
            ldap_inst.del_dn(f'cn=group-{i},ou=posix_groups,ou=Unit2,'
                             f'ou=Unit1,dc=example,dc=test')
        for i in range(1, 9):
            ldap_inst.del_dn(f'cn=user-{i},ou=users,ou=Unit2,'
                             f'ou=Unit1,dc=example,dc=test')
        for dn_dn in ['netgroups', 'services', 'sudoers']:
            ldap_inst.del_dn(f'ou={dn_dn},dc=example,dc=test')
        for dn_dn in ['ou=posix_groups,ou=Unit2,ou=Unit1,dc=example,dc=test',
                      'ou=users,ou=Unit2,ou=Unit1,dc=example,dc=test',
                      'ou=Unit2,ou=Unit1,dc=example,dc=test',
                      'ou=Unit1,dc=example,dc=test']:
            ldap_inst.del_dn(dn_dn)
    request.addfinalizer(restoresssdconf)


@pytest.fixture(scope="function")
def set_dslimits(session_multihost, request):
    """ Modify nsslapd-sizelimit """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    configdn = 'cn=config,cn=ldbm database,cn=plugins,cn=config'
    mod_limit = [(ldap.MOD_REPLACE, 'nsslapd-lookthroughlimit', [b'10'])]
    (ret, _) = ldap_inst.modify_ldap(configdn, mod_limit)
    mod_limit = [(ldap.MOD_REPLACE, 'nsslapd-pagedlookthroughlimit', [b'10'])]
    (ret, _) = ldap_inst.modify_ldap(configdn, mod_limit)

    assert ret == 'Success'

    def restore_dslimits():
        """ Restore the default sizelimit """
        restore_lookthrough = [(ldap.MOD_REPLACE, 'nsslapd-lookthroughlimit',
                               [b'2000'])]
        (ret, _) = ldap_inst.modify_ldap(configdn, restore_lookthrough)
        restore_page = [(ldap.MOD_REPLACE,
                         'nsslapd-pagedlookthroughlimit', [b'2000'])]
        (ret, _) = ldap_inst.modify_ldap(configdn, restore_page)
        assert ret == 'Success'
    request.addfinalizer(restore_dslimits)


@pytest.fixture(scope="function")
def add_nisobject(session_multihost, request):
    """ Add nisobject to auto.direct map """
    share_list = [request.param]
    nfs_server = session_multihost.master[0].external_hostname
    client_ip = session_multihost.client[0].ip
    server = sssdTools(session_multihost.master[0])
    bkup = 'cp -af /etc/exports /etc/exports.backup'
    session_multihost.master[0].run_command(bkup)
    server.export_nfs_fs(share_list, client_ip)
    start_nfs = 'systemctl start nfs-server'
    try:
        session_multihost.master[0].run_command(start_nfs)
    except subprocess.CalledProcessError:
        pytest.fail("Unable to start nfs server")
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ds_suffix = 'dc=example,dc=test'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    ret = ldap_inst.add_map(request.param, 'auto.direct',
                            nfs_server, request.param, ds_suffix)
    assert ret == 'Success'

    def remove_project():
        """ Remove the nisproject from map """
        stop_autofs = 'systemctl stop autofs'
        session_multihost.client[0].run_command(stop_autofs)
        ret = ldap_inst.delete_map(request.param, 'auto.direct', ds_suffix)
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


@pytest.fixture(scope='function')
def create_etc_exports(session_multihost, request):
    """ Remove and recreate /etc/exports """
    remove_exports = 'rm -f /etc/exports'
    session_multihost.master[0].run_command(remove_exports)
    # create an empty /etc/exports
    create_exports_file = 'touch /etc/exports'
    session_multihost.master[0].run_command(create_exports_file)


@pytest.fixture(scope='function')
def indirect_nismaps(session_multihost, request, create_etc_exports):
    """ Create indirect map and add 20 map keys.
        Also create /projects/foo1 to /projects/foo20
        Restart nfs server
    """
    nfs_server = session_multihost.master[0].external_hostname
    client_ip = session_multihost.client[0].ip
    server = sssdTools(session_multihost.master[0])
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    server.export_nfs_fs(['/projects'], client_ip)
    for i in range(1, 20):
        map_keys = ['foo%d' % (i)]
        server_path = '/projects/foo%d' % (i)
        ret = ldap_inst.add_map(map_keys[0], 'auto.idmtest',
                                nfs_server, server_path, ds_suffix)
        permissions = '(rw,sync)'
        path_list = ['/projects/%s' % map_keys[0]]
        server.export_nfs_fs(path_list, client_ip, permissions)
        assert ret == 'Success'
    start_nfs = 'systemctl start nfs-server'
    export_fs = 'exportfs -a'
    try:
        session_multihost.master[0].run_command(export_fs)
    except subprocess.CalledProcessError:
        pytest.fail("Unable to start nfs server")
    try:
        session_multihost.master[0].run_command(start_nfs)
    except subprocess.CalledProcessError:
        pytest.fail("Unable to start nfs server")

    def remove_bulk_maps():
        """ Remove the nisproject from map """
        stop_autofs = 'systemctl stop autofs'
        session_multihost.client[0].run_command(stop_autofs)
        for i in range(1, 20):
            map_keys = ['foo%d' % (i)]
            ret = ldap_inst.delete_map(map_keys[0], 'auto.idmtest', ds_suffix)
            assert ret == 'Success'
        # remove /projects
        remove_projects = 'rm -rf /projects'
        session_multihost.master[0].run_command(remove_projects)
        restore = 'cp -f /etc/exports.backup /etc/exports'
        session_multihost.master[0].run_command(restore)
        stop_nfs = "systemctl stop nfs-server"
        try:
            session_multihost.master[0].run_command(stop_nfs)
        except subprocess.CalledProcessError:
            pytest.fail("failed to stop nfs-server")
    request.addfinalizer(remove_bulk_maps)


@pytest.fixture(scope="function")
def set_autofs_search_base(session_multihost, request):
    """ Enable autofs service """
    client = sssdTools(session_multihost.client[0])
    client.backup_sssd_conf()
    domain_name = client.get_domain_section_name()
    domain_section = 'domain/{}'.format(domain_name)
    autofs_dn = "ou=automount,%s" % (ds_suffix)
    sssd_params = {'ldap_autofs_search_base': autofs_dn}
    client.sssd_conf(domain_section, sssd_params)

    def remove_autofs_search_base():
        """ Remove autofs search base """
        client.restore_sssd_conf()
        client.clear_sssd_cache()
    request.addfinalizer(remove_autofs_search_base)


@pytest.fixture(scope="function")
def set_ldap_uri(session_multihost, request):
    """ Replace ldaps uri with ldap uri """
    tools = sssdTools(session_multihost.client[0])
    ldap_uri = 'ldap://%s' % session_multihost.master[0].sys_hostname
    ldap_params = {'ldap_uri': ldap_uri}
    tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
    session_multihost.client[0].service_sssd('restart')

    def restore_ldaps_uri():
        """ Restore ldaps uri """
        ldap_uri = 'ldaps://%s' % session_multihost.master[0].sys_hostname
        ldap_params = {'ldap_uri': ldap_uri}
        tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
        session_multihost.client[0].service_sssd('restart')
    request.addfinalizer(restore_ldaps_uri)


@pytest.fixture(scope="function")
def create_ssh_keys(session_multihost, request):
    """ Create ssh keys """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    keygen_cmd = "ssh-keygen -q -t rsa -b 2048 -N '' -f /tmp/id_rsa -C ''"
    session_multihost.client[0].run_command(keygen_cmd)
    get_pub_key = 'cat /tmp/id_rsa.pub'
    cmd = session_multihost.client[0].run_command(get_pub_key)
    ssh_key = cmd.stdout_text.strip().split('\n')[0]
    user_dn = "uid=foo1,ou=People,%s" % ds_suffix
    add_objectclass = [(ldap.MOD_ADD, 'objectClass', [b'ldapPublicKey'])]
    (ret, _) = ldap_inst.modify_ldap(user_dn, add_objectclass)
    assert ret == 'Success'
    add_pubkey = [(ldap.MOD_ADD, 'sshPublicKey', [ssh_key.encode('utf-8')])]
    (ret, _) = ldap_inst.modify_ldap(user_dn, add_pubkey)
    assert ret == 'Success'

    def remove_keys():
        """ Remove ssh key file """
        remove_ssh = 'rm -f /tmp/id_rsa*'
        session_multihost.client[0].run_command(remove_ssh)
    request.addfinalizer(remove_keys)


@pytest.fixture(scope='function')
def enable_multiple_responders(session_multihost, request):
    """ Enable multiple responders to sssd services """
    session_multihost.client[0].service_sssd('stop')
    tools = sssdTools(session_multihost.client[0])
    services = 'nss, pam, sudo, autofs, ssh, pac, ifp'
    srv_list = [x.strip() for x in services.split(',')]
    sssd_params = {'services': services}
    tools.sssd_conf('sssd', sssd_params, action='update')
    param = {'debug_level': '9'}
    for new_sec in srv_list:
        tools.sssd_conf(new_sec, param)
    ret = session_multihost.client[0].service_sssd('start')
    time.sleep(10)
    assert ret == 0

    def restore_sssd_conf():
        """ Restore sssd.conf """
        services = 'nss, pam'
        sssd_params = {'services': services}
        tools.sssd_conf('sssd', sssd_params, action='update')
    request.addfinalizer(restore_sssd_conf)


@pytest.fixture(scope='function')
def sssd_sudo_conf(session_multihost, request):
    """ Configure basic sudo parameters in sssd.conf """
    tools = sssdTools(session_multihost.client[0])
    session_multihost.client[0].service_sssd('stop')
    tools.remove_sss_cache('/var/lib/sss/db/')
    tools.remove_sss_cache('/var/log/sssd')
    section = "sssd"
    sssd_params = {'services': 'nss, pam, sudo'}
    tools.sssd_conf(section, sssd_params)
    sudo_base = f'ou=sudoers,{ds_suffix}'
    params = {'ldap_sudo_search_base': sudo_base,
              'sudo_provider': 'ldap'}
    domain_section = f'domain/{ds_instance_name}'
    tools.sssd_conf(domain_section, params, action='update')
    session_multihost.client[0].service_sssd('start')

    def restore_sssd_conf():
        """ Restore sssd.conf """
        services = 'nss, pam'
        sssd_params = {'services': services}
        tools.sssd_conf('sssd', sssd_params)
        tools.sssd_conf(domain_section, params, action='delete')
    request.addfinalizer(restore_sssd_conf)


@pytest.fixture(scope='function')
def sudo_rule(session_multihost, request):
    """ Create sudoers ldap entries """
    ldap_uri = f'ldap://{session_multihost.master[0].sys_hostname}'
    sudo_ou = f'ou=sudoers,{ds_suffix}'
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    try:
        ldap_inst.org_unit('sudoers', ds_suffix)
    except LdapException:
        pytest.fail("already exist or failed to add sudo ou ")
    sudo_options = ["!requiretty", "!authenticate"]
    sudo_cmd = '/usr/bin/head'
    sudo_user = 'foo1'
    rule_dn = f'cn={sudo_cmd},{sudo_ou}'
    try:
        ldap_inst.add_sudo_rule(rule_dn, 'ALL', '/usr/bin/head',
                                sudo_user, sudo_options)
    except LdapException:
        pytest.fail(f"Failed to add sudo rule {rule_dn}")
    else:
        extra_user = 'foo2'
        add_extra = [(ldap.MOD_ADD, 'sudoUser',
                     extra_user.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(rule_dn, add_extra)
        assert ret == 'Success'

    def del_sudo_rule():
        """ Delete sudo rule  """
        rule_dn = f'cn={sudo_cmd},{sudo_ou}'
        (_, _) = ldap_inst.del_dn(rule_dn)
        (ret, _) = ldap_inst.del_dn(sudo_ou)
        assert ret == 'Success'
    request.addfinalizer(del_sudo_rule)


testdata = [
    [(datetime.today() - timedelta(days=1)).strftime('%Y%m%d%H') + 'Z',
     'sudoNotBefore'],
    [(datetime.today() + timedelta(days=1)).strftime('%Y%m%d%H') + 'Z',
     'sudoNotAfter']]


@pytest.fixture(ids=["sudoNotBefore", "sudoNotAfter"], params=testdata)
def timed_sudoers(session_multihost, request):
    """ Creates a time sudoers ldap entries """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    sudo_ou = 'ou=sudoers, %s' % ds_suffix
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    try:
        ldap_inst.org_unit('sudoers', ds_suffix)
    except LdapException:
        pytest.fail("already exist or failed to add sudo ou ")
    sudo_options = ["!requiretty", "!authenticate"]
    rule_dn = "cn=%s, %s" % (request.param[1], sudo_ou)
    try:
        ldap_inst.add_sudo_rule(rule_dn, 'ALL', '/usr/bin/head',
                                'foo1', sudo_options)
    except LdapException:
        pytest.fail("Failed to add sudo rule %s" % rule_dn)
    else:
        sudotime = request.param[0]
        add_attr = [(ldap.MOD_ADD, request.param[1],
                     sudotime.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(rule_dn, add_attr)
        assert ret == 'Success'

    def del_sudo_rule():
        """ Delete sudo rule  """
        rule_dn = 'cn=%s,%s' % (request.param[1], sudo_ou)
        (_, _) = ldap_inst.del_dn(rule_dn)
        (ret, _) = ldap_inst.del_dn(sudo_ou)
        assert ret == 'Success'
    request.addfinalizer(del_sudo_rule)

# ====================  Class Scoped Fixtures ================


@pytest.fixture(scope='class')
def setupds(session_multihost, request):
    """ Setup Directory Server """
    server_list = [session_multihost.master[0].sys_hostname]
    pki_inst = PkiTools()
    try:
        certdb = pki_inst.createselfsignedcerts(server_list)
    except PkiLibException:
        pytest.fail("Failed to create CA")
    master = DirSrvWrap(session_multihost.master[0],
                        client_obj=session_multihost.client[0],
                        ssl=True,
                        ssldb=certdb)
    master.create_ds_instance(ds_instance_name, ds_suffix)

    def removeds():
        """ Remove Directory server instance """
        master.remove_ds_instance(ds_instance_name)
    request.addfinalizer(removeds)
    return master


@pytest.fixture(scope='class')
def multipleds(session_multihost, request):
    """ Setup Multiple Directory Servers """
    server_list = [session_multihost.master[0].sys_hostname,
                   session_multihost.master[1].sys_hostname]
    pki_inst = PkiTools()
    try:
        certdb = pki_inst.createselfsignedcerts(server_list)
    except PkiLibException:
        pytest.fail("Failed to create CA")
    print(certdb)
    dsobjlist = []
    for idx in range(2):
        host = session_multihost.master[idx]
        dsobj = DirSrvWrap(host,
                           client_obj=session_multihost.client[0],
                           ssl=True,
                           ssldb=certdb)
        dsobjlist.append(dsobj)
        inst_name = 'example%d' % idx
        suffix = 'dc=example%d,dc=test' % idx
        dsobj.create_ds_instance(inst_name, suffix)

    def removeds():
        """ Remove DS Instances """
        idx = 0
        for dsinst in dsobjlist:
            instname = 'example%d' % idx
            dsinst.remove_ds_instance(instname)
            idx += 1

    request.addfinalizer(removeds)


@pytest.fixture(scope='class')
def multipleds_failover(session_multihost, request):
    """ Setup Multiple Directory Servers for failover"""
    server_list = [session_multihost.master[0].sys_hostname,
                   session_multihost.master[1].sys_hostname]
    pki_inst = PkiTools()
    try:
        certdb = pki_inst.createselfsignedcerts(server_list)
    except PkiLibException:
        pytest.fail("Failed to create CA")
    print(certdb)
    dsobjlist = []
    for idx in range(2):
        host = session_multihost.master[idx]
        dsobj = DirSrvWrap(host,
                           client_obj=session_multihost.client[0],
                           ssl=True,
                           ssldb=certdb)
        dsobjlist.append(dsobj)
        inst_name = 'example'
        suffix = 'dc=example,dc=test'
        dsobj.create_ds_instance(inst_name, suffix)

    def removeds():
        """ Remove DS Instances """
        for dsinst in dsobjlist:
            instname = 'example'
            dsinst.remove_ds_instance(instname)
    request.addfinalizer(removeds)


@pytest.fixture(scope='class')
# pylint: disable=unused-argument
def posix_users_multidomain(session_multihost, multipleds):
    """ Create posix users groups for multidomain """
    suffix = ['p', 'q']
    id_suffix = ['20', '30']
    for idx in range(2):
        host = session_multihost.master[idx]
        ldap_uri = 'ldap://%s' % (host.sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ds_suffix = 'dc=example%d,dc=test' % idx
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        for i in range(20):
            uid = "{:02d}".format(i)
            user_info = {'cn': '%suser%d' % (suffix[idx], i),
                         'uid': '%suser%d' % (suffix[idx], i),
                         'uidNumber': '%s%s' % (id_suffix[idx], uid),
                         'gidNumber': '%s%s' % (id_suffix[idx], uid)}
            ldap_inst.posix_user("ou=People", ds_suffix, user_info)
            user = '%suser%d' % (suffix[idx], i)
            memberdn = 'uid=%s,ou=People,%s' % (user, ds_suffix)
            group_info = {'cn': '%sgroup%d' % (suffix[idx], i),
                          'gidNumber': '%s%s' % (id_suffix[idx], uid),
                          'uniqueMember': memberdn}
            try:
                ldap_inst.posix_group("ou=Groups", ds_suffix, group_info)
            except LdapException:
                raise
        duplicate_group = {'cn': 'duplicate',
                           'gidNumber': '%s%s' % (id_suffix[idx], uid),
                           'uniqueMember': memberdn}
        try:
            ldap_inst.posix_group("ou=Groups", ds_suffix, duplicate_group)
        except LdapException:
            raise


@pytest.fixture(scope='class')
def sssdproxyldap(session_multihost, request):
    """ Copy sssd proxy pam ldap config file """
    cwd = os.path.dirname(os.path.abspath(__file__))
    remote = '/etc/pam.d/sssdproxyldap'
    source = posixpath.join(cwd, 'sssdproxyldap')
    session_multihost.client[0].transport.put_file(source, remote)

    def removeproxyldap():
        """ Remove sssd proxy pam ldap config file """
        cmd = 'rm -f %s' % remote
        session_multihost.client[0].run_command(cmd)
    request.addfinalizer(removeproxyldap)


@pytest.fixture(scope='class')
def install_nslcd(session_multihost, request):
    """ Install nss-pam-ldapd Configure nslcd.conf """
    client = session_multihost.client[0]
    client.run_command("yum install -y nss-pam-ldapd")
    execute_cmd(session_multihost, "echo 'uid nslcd' > /etc/nslcd.conf")
    execute_cmd(session_multihost, "echo 'gid ldap' >> /etc/nslcd.conf")
    execute_cmd(session_multihost, f"echo 'uri ldap://"
                f"{session_multihost.master[0].ip}'"
                f" >> /etc/nslcd.conf")
    execute_cmd(session_multihost, f"echo 'base {ds_suffix}' >> "
                f"/etc/nslcd.conf")
    execute_cmd(session_multihost, "systemctl restart nslcd")

    def restore_install_nslcd():
        """ Restore"""
        client.run_command("rm -vf /etc/nslcd.conf")
        execute_cmd(session_multihost, "systemctl stop nslcd")

    request.addfinalizer(restore_install_nslcd)


@pytest.fixture(scope='class')
def sssdproxyldap_test(session_multihost, request):
    """ Configure  sssdproxyldap
        Configure  sssd.conf
        Transport sssdproxyldap.sh to client machine
        configure password for ldap user
    """
    master = session_multihost.master[0]
    client = session_multihost.client[0]
    tools = sssdTools(session_multihost.client[0])
    domain_name = tools.get_domain_section_name()
    domain_params = {'proxy_pam_target': 'sssdproxyldap',
                     'id_provider': 'proxy',
                     'proxy_lib_name': 'ldap'}
    tools.sssd_conf('domain/' + domain_name, domain_params)
    file_location = '/script/sssdproxyldap.sh'
    client.transport.put_file(os.path.dirname(os.path.abspath(__file__))
                              + file_location,
                              '/tmp/sssdproxyldap.sh')
    execute_cmd(session_multihost, "chmod 755 /tmp/sssdproxyldap.sh")
    master.run_command("kadmin.local -q "
                       "'addprinc -pw Secret123 "
                       "foo2@example1'")
    tools.clear_sssd_cache()

    def restore_sssdproxyldap_test():
        """ Restore"""
        client.run_command("rm -vf /tmp/sssdproxyldap.sh")
    request.addfinalizer(restore_sssdproxyldap_test)


@pytest.fixture(scope='class')
def nslcd(session_multihost, request):
    """ Setup nslcd.conf """
    ldap_uri = session_multihost.master[0].sys_hostname
    session_multihost.client[0].run_command("yum install "
                                            "-y nss-pam-ldapd",
                                            raiseonerr=False)
    basedn = 'dc=example0,dc=test'
    contents = '''uid nslcd
gid ldap
uri ldap://%s
base %s
''' % (ldap_uri, basedn)
    session_multihost.client[0].put_file_contents('/etc/nslcd.conf', contents)
    start_nslcd = 'systemctl start nslcd'
    session_multihost.client[0].run_command(start_nslcd)

    def remove_nslcd():
        """ Remove nslcd """
        cmd = 'rm -f /etc/nslcd.conf'
        stop_nslcd = 'systemctl stop nslcd'
        session_multihost.client[0].run_command(stop_nslcd)
        session_multihost.client[0].run_command(cmd)
    request.addfinalizer(remove_nslcd)


@pytest.fixture(scope='class')
def template_sssdconf(session_multihost, request):
    """ Copy template sssd conf for multidomain tests """
    cwd = os.path.dirname(os.path.abspath(__file__))
    remote = SSSD_DEFAULT_CONF
    source = posixpath.join(cwd, 'sssd_multidomain.conf')
    session_multihost.client[0].transport.put_file(source, remote)
    tools = sssdTools(session_multihost.client[0])
    tools.fix_sssd_conf_perms()


    def remove_template():
        """ Remove template sssd.conf """
        cmd = f'rm -f {SSSD_DEFAULT_CONF}'
        session_multihost.client[0].run_command(cmd)
    request.addfinalizer(remove_template)


@pytest.fixture(scope="class")
def setup_kerberos(session_multihost, request):
    """ Setup kerberos """
    tools = sssdTools(session_multihost.master[0])
    backup_krb5_conf = 'cp -f /etc/krb5.conf /etc/krb5.conf.orig'
    session_multihost.master[0].run_command(backup_krb5_conf)
    tools.config_etckrb5('EXAMPLE.TEST')
    tools.enable_kcm()
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    krb.krb_setup_new()

    def remove_kerberos():
        """ Remove kerberos instance """
        krb.destroy_krb5server()
        remove_keytab = 'rm -f /etc/krb5.keytab'
        session_multihost.master[0].run_command(remove_keytab)
        restore_krb5 = 'cp -f /etc/krb5.conf.orig /etc/krb5.conf'
        session_multihost.master[0].run_command(restore_krb5)
    request.addfinalizer(remove_kerberos)


@pytest.fixture(scope="class")
def setup_ds_sasl(session_multihost, request):
    """  Enable sasl on Directory Server  """
    ds_hostname = session_multihost.master[0].sys_hostname
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')
    krb.add_principal(p_type=None, service='ldap', service_name=ds_hostname)
    ldap_princ = "ldap/%s" % ds_hostname
    krb.add_remove_keytab(ldap_princ, "/etc/dirsrv/krb5.keytab", 'add')
    keytab_perms = "chown dirsrv.dirsrv /etc/dirsrv/krb5.keytab"
    session_multihost.master[0].run_command(keytab_perms)
    cmd = "echo -e KRB5_KTNAME=/etc/dirsrv/krb5.keytab"\
          " >> /etc/sysconfig/dirsrv-%s" % ds_instance_name
    session_multihost.master[0].run_command(cmd)
    # restart dirsrv
    restart_ds = 'systemctl restart dirsrv@%s' % ds_instance_name
    session_multihost.master[0].run_command(restart_ds)

    def remove_ds_sasl():
        """ Remove keytab file """
        remove_ds_keytab = 'rm -f /etc/dirsrv/krb5.keytab'
        session_multihost.master[0].run_command(remove_ds_keytab)
    request.addfinalizer(remove_ds_sasl)


@pytest.fixture(scope='class')
def setup_sssd(session_multihost, setupds,  # pylint: disable=unused-argument
               setup_kerberos, request):  # pylint: disable=unused-argument
    """ Configure sssd.conf """
    backup_krb5 = "cp -f /etc/krb5.conf /etc/krb5.conf.orig"
    session_multihost.client[0].run_command(backup_krb5)
    tools = sssdTools(session_multihost.client[0])
    krb5_server = session_multihost.master[0].sys_hostname
    tools.config_etckrb5('EXAMPLE.TEST', krb5_server)
    tools.enable_kcm()
    ds_host = session_multihost.master[0].sys_hostname
    sssd_params = {'domains': ds_instance_name}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = 'domain/%s' % ds_instance_name
    ldap_uri = 'ldaps://%s' % (ds_host)
    domain_params = {'ldap_search_base': ds_suffix,
                     'id_provider': 'ldap',
                     'auth_provider': 'ldap',
                     'ldap_user_home_directory': "/home/%u",
                     'ldap_uri': ldap_uri,
                     'ldap_tls_cacert': '/etc/openldap/cacerts/cacert.pem',
                     'use_fully_qualified_names': 'True',
                     'debug_level': '9'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()
    start_sssd = 'systemctl start sssd'
    session_multihost.client[0].run_command(start_sssd)

    def removesssd():
        """ Remove sssd configuration """
        stop_sssd = 'systemctl stop sssd'
        session_multihost.client[0].run_command(stop_sssd)
        removeconf = 'rm -f %s' % (SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(removeconf)
        # revert the krb5.conf
        restore_krb5 = 'cp -f /etc/krb5.conf.orig /etc/krb5.conf'
        session_multihost.client[0].run_command(restore_krb5)
    request.addfinalizer(removesssd)


@pytest.fixture(scope='class')
def setup_sssd_krb(session_multihost, setup_sssd):
    """ Configure sssd.conf with auth_provider = krb5 """
    tools = sssdTools(session_multihost.client[0])
    domain_section = 'domain/%s' % ds_instance_name
    krb5_server = session_multihost.master[0].sys_hostname
    domain_params = {'auth_provider': 'krb5',
                     'krb5_realm': 'EXAMPLE.TEST',
                     'krb5_server': krb5_server}
    tools.sssd_conf(domain_section, domain_params)
    restart_sssd = 'systemctl restart sssd'
    session_multihost.client[0].run_command(restart_sssd,
                                            raiseonerr=False)


@pytest.fixture(scope='class')
def create_host_keytab(session_multihost, request):
    """ Configure host keytab on client """
    # delete keytab file if it exists
    delete_keytab = "rm -f /etc/krb5.keytab"
    session_multihost.client[0].run_command(delete_keytab, raiseonerr=False)
    client_host = session_multihost.client[0].sys_hostname
    add_principal = "add_principal -clearpolicy"\
                    " -randkey host/%s" % client_host
    cmd1 = "kadmin -p root/admin -w Secret123 -q '%s'" % add_principal
    session_multihost.client[0].run_command(cmd1, raiseonerr=False)
    ktadd = 'ktadd -k /etc/krb5.keytab host/%s' % client_host
    cmd2 = "kadmin -p root/admin -w Secret123 -q '%s'" % ktadd
    session_multihost.client[0].run_command(cmd2)

    def remove_keytab():
        """ Remove keytab """
        session_multihost.client[0].run_command(delete_keytab)
    request.addfinalizer(remove_keytab)


@pytest.fixture(scope='class')
def setup_sssd_gssapi(session_multihost, setup_sssd,
                      setup_ds_sasl, create_host_keytab):
    """ Configure sssd.conf  with sasl_mech gssapi """
    tools = sssdTools(session_multihost.client[0])
    domain_section = 'domain/%s' % ds_instance_name
    krb5_server = session_multihost.master[0].sys_hostname
    ldap_uri = 'ldap://%s' % (krb5_server)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    domain_params = {'auth_provider': 'krb5',
                     'ldap_sasl_mech': 'GSSAPI',
                     'krb5_realm': 'EXAMPLE.TEST',
                     'use_fully_qualified_names': 'False',
                     'krb5_server': krb5_server}
    host_info = {'cn': 'host/%s' % session_multihost.client[0].sys_hostname,
                 'uid': 'host/%s' % session_multihost.client[0].sys_hostname,
                 'uidNumber': '19999999',
                 'gidNumber': '14564100'}
    ldap_inst.posix_user("ou=People", "%s" % ds_suffix, host_info)
    tools.sssd_conf(domain_section, domain_params)
    session_multihost.client[0].service_sssd('restart')


@pytest.fixture(scope='class')
def setup_sssd_failover(session_multihost, request):
    """ Configure sssd.conf """
    tools = sssdTools(session_multihost.client[0])
    stop_sssd = 'systemctl stop sssd'
    session_multihost.client[0].run_command(stop_sssd)
    ds_host1 = session_multihost.master[0].sys_hostname
    ds_host2 = session_multihost.master[1].sys_hostname
    sssd_params = {'domains': ds_instance_name}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = 'domain/%s' % ds_instance_name
    ldap_uri = 'ldaps://%s, ldaps://%s' % (ds_host1, ds_host2)
    domain_params = {'ldap_search_base': ds_suffix,
                     'id_provider': 'ldap',
                     'auth_provider': 'ldap',
                     'ldap_user_home_directory': "/home/%u",
                     'ldap_uri': ldap_uri,
                     'ldap_tls_cacert': '/etc/openldap/cacerts/cacert.pem',
                     'use_fully_qualified_names': 'True',
                     'debug_level': '9'}
    tools.sssd_conf(domain_section, domain_params)
    start_sssd = 'systemctl restart sssd'
    session_multihost.client[0].run_command(start_sssd)

    def removesssd():
        """ Remove sssd configuration """
        stop_sssd = 'systemctl stop sssd'
        session_multihost.client[0].run_command(stop_sssd)
        removeconf = 'rm -f %s' % (SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(removeconf)
    request.addfinalizer(removesssd)


@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests
    :param obj session_multihost: multihost object
    :return obj session_multihost: return multihost object
    """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope='class')
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


@pytest.fixture(scope='class')
def create_posix_usersgroups_failover(session_multihost):
    """ Create posix user and groups """
    for idx in range(2):
        ldap_uri = 'ldap://%s' % (session_multihost.master[idx].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        for i in range(10):
            user_info = {'cn': 'foo%d' % i,
                         'uid': 'foo%d' % i,
                         'uidNumber': '1458310%d' % i,
                         'gidNumber': '14564100'}
            ldap_inst.posix_user("ou=People", "dc=example,dc=test", user_info)

        memberdn = 'uid=%s,ou=People,dc=example,dc=test' % ('foo0')
        group_info = {'cn': 'ldapusers',
                      'gidNumber': '14564100',
                      'uniqueMember': memberdn}
        try:
            ldap_inst.posix_group("ou=Groups", "dc=example,dc=test",
                                  group_info)
        except LdapException:
            assert False

        group_dn = 'cn=ldapusers,ou=Groups,dc=example,dc=test'
        for i in range(1, 10):
            user_dn = 'uid=foo%d,ou=People,dc=example,dc=test' % i
            add_member = [(ldap.MOD_ADD, 'uniqueMember',
                           user_dn.encode('utf-8'))]
            (ret, _) = ldap_inst.modify_ldap(group_dn, add_member)
            assert ret == 'Success'


@pytest.fixture(scope='class')
def create_posix_usersgroups_autoprivategroups(session_multihost):
    """ Create posix user and groups for autoprivategroup fixture"""
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    for i in range(10):
        user_info = {'cn': 'foobar%d' % i,
                     'uid': 'foobar%d' % i,
                     'uidNumber': '1234560%d' % i,
                     'gidNumber': '1234560%d' % i}
        try:
            ldap_inst.posix_user("ou=People", ds_suffix, user_info)
        except LdapException:
            assert False
    user_info = {'cn': 'foobar11',
                 'uid': 'foobar11',
                 'uidNumber': '14583103',
                 'gidNumber': '14444444'}
    try:
        ldap_inst.posix_user("ou=People", ds_suffix, user_info)
    except LdapException:
        assert False
    memberdn = 'uid=%s,ou=People,dc=example,dc=test' % ('foobar0')
    for i in range(4):
        group_info = {'cn': 'foobar%d' % i,
                      'gidNumber': '1234560%d' % i,
                      'uniqueMember': memberdn}
        try:
            ldap_inst.posix_group("ou=Groups", ds_suffix, group_info)
        except LdapException:
            assert False
    memberdn = 'uid=%s,ou=People,dc=example,dc=test' % ('foobar11')
    group_info = {'cn': 'foobar11',
                  'gidNumber': '14444444',
                  'uniqueMember': memberdn}
    try:
        ldap_inst.posix_group("ou=Groups", ds_suffix, group_info)
    except LdapException:
        assert False
    group_dn = 'cn=foobar0,ou=Groups,%s' % ds_suffix
    user_dn = 'uid=foobar1,ou=People,%s' % ds_suffix
    add_member = [(ldap.MOD_ADD, 'uniqueMember', user_dn.encode('utf-8'))]
    (ret, _) = ldap_inst.modify_ldap(group_dn, add_member)
    assert ret == 'Success'
    group_dn = 'cn=foobar0,ou=Groups,%s' % ds_suffix
    modify_gid = [(ldap.MOD_REPLACE, 'gidNumber', [b'20000'])]
    (ret, return_value) = ldap_inst.modify_ldap(group_dn, modify_gid)
    if not return_value:
        raise LdapException(
            'fail to modify gid, Error:%s' % (ret))
    else:
        print('modified gid')


@pytest.fixture(scope='class')
def netgroups(session_multihost):
    """ Create netgroup users """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    ldap_inst.org_unit('Netgroups', ds_suffix)
    for idx in range(10):
        nisNetgroupTriple = "(,foo%d, %s)" % (idx, krb_realm)
        netgroup_dn = 'cn=netgroup_%d,ou=Netgroups,%s' % (idx, ds_suffix)
        ldap_inst.create_netgroup(netgroup_dn, nisNetgroupTriple)
    nisNetgroupTriple = "(Host1.example.com,User1,example.com)"
    netgroup_dn = 'cn=NetGroup_CS1,ou=Netgroups,%s' % (ds_suffix)
    ldap_inst.create_netgroup(netgroup_dn, nisNetgroupTriple)
    user = "cn=NetGroup_CS1,ou=Netgroups,dc=example,dc=test"
    add_member = [(ldap.MOD_ADD, 'cn',
                   "NetGroup_CS1_Alias".encode('utf-8'))]
    ldap_inst.modify_ldap(user, add_member)


@pytest.fixture(scope='class')
def write_journalsssd(session_multihost, request):
    """ Creating /etc/sysconfig/sssd and start systemd-journald service"""
    contents = "DEBUG_LOGGER=--logger=journald"
    session_multihost.client[0].put_file_contents('/etc/sysconfig/sssd',
                                                  contents)
    restart_journald = 'systemctl restart systemd-journald'
    session_multihost.client[0].run_command(restart_journald)

    def remove_journalsssd():
        """ Remove  /etc/sysconfig/sssd"""
        cmd = 'rm -f /etc/sysconfig/sssd'
        restart_journald = 'systemctl restart systemd-journald'
        restart_sssd = 'systemctl restart sssd'
        session_multihost.client[0].run_command(cmd)
        session_multihost.client[0].run_command(restart_journald)
        session_multihost.client[0].run_command(restart_sssd)
    request.addfinalizer(remove_journalsssd)


@pytest.fixture(scope="class")
def enable_autofs_schema(session_multihost, request):
    """ Enable autofs schema(rfc2307) to Windows AD.
    :param obj session_multihost: multihost object
    :param obj request: pytest request object
    """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    ldap_inst.autofs_nis_schema(ds_suffix)


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
    sssd_params = {'autofs_provider': 'ldap',
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
def default_sssd(session_multihost, request):
    """ Setup default sssd.conf """
    contents = '''[sssd]
services = nss, pam '''
    session_multihost.client[0].put_file_contents('%s' % (SSSD_DEFAULT_CONF),
                                                  contents)
    tools = sssdTools(session_multihost.client[0])
    tools.fix_sssd_conf_perms()

    def remove_default_sssd():
        """ Remove default sssd.conf """
        session_multihost.client[0].service_sssd('stop')
        cmd = 'rm -f %s' % SSSD_DEFAULT_CONF
        session_multihost.client[0].run_command(cmd)
    request.addfinalizer(remove_default_sssd)


@pytest.fixture(scope='class')
def krb_connection_timeout(
        session_multihost,
        create_host_user,
        request):
    """ Create necessary principals and keytabs for the test.
    :param obj session_multihost: multihost object
    :param obj create_host_user: to create user for SASL with GSSAPI
     authentication
    :param obj request: pytest request object
    """
    krb = krb5srv(session_multihost.master[0], 'EXAMPLE.TEST')

    princ = "ldap/%s" % session_multihost.master[0].sys_hostname
    krb.add_principal(None, None, 'Secret123', 'ldap', '%s@EXAMPLE.TEST' %
                      session_multihost.master[0].sys_hostname)
    keytab = krb.add_remove_keytab(princ, None, 'add')
    if keytab is True:
        assert True
    else:
        assert False
    krb.add_principal(None, None, 'Secret123', 'host', '%s@EXAMPLE.TEST' %
                      session_multihost.client[0].sys_hostname)
    princ = "host/%s" % session_multihost.client[0].sys_hostname
    keytab = krb.add_remove_keytab(princ,
                                   "/opt/sssd_client_valid.keytab", 'add')
    if keytab is True:
        assert True
    else:
        assert False
    chmod_cmd = "chmod 777 /etc/krb5.keytab"
    session_multihost.master[0].run_command(chmod_cmd)
    restore_selinux = "restorecon -v /etc/krb5.keytab"
    session_multihost.master[0].run_command(restore_selinux)
    # Setup client machine
    session_multihost.master[0].transport.get_file(
        "/opt/sssd_client_valid.keytab",
        "/tmp/sssd_client_valid.keytab")
    session_multihost.client[0].transport.put_file(
        "/tmp/sssd_client_valid." "keytab", "/etc/krb5.keytab")
    session_multihost.client[0].run_command(restore_selinux)
    sssd_tools = sssdTools(session_multihost.client[0])
    sssd_tools.remove_sss_cache('/var/lib/sss/db/')
    sssd_tools.fix_sssd_conf_perms()


@pytest.fixture(scope='class')
def create_host_user(session_multihost):
    """ Add host user for SASL with GSSAPI authentication
    :param obj session_multihost: multihost object
    """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    user_info = {'cn': 'host/%s' % session_multihost.client[0].sys_hostname,
                 'uid': 'host/%s' % session_multihost.client[0].sys_hostname,
                 'uidNumber': '9003',
                 'gidNumber': '9003'}
    ldap_inst.posix_user("ou=People", "dc=example,dc=test", user_info)
    group_dn = 'cn=ldapusers,ou=Groups,dc=example,dc=test'
    uid = 'uid=host/%s' % session_multihost.client[0].sys_hostname
    user_dn = '%s,ou=People,dc=example,dc=test' % uid
    add_member = [(ldap.MOD_ADD, 'uniqueMember', user_dn.encode('utf-8'))]
    (ret, _) = ldap_inst.modify_ldap(group_dn, add_member)
    assert ret == 'Success'


@pytest.fixture(scope='class')
def enable_password_check_syntax(session_multihost, request):
    """ Enable passwordCheckSyntax """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_obj = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    mod_dn1 = 'cn=config'
    add_pass_check = [(ldap.MOD_ADD, 'passwordCheckSyntax', [b'on'])]
    (ret, _) = ldap_obj.modify_ldap(mod_dn1, add_pass_check)
    assert ret == 'Success'
    restart_service = 'systemctl restart dirsrv@%s' % ds_instance_name
    session_multihost.master[0].run_command(restart_service)


@pytest.fixture(scope='class')
def enable_ssh_schema(session_multihost, request):
    """ Enable OpenSSH lpk  schema in directory server """
    cwd = os.path.dirname(os.path.abspath(__file__))
    split_cwd = cwd.split('/')
    idx = split_cwd.index('multihost')
    path_list = split_cwd[:idx + 1]
    sssd_qe_path = '/'.join(path_list)
    data_path = "%s/data" % sssd_qe_path
    filename = '98openssh-ldap.ldif'
    schema_path = '/etc/dirsrv/slapd-%s/schema' % ds_instance_name
    remote_file_path = posixpath.join(schema_path, filename)
    source_file_path = posixpath.join(data_path, filename)
    chown = 'chown nobody.nobody %s' % remote_file_path
    chmod = 'chmod 660 %s' % remote_file_path
    session_multihost.master[0].transport.put_file(source_file_path,
                                                   remote_file_path)
    session_multihost.master[0].run_command(chown)
    session_multihost.master[0].run_command(chmod)
    restart_ds = 'systemctl restart dirsrv@%s' % ds_instance_name
    session_multihost.master[0].run_command(restart_ds)


@pytest.fixture(scope='class')
def setup_sshd_authorized_keys(session_multihost, request):
    """ Configuring OpenSSH to Use SSSD for User Keys """
    sshd_conf = '/etc/ssh/sshd_config'
    sshd_conf_bkup = '/etc/ssh/sshd_config.orig'
    bkup_cmd = 'cp %s %s' % (sshd_conf, sshd_conf_bkup)
    session_multihost.client[0].run_command(bkup_cmd)
    session_multihost.client[0].transport.get_file(sshd_conf,
                                                   '/tmp/sshd_config')
    with open('/tmp/sshd_config', 'a+') as conf:
        conf.write('\nAuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys')
        conf.write('\nAuthorizedKeysCommandUser nobody\n')
    session_multihost.client[0].transport.put_file('/tmp/sshd_config',
                                                   sshd_conf)
    restart_sshd = 'systemctl restart sshd'
    session_multihost.client[0].run_command(restart_sshd)

    def restore_sshd():
        """ Restore sshd configuration """
        restore_cmd = 'cp %s %s' % (sshd_conf_bkup, sshd_conf)
        session_multihost.client[0].run_command(restore_cmd)
    request.addfinalizer(restore_sshd)


@pytest.fixture(scope='class')
def enable_ssh_responder(session_multihost, request):
    """ Enable ssh responder in sssd.conf """
    tools = sssdTools(session_multihost.client[0])
    tools.backup_sssd_conf()
    session_multihost.client[0].service_sssd('stop')
    tools.remove_sss_cache('/var/lib/sss/db')
    sssd_params = {'services': 'nss, pam, ssh'}
    tools.sssd_conf("sssd", sssd_params, action='update')
    session_multihost.client[0].service_sssd('start')

    def restore_sssd():
        """ Restore sssd.conf """
        tools.restore_sssd_conf()
    request.addfinalizer(restore_sssd)


@pytest.fixture(scope='class')
def enable_sssd_hostmap(session_multihost, request):
    """ Enables sssd for network and host database in nsswitch.conf """
    tools = sssdTools(session_multihost.client[0])
    # Since Fedora 36+ support of user-nsswitch was dropped
    # This applies to CentOS 10 and RHEL 10
    nsswitch_file = '/etc/authselect/user-nsswitch.conf'
    cmd = session_multihost.client[0].run_command(
        f"test -f {nsswitch_file}", raiseonerr=False)
    has_user_nsswith = cmd.returncode == 0
    if not has_user_nsswith:
        nsswitch_file = "/etc/nsswitch.conf"

    bkup = f'cp -vf {nsswitch_file} {nsswitch_file}_bkp'
    session_multihost.client[0].run_command(bkup)

    for value in ['hosts', 'networks']:
        update_nsswitch = f"sed -i 's/{value}:/{value}: sss/' {nsswitch_file}"
        session_multihost.client[0].run_command(update_nsswitch)
    if has_user_nsswith:
        authselect = 'authselect select sssd'
        session_multihost.client[0].run_command(authselect)

    def restore_nsswitch():
        restore = f"cp -vf {nsswitch_file}_bkp {nsswitch_file}"
        session_multihost.client[0].run_command(restore)
        if has_user_nsswith:
            session_multihost.client[0].run_command(authselect)
        tools.clear_sssd_cache()
        # remove the backup file
        remove_bkup = 'rm -f %s_bkup' % nsswitch_file
        session_multihost.client[0].run_command(remove_bkup)
    request.addfinalizer(restore_nsswitch)


@pytest.fixture(scope='class')
def add_host_entry(session_multihost, request):
    """
    Add host and network entries in Directory server to be used
    by sssd hostmap feature.
    """
    ldap_uri = 'ldap://%s' % (session_multihost.master[0].sys_hostname)
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    user_info = {'cn': 'node1'.encode('utf-8'),
                 'objectClass': [b'top', b'ipHost', b'device'],
                 'ipHostNumber': '192.168.1.1'.encode('utf-8')}
    user_dn = 'cn=node1,ou=People,dc=example,dc=test'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)
    user_info = {'cn': 'node2'.encode('utf-8'),
                 'objectClass': [b'top', b'ipNetwork', b'device'],
                 'ipNetworkNumber': '192.168.1.2'.encode('utf-8')}
    user_dn = 'cn=node2,ou=People,dc=example,dc=test'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)
    user_info = {'cn': 'node3'.encode('utf-8'),
                 'objectClass': [b'top', b'ipHost', b'device', b'ipNetwork'],
                 'ipNetworkNumber': '192.168.1.3'.encode('utf-8'),
                 'ipHostNumber': '192.168.1.3'.encode('utf-8')}
    user_dn = 'cn=node3,ou=People,dc=example,dc=test'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)

    def remove_host_entry():
        """ Removing Hostmap entries from ldap """
        for node in ['node1', 'node2', 'node3']:
            dn = f'cn={node},ou=People,dc=example,dc=test'
            print("deleting %s" % dn)
            (_, _) = ldap_inst.del_dn(dn)
    request.addfinalizer(remove_host_entry)


def execute_cmd(session_multihost, command):
    """ Execute command on client """
    cmd = session_multihost.client[0].run_command(command)
    return cmd


@pytest.fixture(scope='class')
def ns_account_lock(session_multihost, request):
    """ Backup and restore sssd.conf """
    version = float(re.findall(r"\d+\.\d+",
                               session_multihost.client[0].distro)[0])
    if version >= 9:
        execute_cmd(session_multihost, "yum install -y 389-ds-base")
    else:
        execute_cmd(session_multihost, "yum module "
                                       "enable -y 389-ds; "
                                       "yum install -y "
                                       "389-ds-base")
    tools = sssdTools(session_multihost.client[0])
    domain_name = tools.get_domain_section_name()
    client = sssdTools(session_multihost.client[0])
    domain_params = {'cache_credentials': 'true',
                     'enumerate': 'true',
                     'access_provider': 'ldap',
                     'ldap_access_order': 'expire',
                     'ldap_account_expire_policy': '389DS',
                     'ldap_ns_account_lock': 'nsAccountlock'}
    client.sssd_conf(f'domain/{domain_name}', domain_params)
    domain_params = {'reconnection_retries': '3'}
    client.sssd_conf('pam', domain_params)
    domain_params = {'filter_groups': 'root',
                     'filter_users': 'root',
                     'reconnection_retries': '3',
                     'debug_level': '9'}
    client.sssd_conf('nss', domain_params)
    session_multihost.client[0].service_sssd('restart')
    # Add managed role
    master_e = session_multihost.master[0].ip
    ldap_uri = f'ldap://{master_e}'
    ds_rootdn = 'cn=Directory Manager'
    ds_rootpw = 'Secret123'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    user_info = {'cn': 'managed'.encode('utf-8'),
                 'objectClass': [b'top', b'LdapSubEntry',
                                 b'nsRoleDefinition',
                                 b'nsSimpleRoleDefinition',
                                 b'nsManagedRoleDefinition']}
    user_dn = 'cn=managed,ou=People,dc=example,dc=test'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)
    user_dn = 'uid=foo1,ou=People,dc=example,dc=test'
    role_dn = "cn=managed,ou=people,dc=example,dc=test"
    add_member = [(ldap.MOD_ADD, 'nsRoleDN', role_dn.encode('utf-8'))]
    (ret, _) = ldap_inst.modify_ldap(user_dn, add_member)
    assert ret == 'Success'
    # Add filter role
    user_info = {'cn': 'filtered'.encode('utf-8'),
                 'objectClass': [b'top', b'LdapSubEntry',
                                 b'nsRoleDefinition',
                                 b'nsComplexRoleDefinition',
                                 b'nsFilteredRoleDefinition'],
                 'nsRoleFilter': 'o=filtered'.encode('utf-8'),
                 'Description': 'filtered role'.encode('utf-8')}
    user_dn = 'cn=filtered,ou=People,dc=example,dc=test'
    (_, _) = ldap_inst.add_entry(user_info, user_dn)
    user_dn = 'uid=foo4,ou=People,dc=example,dc=test'
    role_dn = "filtered"
    add_member = [(ldap.MOD_ADD, 'o', role_dn.encode('utf-8'))]
    (ret, _) = ldap_inst.modify_ldap(user_dn, add_member)
    assert ret == 'Success'

    def restoresssdconf():
        """ Restore sssd.conf """
        master_e = session_multihost.master[0].ip
        ldap_uri = f'ldap://{master_e}'
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = 'uid=foo1,ou=People,dc=example,dc=test'
        role_dn = "cn=managed,ou=people,dc=example,dc=test"
        del_member = [(ldap.MOD_DELETE, 'nsRoleDN', role_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(user_dn, del_member)
        assert ret == 'Success'
        user_dn = 'uid=foo4,ou=People,dc=example,dc=test'
        role_dn = "filtered"
        del_member = [(ldap.MOD_DELETE, 'o', role_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(user_dn, del_member)
        assert ret == 'Success'
        for i in ['cn=managed,ou=people,dc=example,dc=test',
                  'cn=filtered,ou=people,dc=example,dc=test',
                  'cn=nested,ou=People,dc=example,dc=test']:
            ldap_inst.del_dn(i)
    request.addfinalizer(restoresssdconf)

# ====================  Session Scoped Fixtures ================


@pytest.fixture(scope="session", autouse=True)
# pylint: disable=unused-argument
def setup_session(session_multihost, request, create_testdir):
    """
    Session fixture which calls fixture in order before tests run
    :param obj session_multihost: multihost object
    :param obj request: pytest request object
    """
    client_libs = sssdTools(session_multihost.client[0])
    client_libs.client_install_pkgs()
    client_libs.authselect()
    restart_rsyslog = 'systemctl restart rsyslog'
    session_multihost.client[0].run_command(restart_rsyslog)
    for idx in range(2):
        master_libs = sssdTools(session_multihost.master[idx])
        master_libs.server_install_pkgs()
        master_libs.authselect()

    def teardown_session():
        """ Teardown session """
        print("i am in teardown session")
    request.addfinalizer(teardown_session)
