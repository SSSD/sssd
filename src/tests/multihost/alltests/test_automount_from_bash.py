""" Automation of Auto Mount suite
:requirement: Ldap Provider - automount
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import pytest
import os
import ldap
import subprocess
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_instance_name, ds_suffix, ds_rootdn, ds_rootpw
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    assert string_name in log_str


def clear_only_domain_log(multihost):
    """
    This function will clear domain logs
    """
    client = multihost.client[0]
    log_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
    client.run_command(f'> {log_ssd}')


@pytest.fixture(scope='function')
def common_sssd_setup(multihost):
    """
    This is common sssd setup used in this test suite.
    """
    tools = sssdTools(multihost.client[0])
    tools.sssd_conf("nss", {'filter_groups': 'root',
                            'filter_users': 'root',
                            'debug_level': '9'}, action='update')
    tools.sssd_conf("sssd", {'services': 'nss, pam, autofs'}, action='update')
    tools.sssd_conf("autofs", {}, action='update')
    ldap_params = {'enumerate': True, 'use_fully_qualified_names': False}
    tools.sssd_conf(f'domain/{ds_instance_name}', ldap_params)
    tools.clear_sssd_cache()


@pytest.fixture(scope='function')
def ldap_autofs(multihost):
    """
    This is common sssd setup used in this test suite.
    """
    tools = sssdTools(multihost.client[0])
    tools.sssd_conf("nss", {'filter_groups': 'root',
                            'filter_users': 'root',
                            'debug_level': '9'}, action='update')
    tools.sssd_conf("sssd", {'services': 'nss, pam, autofs'}, action='update')
    tools.sssd_conf("autofs", {'debug_level': "9"}, action='update')
    tools.sssd_conf("domain/example1", {'enumerate': True,
                                        'autofs_provider': "ldap",
                                        'ldap_autofs_search_base': f'ou=mount,{ds_suffix}',
                                        'use_fully_qualified_names': False,
                                        'ldap_autofs_map_object_class': "nisMap",
                                        "ldap_autofs_map_name": "nisMapName",
                                        "ldap_autofs_entry_object_class": "nisObject",
                                        "ldap_autofs_entry_key": "cn",
                                        "ldap_autofs_entry_value": "nisMapEntry"}, action='update')
    tools.clear_sssd_cache()


@pytest.fixture(scope='class')
def nfs_server_setup(multihost, request):
    """
    This function will setup NFS server in master machine.
    """
    master = multihost.master[0]
    master.run_command("mkdir -p /export/project{1..2}")
    master.run_command("mkdir /export/directtest{1..2}")
    master.run_command("mkdir /export/projects")
    master.run_command("mkdir /export/projects_new")
    master.run_command("mkdir /export/largepathfolder")
    master.run_command("mkdir -p /export/shared{1..2}/key{1..2}")
    master.run_command("mkdir -p /export/home/test")
    master.run_command('echo "/export    *(rw,sync)" > /etc/exports')
    master.run_command("systemctl restart nfs-server")

    def restore():
        """Will restore nfs server after test."""
        master.run_command("rm -rvf /export/*")
    request.addfinalizer(restore)


@pytest.fixture(scope='class')
def create_users(multihost, request):
    """
    This function will create users for this test.
    """
    client = multihost.client[0]
    client.run_command("authselect select sssd --force")
    client.run_command("cp -f /etc/nsswitch.conf /etc/nsswitch.conf.backup")
    client.run_command("cp -f /etc/sysconfig/autofs /etc/sysconfig/autofs_bkp")
    client.run_command("sed -i 's/automount:  files/automount:  sss files/g' /etc/nsswitch.conf")
    ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    ldap_inst.org_unit("mount", ds_suffix)
    user_dn = f'nisMapName=auto.master,ou=mount,{ds_suffix}'
    user_info = {'nisMapName': 'auto.master'.encode('utf-8'),
                 'objectClass': ['nisMap'.encode('utf-8'),
                                 'top'.encode('utf-8')]}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/-,nisMapName=auto.master,ou=mount,{ds_suffix}'
    user_info = {'cn': '/-'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': 'auto.direct'.encode('utf-8'),
                 'nisMapName': 'auto.master'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/share1,nisMapName=auto.master,ou=mount,{ds_suffix}'
    user_info = {'cn': '/share1'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': 'auto.share1'.encode('utf-8'),
                 'nisMapName': 'auto.master'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/share2,nisMapName=auto.master,ou=mount,{ds_suffix}'
    user_info = {'cn': '/share2'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': 'auto.share2'.encode('utf-8'),
                 'nisMapName': 'auto.master'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/export/home,nisMapName=auto.master,ou=mount,{ds_suffix}'
    user_info = {'cn': '/export/home'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': 'auto.home'.encode('utf-8'),
                 'nisMapName': 'auto.master'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'nisMapName=auto.direct,ou=mount,{ds_suffix}'
    user_info = {'objectClass': ['nisMap'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapName': 'auto.direct'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'nisMapName=auto.share1,ou=mount,{ds_suffix}'
    user_info = {'objectClass': ['nisMap'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapName': 'auto.share1'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'nisMapName=auto.share2,ou=mount,{ds_suffix}'
    user_info = {'objectClass': ['nisMap'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapName': 'auto.share2'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    master_server = multihost.master[0].sys_hostname
    user_dn = f'cn=/proj1,nisMapName=auto.direct,ou=mount,{ds_suffix}'
    user_info = {'cn': '/proj1'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/project1'.encode('utf-8'),
                 'nisMapName': 'auto.direct'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/proj2,nisMapName=auto.direct,ou=mount,{ds_suffix}'
    user_info = {'cn': '/proj2'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/project2'.encode('utf-8'),
                 'nisMapName': 'auto.direct'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}'
    user_info = {'cn': '/folder1/folder2/projects'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/projects'.encode('utf-8'),
                 'nisMapName': 'auto.direct'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/directtest,nisMapName=auto.direct,ou=mount,{ds_suffix}'
    user_info = {'cn': '/directtest'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/directtest1'.encode('utf-8'),
                 'nisMapName': 'auto.direct'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=key1,nisMapName=auto.share1,ou=mount,{ds_suffix}'
    user_info = {'cn': 'key1'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/shared1/key1'.encode('utf-8'),
                 'nisMapName': 'auto.share1'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=key2,nisMapName=auto.share1,ou=mount,{ds_suffix}'
    user_info = {'cn': 'key2'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/shared1/key2'.encode('utf-8'),
                 'nisMapName': 'auto.share1'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=key1,nisMapName=auto.share2,ou=mount,{ds_suffix}'
    user_info = {'cn': 'key1'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/shared2/key1'.encode('utf-8'),
                 'nisMapName': 'auto.share2'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'nisMapName=auto.home,ou=mount,{ds_suffix}'
    user_info = {'nisMapName': 'auto.home'.encode('utf-8'),
                 'objectClass': ['nisMap'.encode('utf-8'),
                                 'top'.encode('utf-8')]}
    ldap_inst.add_entry(user_info, user_dn)
    user_dn = f'cn=/,nisMapName=auto.home,ou=mount,{ds_suffix}'
    user_info = {'cn': '/'.encode('utf-8'),
                 'objectClass': ['nisObject'.encode('utf-8'),
                                 'top'.encode('utf-8')],
                 'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/home/&'.encode('utf-8'),
                 'nisMapName': 'auto.home'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    file_location_cpp = '/script/a1.cpp'
    client.transport.put_file(os.path.dirname(os.path.abspath(__file__)) + file_location_cpp, '/tmp/a1.cpp')

    def restore():
        """
        Delete user after test finish
        """
        client.run_command("cp -f /etc/nsswitch.conf.backup /etc/nsswitch.conf")
        client.run_command("cp -vf /etc/sysconfig/autofs_bkp /etc/sysconfig/autofs")
        client.run_command("rm -vf /tmp/a1.cpp")
        for i in range(250):
            user_dn = f'cn=/foo{i},nisMapName=auto.master,ou=mount,{ds_suffix}'
            ldap_inst.del_dn(user_dn)
            user_dn = f'cn=testkey{i},nisMapName=auto.share,ou=mount,{ds_suffix}'
            ldap_inst.del_dn(user_dn)
        for dn_dn in [f'nisMapName=auto.share,ou=mount,{ds_suffix}',
                      f'cn=/largepathfolder1/largepathfolder2/largepathfolder3/'
                      f'largepathfolder4/largepathfolder5/largepathfolder6/largepathfolder7/'
                      f'largepathfolder8/largepathfolder9/largepathfolder10/largepathfolder11/'
                      f'largepathfolder12/largepathfolder13/largepathfolders,'
                      f'nisMapName=auto.direct,ou=mount,{ds_suffix}',
                      f'cn=key1,nisMapName=auto.share3,ou=mount,{ds_suffix}',
                      f'cn=/share3,nisMapName=auto.master,ou=mount,{ds_suffix}',
                      f'nisMapName=auto.share3,ou=mount,{ds_suffix}']:
            ldap_inst.del_dn(dn_dn)
        time.sleep(2)
        for dn_dn in [f'cn=/,nisMapName=auto.home,ou=mount,{ds_suffix}',
                      f'nisMapName=auto.home,ou=mount,{ds_suffix}',
                      f'cn=key1,nisMapName=auto.share2,ou=mount,{ds_suffix}',
                      f'cn=key2,nisMapName=auto.share1,ou=mount,{ds_suffix}',
                      f'cn=key1,nisMapName=auto.share1,ou=mount,{ds_suffix}',
                      f'cn=/directtest,nisMapName=auto.direct,ou=mount,{ds_suffix}',
                      f'cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}',
                      f'cn=/proj2,nisMapName=auto.direct,ou=mount,{ds_suffix}',
                      f'cn=/proj1,nisMapName=auto.direct,ou=mount,{ds_suffix}',
                      f'nisMapName=auto.share2,ou=mount,{ds_suffix}',
                      f'nisMapName=auto.share1,ou=mount,{ds_suffix}',
                      f'nisMapName=auto.direct,ou=mount,{ds_suffix}',
                      f'cn=/export/home,nisMapName=auto.master,ou=mount,{ds_suffix}',
                      f'cn=/share2,nisMapName=auto.master,ou=mount,{ds_suffix}',
                      f'cn=/share1,nisMapName=auto.master,ou=mount,{ds_suffix}',
                      f'cn=/-,nisMapName=auto.master,ou=mount,{ds_suffix}',
                      f'nisMapName=auto.master,ou=mount,{ds_suffix}',
                      f'ou=mount,{ds_suffix}']:
            ldap_inst.del_dn(dn_dn)
    request.addfinalizer(restore)


@pytest.mark.tier1_4
@pytest.mark.usefixtures('setup_sssd',
                         'create_users',
                         'nfs_server_setup')
@pytest.mark.offline
class TestAutoFs(object):
    """
    This is test case class for auto fs suite
    """
    @staticmethod
    def test_autofs_search(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: ldap autofs search base not mentioned
        :id: 838bd768-9897-11ed-a1c6-845cf3eff344
        :setup:
            1. SSSD configuration is updated to delete the ldap_search_base option.
            2. The SSSD cache is cleared.
        :steps:
            1. Sssd default autofs config
            2. Dont configure autofs search base with sssd
        :expectedresults:
            1. Sssd should work without autofs search base
            2. Corresponding sssd logs should be generated
        """
        tools = sssdTools(multihost.client[0])
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        tools.sssd_conf("domain/example1", {'ldap_search_base': ''}, action='delete')
        tools.clear_sssd_cache()
        find_logs(multihost, log_sssd, "Got rootdse")
        find_logs(multihost, log_sssd, f"Setting option [ldap_autofs_search_base] to [{ds_suffix}]")

    @staticmethod
    def test_ldap_search_base(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: ldap autofs search base picks up the value from ldap search base
        :id: 7fc8e7f6-9897-11ed-8ec5-845cf3eff344
        :setup:
            1. SSSD configuration is updated to ldap_search_base.
            2. The SSSD cache is cleared.
        :steps:
            1. Sssd should work with autofs search base
        :expectedresults:
            1. Corresponding sssd logs should be generated
        """
        tools = sssdTools(multihost.client[0])
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        ldap_params = {'ldap_search_base': f'ou=mount,{ds_suffix}'}
        tools.sssd_conf(f'domain/{ds_instance_name}', ldap_params)
        tools.clear_sssd_cache()
        find_logs(multihost, log_sssd, f"Option ldap_autofs_search_base set to ou=mount,{ds_suffix}")

    @staticmethod
    def test_ldap_autofs_search_base(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: ldap autofs search base set to ou equals to mount and DS BASE DN
        :id: 7bbdddb0-9897-11ed-85fc-845cf3eff344
        :setup:
            1. SSSD configuration is updated for ldap_search_base to ldap_autofs_search_base
            2. The SSSD cache is cleared.
        :steps:
            1. Remove ldap_search_base
        :expectedresults:
            1. Sssd should work with autofs ldap_autofs_search_base and
                Corresponding sssd logs should be generated
        """
        tools = sssdTools(multihost.client[0])
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        # ldap autofs search base set to ou equals to mount and DS BASE DN
        client = multihost.client[0]
        tools.sssd_conf("domain/example1", {'ldap_search_base': f'ou=mount,{ds_suffix}'}, action='update')
        client.run_command("sed -i 's/ldap_search_base/ldap_autofs_search_base/g' /etc/sssd/sssd.conf")
        tools.clear_sssd_cache()
        find_logs(multihost, log_sssd, f"Search base added: [AUTOFS][ou=mount,{ds_suffix}][SUBTREE]")

    @staticmethod
    def test_autofs_provider_none(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: ldap autofs search base set to ou equals to mount and DS
            BASE DN and autofs_provider is None
        :id: 778f7f78-9897-11ed-ba16-845cf3eff344
        :setup:
            1. SSSD configuration is updated for ldap_autofs_search_base
            2. The SSSD cache is cleared.
        :steps:
            1. Set autofs provider equals to none
        :expectedresults:
            1. Sssd should not work with provider none
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {'ldap_autofs_search_base':
                                                f'ou=mount,{ds_suffix}'}, action='update')
        ldap_params = {'autofs_provider': None}
        tools.sssd_conf(f'domain/{ds_instance_name}', ldap_params)
        tools.clear_sssd_cache()
        # Automount should not work here
        assert "share1" not in client.run_command("automount -m").stdout_text

    @staticmethod
    def test_autofs_id_provider(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: autofs provider uses the value from id provider
        :id: 738825ec-9897-11ed-ac02-845cf3eff344
        :setup:
            1. SSSD configuration is updated for ldap_autofs_search_base and autofs_provider
            2. The SSSD cache is cleared.
        :steps:
            1. Remove autofs_provider = None from sssd config
        :expectedresults:
            1. Sssd default autofs config works and Corresponding sssd logs should be generated
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {'ldap_autofs_search_base': f'ou=mount,{ds_suffix}'}, action='update')
        tools.sssd_conf("domain/example1", {'autofs_provider': None}, action='delete')
        tools.clear_sssd_cache()
        client.run_command("automount -m 1> /tmp/automount")
        find_logs(multihost, "/tmp/automount", "Mount point: /share2")

    @staticmethod
    def test_autofs_provider_ldap(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Set autofs provider to ldap
        :id: 9304c416-9c70-11ed-9d67-845cf3eff344
        :setup:
            1. SSSD configuration is updated for ldap_autofs_search_base and autofs_provider
            2. The SSSD cache is cleared.
        :steps:
            1. Set autofs provider to ldap, check share2 is visible
        :expectedresults:
            1. Sssd should work with autofs provider to ldap, share2 should visible
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {
            'autofs_provider': 'ldap',
            'ldap_autofs_search_base': f'ou=mount,{ds_suffix}'}, action='update')
        tools.clear_sssd_cache()
        assert "share2" in client.run_command("automount -m").stdout_text

    @staticmethod
    def test_available_automount_maps(multihost, backupsssdconf, ldap_autofs):
        """
        :title: Set autofs provider to ldap
        :id: 6f735d8c-9897-11ed-8c51-845cf3eff344
        :steps:
            1. "automount -m" command, which lists the available automount maps.
                It checks that the maps "share2", "share", "export", and "directtest"
                are all present in the output.
            2. Searching the logs of the SSSD service for specific configuration options and
                verifying that these options have the expected values.
                The options being checked include "ldap_autofs_map_object_class",
                "ldap_autofs_map_name", "ldap_autofs_entry_object_class",
                "ldap_autofs_entry_key", and "ldap_autofs_entry_value".

        :expectedresults:
            1. If any of these maps are not present in the output,
                it raises an exception with a descriptive error message.
            2. If the logs do not contain the expected values for these options,
                an error will be raised.
        """
        # Set autofs provider to ldap
        client = multihost.client[0]
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        assert "share2" in client.run_command("automount -m").stdout_text
        # non default values of all ldap attributes bz822404
        find_logs(multihost, log_sssd, "Option ldap_autofs_map_object_class has value nisMap")
        find_logs(multihost, log_sssd, "Option ldap_autofs_map_name has value nisMapName")
        find_logs(multihost, log_sssd, "Option ldap_autofs_entry_object_class has value nisObject")
        find_logs(multihost, log_sssd, "Option ldap_autofs_entry_key has value cn")
        find_logs(multihost, log_sssd, "Option ldap_autofs_entry_value has value nisMapEntry")
        cmd = client.run_command("automount -m")
        assert "share" in cmd.stdout_text, "Could not find share in automounts"
        assert "export" in cmd.stdout_text, "Could not find export in automounts"
        assert "directtest" in cmd.stdout_text, "Could not find directtest in automounts"

    @staticmethod
    def test_autofs_shares(multihost, backupsssdconf, ldap_autofs):
        """
        :title: Set autofs provider to ldap
        :id: 6b34da0c-9897-11ed-bb11-845cf3eff344
        :steps:
            1. Restart the autofs service on the client machine
            2. Try to access each of the autofs mounts by changing to the respective
                directories and running the cd command twice to return to the current directory.
            3. Check if the mount points are correctly mounted by running the mount
                command and checking the output for specific strings indicating the mount points.
        :expectedresults:
            1. Restart of autofs service should success
            2. Mount Points should accessible
            3. The code checks for the presence of the following mounts:
                /export/home/test
                /export/shared1/key1
                /export/shared1/key2
                /export/shared2/key1
                /export/directtest1
                /export/projects
        """
        # mount autofs shares
        client = multihost.client[0]
        master_server = multihost.master[0].sys_hostname
        client.run_command("service autofs restart")
        # Try to access the autofs mounts
        client.run_command("cd /export/home/test;cd -")
        cmd = client.run_command("mount")
        assert f"{master_server}:/export/home/test" in cmd.stdout_text, "Could not find mount /export/home/test"
        client.run_command("cd /share1/key1;cd -")
        cmd = client.run_command("mount")
        assert f"{master_server}:/export/shared1/key1" in cmd.stdout_text, "Could not find mount /export/shared1/key1"
        client.run_command("cd /share1/key2;cd -")
        cmd = client.run_command("mount")
        assert f"{master_server}:/export/shared1/key2" in cmd.stdout_text, "Could not find mount /export/shared1/key2"
        client.run_command("cd /share2/key1;cd -")
        cmd = client.run_command("mount")
        assert f"{master_server}:/export/shared2/key1" in cmd.stdout_text, "Could not find mount /export/shared2/key1"
        # Duplicate Direct Mounts
        client.run_command("cd /directtest;cd -")
        cmd = client.run_command("mount")
        assert f"{master_server}:/export/directtest1" in cmd.stdout_text, "Could not find mount /export/directtest1"
        # Direct Mount
        client.run_command("cd /folder1/folder2/projects;cd -")
        cmd = client.run_command("mount")
        assert f"{master_server}:/export/projects" in cmd.stdout_text, "Could not find mount /export/projects"

    @staticmethod
    def test_autofs_timeout(multihost, backupsssdconf, ldap_autofs):
        """
        :title: Set entry cache autofs timeout value
        :id: 670cf00e-9897-11ed-8169-845cf3eff344
        :Setup:
            1. Update the 'entry_cache_autofs_timeout' value in the SSSD
                configuration for the "domain/example1" domain to 100.
            2. Clears the SSSD cache.
            3. Update the autofs configuration to set the
                timeout to 10 seconds and disables browsing
                MOUNT_NFS_DEFAULT_PROTOCOL to 4
            4. Restarts the autofs service.
        :steps:
            1. Tries to access the "/share2/key1" directory and checks if it
                is mounted from the master server at "/export/shared2/key1".
            2. Searches for log messages indicating that SSSD is searching for automount map entries.
            3. After a delay of 12 seconds, clears the SSSD log file.
            4. Tries to access the "/share2/key1" directory and checks if it is still mounted.
            5. Raises an error if it finds log messages indicating that
                SSSD is searching for automount map entries.
            6. After a delay of 110 seconds, clears the SSSD log file.
            7. Tries to access the "/share2/key1" directory and checks if it is still mounted.
        :expectedresults:
            1. /shared2/key1 should mount
            2. Corresponding sssd logs should be generated
            3. Sssd logs should be cleared
            4. /export/shared2/key1 should be accessible
            5. Sssd should not sent new request for automount map entries
            6. SSSD logs should be cleared
            7. /shared2/key1 should be accessible
        """
        # Set entry cache autofs timeout value
        client = multihost.client[0]
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        tools = sssdTools(multihost.client[0])
        master_server = multihost.master[0].sys_hostname
        tools.sssd_conf("domain/example1", {'entry_cache_autofs_timeout': "100"}, action='update')
        tools.clear_sssd_cache()
        client.run_command("echo 'TIMEOUT=10' >> /etc/sysconfig/autofs")
        client.run_command("echo 'BROWSE_MODE=\"no\"' >> /etc/sysconfig/autofs")
        client.run_command("echo 'MOUNT_NFS_DEFAULT_PROTOCOL=4' >> /etc/sysconfig/autofs")
        client.run_command("service autofs restart")
        client.run_command("cd /share2/key1;cd -")
        assert f"{master_server}:/export/shared2/key1" in client.run_command("mount").stdout_text
        time.sleep(2)
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        time.sleep(12)
        client.run_command(f'> {log_sssd}')
        client.run_command("cd /share2/key1;cd -")
        assert f"{master_server}:/export/shared2/key1" in client.run_command("mount").stdout_text
        with pytest.raises(AssertionError):
            find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        time.sleep(110)
        client.run_command(f'> {log_sssd}')
        client.run_command("cd /share2/key1;cd -")
        assert f"{master_server}:/export/shared2/key1" in client.run_command("mount").stdout_text

    @staticmethod
    def test_key_location(multihost, backupsssdconf, ldap_autofs):
        """
        :title: change key and location
        :id: 62521da0-9897-11ed-a276-845cf3eff344
        :setup:
            1. Modify the SSSD configuration file.
            2. The cache of the SSSD is then cleared.
            3. The autofs timeout is increased and the autofs service is restarted.
        :steps:
            1. The client system tries to mount a folder (/folder1/folder2/projects)
                from the master server (master_server).
            2. Searches the log files of the SSSD for log entries related to automount map entries.
            3. The mounted folder is then unmounted and the LDAP entry for the folder is updated.
            4. The autofs service is restarted and the client system tries to mount the folder again.
            5. Finally, the test case searches the SSSD log files again to see if the new mount is reflected.
        :expectedresults:
            1. Mount of /folder1/folder2/projects Should Success
            2. Corresponding sssd logs should be generated
            3. Unmount Should Success
            4. Mounting of folder should success
            5. New mount is reflected Successfully
        """
        # change key and location
        client = multihost.client[0]
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        tools = sssdTools(multihost.client[0])
        master_server = multihost.master[0].sys_hostname
        tools.sssd_conf("domain/example1", {'entry_cache_autofs_timeout': "60"}, action='update')
        tools.clear_sssd_cache()
        client.run_command("sed -i 's/TIMEOUT=10/TIMEOUT=60/g' /etc/sysconfig/autofs")
        client.run_command("service autofs restart")
        client.run_command("cd /folder1/folder2/projects;cd -")
        cmd = client.run_command("mount")
        assert "/folder1/folder2/projects" in cmd.stdout_text
        assert f"{master_server}:/export/projects" in cmd.stdout_text
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        client.run_command("umount -v /folder1/folder2/projects")
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        modify_gid = [(ldap.MOD_REPLACE, 'nisMapEntry',
                       f'-fstype=nfs,rw {master_server}:/export/projects_new'.encode('utf-8'))]
        ldap_inst.modify_ldap(f'cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}', modify_gid)
        time.sleep(40)
        clear_only_domain_log(multihost)
        client.run_command("cd /folder1/folder2/projects;cd -")
        cmd = client.run_command("mount")
        assert "/folder1/folder2/projects" in cmd.stdout_text
        assert f"{master_server}:/export/projects" in cmd.stdout_text
        with pytest.raises(AssertionError):
            find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        clear_only_domain_log(multihost)
        time.sleep(30)
        client.run_command("umount -v /folder1/folder2/projects")
        # Restart autofs to clear the autofs cache and pull in the changes from ldap
        client.run_command("service autofs restart")
        client.run_command("cd /folder1/folder2/projects;cd -")
        cmd = client.run_command("mount")
        assert "/folder1/folder2/projects" in cmd.stdout_text
        assert f"{master_server}:/export/projects_new" in cmd.stdout_text
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        modify_gid = [(ldap.MOD_REPLACE, 'nisMapEntry',
                       f'-fstype=nfs,rw {master_server}:/export/projects'.encode('utf-8'))]
        ldap_inst.modify_ldap(f'cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}', modify_gid)

    @staticmethod
    def test_change_key_map(multihost, backupsssdconf, ldap_autofs):
        """
        :title: change key and map
        :id: 5e15fd9c-9897-11ed-acf5-845cf3eff344
        :setup:
            1. Configures SSSD by updating the SSSD configuration file and clearing the SSSD cache.
            3. Restarts the autofs service.
        :steps:
            1. Searches the log files for messages to verify that the mount was successful.
            2. Unmounts the file system and deletes the corresponding automount map from the LDAP server.
            3. Verifies that the unmount was successful and that the NFS file system is no longer accessible.
            4. Restarts the autofs service again and verifies that the NFS file system cannot be accessed.
            5. Adds the deleted automount map back to the LDAP server.
        :expectedresults:
            1. Corresponding sssd logs should be generated
            2. Unmount Should Success
            3. Unmounted NFS file system not be accessible
            4. After restart unmounted NFS file system not be accessible
            5. Deleted mounts can be remounted
        """
        # change key and map
        client = multihost.client[0]
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        master_server = multihost.master[0].sys_hostname
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {'entry_cache_autofs_timeout': "60"}, action='update')
        tools.clear_sssd_cache()
        client.run_command("service autofs restart")
        client.run_command("cd /folder1/folder2/projects;cd -")
        cmd = client.run_command("mount")
        assert "/folder1/folder2/projects" in cmd.stdout_text
        assert f"{master_server}:/export/projects" in cmd.stdout_text
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        client.run_command("umount /folder1/folder2/projects")
        ldap_inst.del_dn(f"cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}")
        time.sleep(40)
        clear_only_domain_log(multihost)
        client.run_command("cd /folder1/folder2/projects;cd -")
        cmd = client.run_command("mount")
        assert "/folder1/folder2/projects" in cmd.stdout_text
        assert f"{master_server}:/export/projects" in cmd.stdout_text
        with pytest.raises(AssertionError):
            find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        clear_only_domain_log(multihost)
        time.sleep(30)
        client.run_command("umount -v /folder1/folder2/projects")
        # Restart autofs to clear the autofs cache and pull in the changes from ldap
        client.run_command("service autofs restart")
        time.sleep(10)
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("ls -d /folder1/folder2/projects")
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        # Adding the deleted direct map
        user_dn = f'cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}'
        user_info = {'cn': '/folder1/folder2/projects'.encode('utf-8'),
                     'objectClass': ['nisObject'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisMapEntry':f'-fstype=nfs,rw {master_server}:/export/projects'.encode('utf-8'),
                     'nisMapName': 'auto.direct'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)

    @staticmethod
    def test_bz870045(multihost, backupsssdconf, ldap_autofs):
        """
        :title: Always reread master map from ldap bz870045
        :id: 5983c6f6-9897-11ed-9101-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=870045
        :setup:
            1. Configures SSSD by updating the SSSD configuration file and clearing the SSSD cache.
        :steps:
            1. The client restarts the autofs service
            2. Logs are checked for various messages to confirm the correct behavior of SSSD and automount.
            3. Adds a new map auto.share3 to the LDAP server
            4. Restarts the autofs service on the client
            5. Checks the logs again to confirm the correct behavior of SSSD and automount with the new map.
        :expectedresults:
            1. Restarts should Success
            2. Corresponding logs should generate
            3. auto.share3 should added to master server
            4. Restart should success
            5. Corresponding logs should generate
        """
        # Always reread master map from ldap bz870045
        client = multihost.client[0]
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        master_server = multihost.master[0].sys_hostname
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {'entry_cache_autofs_timeout': "60"}, action='update')
        tools.clear_sssd_cache()
        client.run_command("automount -m")
        time.sleep(2)
        find_logs(multihost, "/var/log/sssd/sssd_autofs.log", "Obtaining autofs map auto.master")
        find_logs(multihost, log_sssd, "Requested refresh for: auto.master" )
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        find_logs(multihost, log_sssd, f"{master_server}:/export/shared2/key1")
        time.sleep(30)
        clear_only_domain_log(multihost)
        client.run_command("> /var/log/sssd/sssd_autofs.log")
        client.run_command("service autofs restart")
        time.sleep(2)
        find_logs(multihost, "/var/log/sssd/sssd_autofs.log", "Looking up [auto.master] in data provider")
        find_logs(multihost, "/var/log/sssd/sssd_autofs.log", "Obtaining autofs map auto.master")
        find_logs(multihost, log_sssd, "Requested refresh for: auto.master")
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        time.sleep(10)
        clear_only_domain_log(multihost)
        client.run_command("> /var/log/sssd/sssd_autofs.log")
        ## Add a new map auto.share3
        user_dn = f'cn=/share3,nisMapName=auto.master,ou=mount,{ds_suffix}'
        user_info = {'cn': '/share3'.encode('utf-8'),
                     'objectClass': ['nisObject'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisMapEntry':'auto.share3'.encode('utf-8'),
                     'nisMapName': 'auto.master'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        user_dn = f'nisMapName=auto.share3,ou=mount,{ds_suffix}'
        user_info = {'objectClass': ['nisMap'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisMapName': 'auto.share3'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        user_dn = f'cn=key1,nisMapName=auto.share3,ou=mount,{ds_suffix}'
        user_info = {'cn':'key1'.encode('utf-8'),
                     'objectClass': ['nisObject'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisMapEntry':f'-fstype=nfs,rw {master_server}:/export/shared3/key1'.encode('utf-8'),
                     'nisMapName': 'auto.share3'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        client.run_command("service autofs restart")
        time.sleep(2)
        find_logs(multihost, "/var/log/sssd/sssd_autofs.log", "Obtaining autofs map auto.master")
        find_logs(multihost, log_sssd, "Requested refresh for: auto.master")
        find_logs(multihost, log_sssd, f"Searching for automount map entries with base [ou=mount,{ds_suffix}]")
        find_logs(multihost, log_sssd, f"[cn=/share3,nisMapName=auto.master,ou=mount,{ds_suffix}]")
        find_logs(multihost, log_sssd, f"Adding autofs entry [/share3] - [auto.share3]")

    @staticmethod
    def test_bz876531_bz894428(multihost, backupsssdconf, ldap_autofs):
        """
        :title: sss cache does not work for automount maps bz876531 bz894428
        :id: 53c18da2-9897-11ed-b023-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=894428
                   https://bugzilla.redhat.com/show_bug.cgi?id=876531
        :setup:
            1. Updates the SSSD configuration file with a new setting for entry_cache_autofs_timeout,
                which controls the cache timeout for autofs maps in SSSD.
            2. clear the SSSD cache
        :steps:
            1. Run a series of commands to check that the autofs maps are correctly populated in the SSSD
                cache and the cache entries are not expired.
                search the specified LDB (Lightweight Directory-Based Authentication) database
                (/var/lib/sss/db/cache_example1.ldb) for the specified entries
                (name=auto.master and name=auto.direct) and retrieve their dataExpireTimestamp values.
            2. Search for some errors which should not occur.
            3. Modify a direct map
            4. on the client run sss_cache -A
            5. on the client run automount -m to see if the change is visible by the automounter
        :expectedresults:
            1. Retrieving dataExpireTimestamp values should success
            2. There should not be any error
            3. Direct map modification should success
            4. sss_cache -A command should success
            5. automount -m should display the current automount maps
        """
        # sss cache does not work for automount maps bz876531 bz894428
        client = multihost.client[0]
        master_server = multihost.master[0].sys_hostname
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {'entry_cache_autofs_timeout': "60"}, action='update')
        tools.clear_sssd_cache()
        client.run_command("service autofs restart")
        time.sleep(2)
        client.run_command("automount -m")
        for mount_point in ["auto.master",
                            "auto.direct",
                            "auto.home",
                            "auto.share1",
                            "auto.share2",
                            "auto.share3"]:
            assert "dataExpireTimestamp" in \
                   client.run_command(f"ldbsearch -H "
                                      f"/var/lib/sss/db/cache_example1.ldb name={mount_point} "
                                      f"dataExpireTimestamp").stdout_text
        client.run_command("sss_cache -A --domain=example1 --debug 10 2> /tmp/cache_debugout")
        for result in ["failed",
                       "No cache object matched the specified search",
                       "No such autofs map"]:
            with pytest.raises(AssertionError):
                find_logs(multihost, "/tmp/cache_debugout", result)
        for mount_point in ["auto.master",
                            "auto.direct",
                            "auto.home",
                            "auto.share1",
                            "auto.share2",
                            "auto.share3"]:
            assert "dataExpireTimestamp" in \
                   client.run_command(f"ldbsearch -H /var/lib/sss/db/cache_example1.ldb "
                                      f"name={mount_point} dataExpireTimestamp").stdout_text
        client.run_command("automount -m")
        # Modify a direct map
        modify_gid = [(ldap.MOD_REPLACE, 'nisMapEntry',
                       f'-fstype=nfs,rw {master_server}:/export/projects_old'.encode('utf-8'))]
        ldap_inst.modify_ldap(f'cn=/folder1/folder2/projects,nisMapName=auto.direct,ou=mount,{ds_suffix}', modify_gid)
        clear_only_domain_log(multihost)
        client.run_command("sss_cache -a auto.direct --debug 10 2> /tmp/cache_debugout")
        for result in ["failed", "No cache object matched the specified search", "No such autofs map"]:
            with pytest.raises(AssertionError):
                find_logs(multihost, "/tmp/cache_debugout", result)
        for mount_point in ["auto.direct",
                            "auto.master",
                            "auto.home",
                            "auto.share1",
                            "auto.share2",
                            "auto.share3"]:
            assert "dataExpireTimestamp" in \
                   client.run_command(f"ldbsearch -H /var/lib/sss/db/cache_example1.ldb "
                                      f"name={mount_point} dataExpireTimestamp").stdout_text
        client.run_command("automount -m")
        time.sleep(2)
        find_logs(multihost, log_sssd, f"{master_server}:/export/projects_old")
        modify_gid = [(ldap.MOD_REPLACE, 'nisMapEntry',
                       f'-fstype=nfs,rw {master_server}:/export/shared1/key_new'.encode('utf-8'))]
        ldap_inst.modify_ldap(f'cn=key1,nisMapName=auto.share1,ou=mount,{ds_suffix}', modify_gid)
        clear_only_domain_log(multihost)
        client.run_command("sss_cache -a auto.share1 --domain=example1 --debug 10 2> /tmp/cache_debugout")
        for result in ["failed", "No cache object matched the specified search", "No such autofs map"]:
            with pytest.raises(AssertionError):
                find_logs(multihost, "/tmp/cache_debugout", result)
        for mount_point in ["auto.direct",
                            "auto.master",
                            "auto.home",
                            "auto.share1",
                            "auto.share2",
                            "auto.share3"]:
            assert "dataExpireTimestamp" in \
                   client.run_command(f"ldbsearch -H /var/lib/sss/db/cache_example1.ldb "
                                      f"name={mount_point} dataExpireTimestamp").stdout_text
        client.run_command("automount -m")
        time.sleep(5)
        find_logs(multihost, log_sssd, f"{master_server}:/export/shared1/key_new")

    @staticmethod
    def test_bz811987(multihost, backupsssdconf, ldap_autofs):
        """
        :title: maximum key name must be PATH MAX bz811987
        :id: 4e9e6930-9897-11ed-b12f-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=811987
        :setup:
            1. Updates the SSSD configuration file with a new setting for entry_cache_autofs_timeout,
                which controls the cache timeout for autofs maps in SSSD.
            2. clear the SSSD cache
        :steps:
            1. Create a big size user for automount
            2. Mount it and should work as normal.
        :expectedresults:
            1. size user for automount should be added
            2. Should be mounted
        """
        # maximum key name must be PATH MAX bz811987
        client = multihost.client[0]
        master_server = multihost.master[0].sys_hostname
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("domain/example1", {'entry_cache_autofs_timeout': "60"}, action='update')
        tools.clear_sssd_cache()
        user_dn = f'cn=/largepathfolder1/largepathfolder2/largepathfolder3/largepathfolder4/' \
                  f'largepathfolder5/largepathfolder6/largepathfolder7/largepathfolder8/largepathfolder9/' \
                  f'largepathfolder10/largepathfolder11/largepathfolder12/largepathfolder13/largepathfolders,' \
                  f'nisMapName=auto.direct,ou=mount,{ds_suffix}'
        user_info = {'objectClass': ['nisObject'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisMapName': 'auto.direct'.encode('utf-8'),
                     'cn': '/largepathfolder1/largepathfolder2/largepathfolder3/'
                           'largepathfolder4/largepathfolder5/largepathfolder6/largepathfolder7/'
                           'largepathfolder8/largepathfolder9/largepathfolder10/largepathfolder11/'
                           'largepathfolder12/largepathfolder13/largepathfolders'.encode('utf-8'),
                     'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/largepathfolder'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        client.run_command("service autofs restart")
        tools.clear_sssd_cache()
        client.run_command("cd /largepathfolder1/largepathfolder2/largepathfolder3/largepathfolder4/"
                           "largepathfolder5/largepathfolder6/largepathfolder7/largepathfolder8/"
                           "largepathfolder9/largepathfolder10/largepathfolder11/largepathfolder12/"
                           "largepathfolder13/largepathfolders;cd -")
        assert f"{master_server}:/export/largepathfolder" in client.run_command("mount").stdout_text

    @staticmethod
    def test_autofs_dumpmaps(multihost, backupsssdconf, ldap_autofs):
        """
        :title: SSSD frequently fails to return automount maps from LDAP bz967636
        :id: 499275c6-9897-11ed-8e99-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=967636
        :steps:
            1. Have lots of automount entries in an LDAP server (~250 in our case).
            2. On an SSSD+autofs+LDAP client, run `automount --dumpmaps` 10 times.
            3. assert --dumpmaps is returining complete maps from ldap
        :expectedresults:
            1. 250 automount entries should be created
            2. Sssd should not crash
            3. automount --dumpmaps should always return a
                complete set of automount maps from  LDAP.
        """
        # SSSD frequently fails to return automount maps from LDAP bz967636
        client = multihost.client[0]
        master_server = multihost.master[0].sys_hostname
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        # sssd automount maps from LDAP test BZ 967636
        client.run_command("service autofs restart")
        user_dn = f'nisMapName=auto.share,ou=mount,{ds_suffix}'
        user_info = {'objectClass': ['nisMap'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisMapName': 'auto.share'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        # Test autofs dumpmaps consistency.
        for i in range(250):
            user_dn = f'cn=/foo{i},nisMapName=auto.master,ou=mount,{ds_suffix}'
            user_info = {'objectClass': ['nisObject'.encode('utf-8'),
                                         'top'.encode('utf-8')],
                         'cn': f'/foo{i}'.encode('utf-8'),
                         'nisMapName': 'auto.master'.encode('utf-8'),
                         'nisMapEntry': 'auto.share'.encode('utf-8')}
            ldap_inst.add_entry(user_info, user_dn)
            user_dn = f'cn=testkey{i},nisMapName=auto.share,ou=mount,{ds_suffix}'
            user_info = {'objectClass': ['nisObject'.encode('utf-8'),
                                         'top'.encode('utf-8')],
                         'cn': f'testkey{i}'.encode('utf-8'),
                         'nisMapName': 'auto.share'.encode('utf-8'),
                         'nisMapEntry': f'-fstype=nfs,rw {master_server}:/export/foo/testkey{i}'.encode('utf-8')}
            ldap_inst.add_entry(user_info, user_dn)
        dumpmap_fixed_val = "automount - -dumpmaps | wc - l"
        for i in range(1, 11):
            dumpmap_current_val = "automount - -dumpmaps | wc - l"
            assert dumpmap_fixed_val == dumpmap_current_val

    @staticmethod
    def test_autofs_segfaults(multihost, backupsssdconf):
        """
        :title: Automount segfaults in sss nss check header bz1123291
        :id: 44af3d14-9897-11ed-a25c-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1123291
        :setup:
            1. The original SSSD configuration file is backed up and the new
                configuration options are set using the sssd_conf method.
                The options include the filter groups, filter users, and debug level for the nss section.
                The script then sets additional parameters for the domain specified by ds_instance_name.
            2. The SSSD cache is then cleared using the clear_sssd_cache method, and the autofs service is restarted.
        :steps:
            1. The script compiles and runs a C++ program called a1 100 times and not able to see the crash.
        :expectedresults:
            1. Should not crash
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        client.run_command(f'cp -f {SSSD_DEFAULT_CONF}.orig {SSSD_DEFAULT_CONF}')
        tools.sssd_conf("nss", {'filter_groups': 'root',
                                'filter_users': 'root',
                                'debug_level': '9'}, action='update')
        ldap_params = {'use_fully_qualified_names': False,
                       'ldap_search_base': f'{ds_suffix}',
                       'ldap_autofs_map_object_class': 'nisMap',
                       'ldap_autofs_map_name': 'nisMapName',
                       'ldap_autofs_entry_object_class': 'nisObject',
                       'ldap_autofs_entry_key': 'cn',
                       'ldap_autofs_entry_value': 'nisMapEntry'}
        tools.sssd_conf(f'domain/{ds_instance_name}', ldap_params)
        tools.clear_sssd_cache()
        time.sleep(2)
        client.run_command("service autofs restart")
        client.run_command("g++ -lpthread -o a1 /tmp/a1.cpp")
        client.run_command("chmod +x a1")
        for _ in range(100):
            cmd = client.run_command("./a1")
            assert cmd.returncode == 0
