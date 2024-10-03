""" Automation of misc bugs

:requirement: IDM-SSSD-REQ : LDAP Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import time
import subprocess
import pytest
import textwrap
from datetime import datetime as D_T
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_instance_name, ds_suffix, ds_rootdn, ds_rootpw
from sssd.testlib.common.ssh2_python import check_login_client
from sssd.testlib.common.helper_functions import count_pattern_logs, client_remove_file


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    return string_name in log_str


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.misc
class TestMisc(object):
    """
    This is for misc bugs automation
    """
    @pytest.mark.tier1
    def test_0001_ldapcachepurgetimeout(self,
                                        multihost, backupsssdconf):
        """
        :title: ldap_purge_cache_timeout validates most of
         the entries once the cleanup task kicks in.
        :id: 5ed009f4-6462-402c-a1fe-4bef7fb0ef73
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1471808
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        domainname = tools.get_domain_section_name()
        section = "domain/%s" % ds_instance_name
        params = {'enumerate': 'True',
                  'ldap_enumeration_refresh_timeout': '30',
                  'ldap_purge_cache_timeout': '60',
                  'entry_cache_timeout': '20'}
        tools.sssd_conf(section, params)
        multihost.client[0].service_sssd('start')
        try:
            multihost.client[0].run_command('id foo1@%s' % domainname,
                                            raiseonerr=False)
        except subprocess.CalledProcessError:
            pytest.fail("Unable to fetch the user foo1@%s" % domainname)
        for i in range(2):
            time.sleep(60)
            log_file = '/var/log/sssd/sssd_%s.log' % domainname
            log_str = multihost.client[0].get_file_contents(log_file)
            log1 = re.compile(r'Found 0 expired user')
            result = log1.search(log_str.decode())
            if result is not None:
                status = 'PASS'
            else:
                status = 'FAIL'
            log2 = re.compile(r'Found [1-9]* expired user')
            result1 = log2.search(log_str.decode())
            if result1 is None:
                status = 'PASS'
            else:
                status = 'FAIL'
        multihost.client[0].service_sssd('stop')
        tools.sssd_conf(section, params, action='delete')
        multihost.client[0].service_sssd('start')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0003_sssd_crashes_after_update(self, multihost,
                                            backupsssdconf):
        """
        :title: misc: sssd crashes after last update to
         sssd-common-1.16.4-37.el7_8.1
        :id: 55cbdb9c-c62e-4604-8c77-9d70dd333a50
        :customerscenario: True
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1854317
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        client = sssdTools(multihost.client[0])
        domain_params = {'cache_credentials': 'true',
                         'refresh_expired_interval': '4000'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        s_param = {'domains': f'{domain_name}, local'}
        tools.sssd_conf('sssd',s_param, action='update')
        param = {'id_provider': 'proxy',
                 'proxy_lib_name': 'files',
                 'passwd_files': '/etc/passwd',
                 'proxy_pam_target': 'sssd-shadowutils'}
        tools.sssd_conf('domain/local', param)
        multihost.client[0].service_sssd('restart')
        user = f'foo1@{domain_name}'
        check_login_client(multihost, user, "Secret123")
        time.sleep(2)
        for _ in range(3):
            check_login_client(multihost, user, "Secret123")
        time.sleep(2)
        check_login_client(multihost, user, "Secret123")
        time.sleep(2)
        cmd_id = f'id {user}'
        cmd = multihost.client[0].run_command(cmd_id)
        if "no such user" in cmd.stdout_text:
            status = "FAIL"
        else:
            status = "PASS"
        assert status == "PASS"

    @pytest.mark.tier1
    def test_0004_sssd_api_conf(self, multihost, backupsssdconf):
        """
        :title: sssd.api.conf and sssd.api.d
         should belong to python-sssdconfig package
        :id: 4c6bd6a2-d7eb-4c2c-9346-a89b2bdd553e
        :description: Verify by removing sssd-common that
         sssd.api.conf, sssd.api.d is part of python-sssdconfig package
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1800564 (RHEL7.8)
         https://bugzilla.redhat.com/show_bug.cgi?id=1829470 (RHEL8.2)
        """
        # remove sssd-common package
        rpm_remove = 'rpm -e sssd-common --nodeps'
        try:
            multihost.client[0].run_command(rpm_remove)
        except subprocess.CalledProcessError:
            print("Failed to remove sssd-common package")
            status = 'FAIL'
        else:
            python_cmd = "python3 -c 'from SSSDConfig import"\
                         " SSSDConfig; print(SSSDConfig());'"
            cmd = multihost.client[0].run_command(python_cmd, raiseonerr=False)
            if cmd.returncode != 0:
                status = 'FAIL'
            else:
                status = 'PASS'
        # reinstall sssd-common
        install = 'yum -y install sssd-common'
        multihost.client[0].run_command(install, raiseonerr=False)
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0005_getent_homedirectory(self, multihost,
                                       backupsssdconf):
        """
        :title: misc: fallback_homedir returns '/'
         for empty home directories in passwd file
        :id: 69a6b54e-a8eb-4145-8554-c5e666d82276
        :customerscenario: True
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1660693
        """
        multihost.client[0].service_sssd('restart')
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_info = {'cn': 'user_exp4'.encode('utf-8'),
                     'objectClass': [b'top', b'person',
                                     b'inetOrgPerson',
                                     b'organizationalPerson',
                                     b'posixAccount'],
                     'sn': 'user_exp'.encode('utf-8'),
                     'uid': 'user_exp'.encode('utf-8'),
                     'userPassword': 'Secret123'.encode('utf-8'),
                     'homeDirectory': ' '.encode('utf-8'),
                     'uidNumber': '121012'.encode('utf-8'),
                     'gidNumber': '121012'.encode('utf-8'),
                     'loginShell': '/bin/bash'.encode('utf-8')}
        user_dn = 'uid=user_exp4,ou=People,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        cmd_getent = "getent passwd -s sss user_exp4@example1"
        cmd = multihost.client[0].run_command(cmd_getent)
        ldap_inst.del_dn(user_dn)
        assert ":/:" not in cmd.stdout_text

    @pytest.mark.tier1_2
    def test_0006_getent_group(self, multihost,
                               backupsssdconf,
                               delete_groups_users):
        """
        :title: 'getent group ldapgroupname' doesn't
         show any LDAP users or some LDAP users when
         'rfc2307bis' schema is used with SSSD
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1817122
        :id: dc81bb8e-72c0-11eb-9eae-002b677efe14
        :customerscenario: true
        :steps:
            1. Configure SSSD with id_provider = ldap and
               set ldap_schema = rfc2307bis
            2. Add necessary users and groups with uniqueMember.
            3. Check 'getent group ldapgroupname' output.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. 'getent group ldapgroupname' should show
               all it's member ldapusers.
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_schema': 'rfc2307bis',
                         'ldap_group_member': 'uniquemember'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        multihost.client[0].service_sssd('restart')
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_info = {
            'ou': 'Unit1'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=Unit1,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'ou': 'Unit2'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=Unit2,ou=Unit1,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'ou': 'users'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=users,ou=Unit2,ou=Unit1,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'ou': 'posix_groups'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=posix_groups,ou=Unit2,' \
                  'ou=Unit1,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'ou': 'netgroups'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=netgroups,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'ou': 'services'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=services,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'ou': 'sudoers'.encode('utf-8'),
            'objectClass': [b'top', b'organizationalUnit']}
        user_dn = 'ou=sudoers,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        for i in range(1, 9):
            user_info = {
                'cn': f'user-{i}'.encode('utf-8'),
                'objectClass': [b'top', b'posixAccount'],
                'uid': f'user-{i}'.encode('utf-8'),
                'uidNumber': f'1111{i}'.encode('utf-8'),
                'gidNumber': f'1111{i}'.encode('utf-8'),
                'homeDirectory': f'/home/user-{i}'.encode('utf-8')}
            user_dn = f'cn=user-{i},ou=users,ou=Unit2,' \
                      f'ou=Unit1,dc=example,dc=test'
            (_, _) = ldap_inst.add_entry(user_info, user_dn)
        for i in range(1, 9):
            user_info = {
                'cn': f'user-{i}'.encode('utf-8'),
                'objectClass': [b'top', b'posixGroup'],
                'gidNumber': f'1111{i}'.encode('utf-8')}
            user_dn = f'cn=user-{i},ou=posix_groups,' \
                      f'ou=Unit2,ou=Unit1,dc=example,dc=test'
            (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {
            'cn': 'group-1'.encode('utf-8'),
            'objectClass': [b'top', b'posixGroup', b'groupOfUniqueNames'],
            'gidNumber': '20001'.encode('utf-8'),
            'uniqueMember': [
                b'cn=user-1,ou=users,ou=unit2,ou=unit1,dc=example,dc=test',
                b'cn=user-3,ou=users,ou=unit2,ou=unit1,dc=example,dc=test',
                b'cn=user-5,ou=users,ou=unit2,ou=unit1,dc=example,dc=test',
                b'cn=user-7,ou=users,ou=unit2,ou=unit1,dc=example,dc=test']}
        user_dn = 'cn=group-1,ou=posix_groups,ou=Unit2,' \
                  'ou=Unit1,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)

        user_info = {
            'cn': 'group-2'.encode('utf-8'),
            'objectClass': [b'top', b'posixGroup', b'groupOfUniqueNames'],
            'gidNumber': '20002'.encode('utf-8'),
            'uniqueMember': [
                b'cn=user-2,ou=users,ou=unit2,ou=unit1,dc=example,dc=test',
                b'cn=user-4,ou=users,ou=unit2,ou=unit1,dc=example,dc=test',
                b'cn=user-6,ou=users,ou=unit2,ou=unit1,dc=example,dc=test',
                b'cn=user-8,ou=users,ou=unit2,ou=unit1,dc=example,dc=test']}
        user_dn = 'cn=group-2,ou=posix_groups,ou=Unit2,' \
                  'ou=Unit1,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        time.sleep(3)
        cmd = multihost.client[0].run_command("getent group "
                                              "group-2@example1")
        assert "group-2@example1:*:20002:user-2@example1," \
               "user-4@example1,user-6@example1," \
               "user-8@example1" in cmd.stdout_text

    @pytest.mark.tier1_2
    def test_0007_getent_admproxy(self, multihost, backupsssdconf):
        """
        :title: 'getent passwd adm@proxy' doesn't return anything when
         'cache_first = True' option is used with nss.
        :description: Lookup with the fully-qualified name of a user or
         group will fail if the requested object is not already in the
         cache.
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2013294
        :id: 9ff64ee0-255d-46ac-bf0a-b022eaad463e
        :customerscenario: false
        :steps:
            1. Configure SSSD with nss having cache_first = True.
            2. restart SSSD with empty cache.
            3. Check 'getent passwd adm@proxy' output.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. 'getent passwd adm@proxy' should return identity lookup
               of user adm.
        """
        getent_admproxy = "getent passwd adm@proxy"
        tools = sssdTools(multihost.client[0])
        section = "sssd"
        section_params = {"domains": "proxy", "services": "nss"}
        tools.sssd_conf(section, section_params, action="update")
        section = "domain/proxy"
        section_params = {"id_provider": "proxy", "proxy_lib_name": "files",
                          'auth_provider': "none"}
        tools.sssd_conf(section, section_params, action="update")
        section = "nss"
        section_params = {"cache_first": "True"}
        tools.sssd_conf(section, section_params, action="update")
        tools.clear_sssd_cache(start=True)
        cache_first_true = multihost.client[0].run_command(getent_admproxy,
                                                           raiseonerr=False)
        assert cache_first_true.returncode == 0, "Bug 2013294/1992973/2013379"
        section = "nss"
        section_params = {"cache_first": "True"}
        tools.sssd_conf(section, section_params, action="delete")
        tools.clear_sssd_cache(start=True)
        cache_first_false = multihost.client[0].run_command(getent_admproxy,
                                                            raiseonerr=False)
        assert cache_first_false.returncode == 0

    @staticmethod
    @pytest.mark.tier1_2
    def test_0008_1636002(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: ldap_provider: socket-activated services start as
         the sssd user and then are unable to read the confdb
        :id: 7a33729a-ab74-4d9e-9d75-e952deaa7bd2
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1636002
        :customerscenario: true
        :steps:
            1. Switch to socket activated services, restart sssd
            2. Check 'getent passwd <user> output.
            3. Run ssh for the user to trigger PAM.
            4. Check log for error messages related to opening
               /var/lib/sss/db/config.ldb
        :expectedresults:
            1. No issue switching and sssd has started.
            2. It should succeed.
            3. /var/log/sssd/sssd_pam.log is present
            4. The error messages are not present.
        :teardown:
            1. Undo socket activation.
            2. Restore sssd.conf
        """
        # pylint: disable=unused-argument
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        domain_name = client.get_domain_section_name()
        user = f'foo1@{domain_name}'

        # Configure socket activation
        sssd_params = {'services': ''}
        client.sssd_conf('sssd', sssd_params)
        client.clear_sssd_cache()
        enable_cmd = "systemctl enable sssd-nss.socket sssd-pam.socket"
        multihost.client[0].run_command(enable_cmd)
        multihost.client[0].service_sssd('restart')

        # Show the sssd config
        multihost.client[0].run_command(
            'cat /etc/sssd/sssd.conf', raiseonerr=False)

        # Run getent passwd
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {user}', raiseonerr=False)

        # Try ssh after socket activation is configured
        # Result does not matter we just need to trigger the PAM stack
        with pytest.raises(Exception):
            check_login_client(multihost, user, 'Secret1234')

        # Download sssd pam log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{domain_name}.log").decode('utf-8')

        # Disable socket activation
        multihost.client[0].run_command(
            "systemctl disable sssd-nss.socket sssd-pam.socket",
            raiseonerr=False)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {user} was not found."
        assert "CONFDB: /var/lib/sss/db/config.ldb" in log_str
        assert "Unable to open tdb '/var/lib/sss/db/config.ldb': " \
               "Permission denied" not in log_str
        assert "Failed to connect to '/var/lib/sss/db/config.ldb'" \
            not in log_str
        assert "The confdb initialization failed" not in log_str

    @staticmethod
    @pytest.mark.tier1
    def test_0009_dbus_method_find_usrby_attr(multihost, backupsssdconf, ldap_posix_usergroup):
        """
        :title: D-Bus method to find user by attributes
        :id: ee3437ff-572e-472e-8f55-0d7d8134266c
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2128840
        :customerscenario: true
        :setup:
          1. In sssd.conf
             set ldap_user_extra_attrs = sn:sn in domain section of sssd.conf
             set user_attributes = +sn in [ifp] section
          2. Create 10 users with 'sn' attribute containing pattern foo
          3. Create a user who does not have sn=foo pattern in it's sn attribute
        :steps:
          1. Restart sssd with clean cache
          2. Fetch users with attribute 'sn:foo*' with dbus-send command
          3. Confirm dbus-send command output has all users with foo*
          4. Confirm dbus-send command output does not contain user
             who donot have sn=foo* matching pattern
        :expectedresults:
          1. SSSD should start successfully
          2. Command should be completed successfully
          3. Expected users with sn:foo* are returned
          4. Expected users without sn:foo* are not returned
        :teardown:
          1. Delete users and groups created for test
          2. Restore sssd.conf
        """
        usr = ldap_posix_usergroup
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        domain_params = {'ldap_search_base': ds_suffix,
                         'auth_provider': 'ldap',
                         'id_provider': 'ldap',
                         'ldap_uri': f'ldaps://{multihost.master[0].sys_hostname}',
                         'ldap_tls_cacert': '/etc/openldap/cacerts/cacert.pem',
                         'use_fully_qualified_names': 'True',
                         'debug_level': '9',
                         'ldap_user_extra_attrs': 'sn:sn'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        client.sssd_conf('ifp', {'user_attributes': '+sn'}, action='add')
        client.clear_sssd_cache()
        dbuscmd = 'dbus-send --system --print-reply --dest=org.freedesktop.sssd.infopipe '\
                  '/org/freedesktop/sssd/infopipe/Users org.freedesktop.sssd.infopipe.Users.ListByAttr '\
                  '"string:sn" "string:foo*" "uint32:0"'
        cmd = multihost.client[0].run_command(dbuscmd, raiseonerr=False)
        for i in range(10):
            cmd2 = multihost.client[0].run_command(f'id -u foo{i}@{domain_name}', raiseonerr=False)
            assert cmd2.stdout_text.strip('\n') in cmd.stdout_text, 'dbus is not fetching expected users'
        cmd1 = multihost.client[0].run_command(f'id -u {usr}@{domain_name}', raiseonerr=False)
        assert cmd1.stdout_text.strip('\n') not in cmd.stdout_text, 'dbus is fetching unwanted user'

    @staticmethod
    @pytest.mark.tier1_4
    def test_bz822236(multihost, backupsssdconf):
        """
        :title: Netgroups do not honor entry cache nowait percentage
        :id: dda33ba4-ef10-11ed-a27d-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=822236
        :setup:
            1. Retrieve the name of the network interface that is currently connected using
                the 'nmcli' command, and saves it to the 'intf' variable.
            2. Sets up an LDAP connection to the LDAP server using the LdapOperations class.
            3. Creates a new organizational unit named "Netgroup" under the base DN
                specified in the 'ds_suffix' variable.
            4. Creates a new LDAP entry for a netgroup named "netgrp_nowait"
                under the "Netgroup" organizational unit.
            5. Use the sssdTools class to update the configuration file for the
                'nss' and 'domain/example1' sections of the SSSD service.
            7. Clear the SSSD cache using the 'clear_sssd_cache' method of the sssdTools class.
            8. Delete the contents of the '/var/log/sssd/sssd_nss.log' file
            9. Add a 50ms delay to the network interface using the 'tc' command.
        :steps:
            1. Measures the response time for the 'getent netgroup netgrp_nowait'
                command and saves it to the 'res_time' variable.
            2. Run a loop that repeats the 'getent netgroup netgrp_nowait' command 4 times
                and checks if the response time is less than to the initial response time.
            3. Wait for 15 seconds before deleting the contents of the '/var/log/sssd/sssd_nss.log' file again.
            4. Remove the network delay added in step 9 using the 'tc' command.
        :expectedresults:
            1. res_time variable will have the response time
            2. Response time is less than to the initial response time
            3. Wait for 15 seconds
            4. Network delay should be removed
        """
        client = multihost.client[0]
        multihost.client[0].run_command("modprobe sch_netem")
        log_nss = '/var/log/sssd/sssd_nss.log'
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        ldap_inst.org_unit("Netgroup", ds_suffix)
        user_dn = f'cn=netgrp_nowait,ou=Netgroup,{ds_suffix}'
        user_info = {'cn': 'netgrp_nowait'.encode('utf-8'),
                     'objectClass': ['nisNetgroup'.encode('utf-8'),
                                     'top'.encode('utf-8')],
                     'nisNetgroupTriple': '(host1,kau10,example.com)'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("nss", {'filter_groups': 'root',
                                'filter_users': 'root',
                                'debug_level': '9',
                                'entry_cache_nowait_percentage': '50'}, action='update')
        tools.sssd_conf("domain/example1",
                        {'entry_cache_timeout': '30',
                         'ldap_netgroup_search_base': f"ou=Netgroup,{ds_suffix}"}, action='update')
        tools.clear_sssd_cache()
        client.run_command(f"> {log_nss}")
        intf = [s for s in client.run_command("nmcli").stdout_text.split('\n')
                if re.search(r'\b' + "connected to" + r'\b', s)][0].split(":")[0]
        client.run_command(f"tc qdisc add dev {intf} root netem delay 50ms")
        start = D_T.now()
        client.run_command("getent netgroup netgrp_nowait")
        end = D_T.now()
        res_time = end - start
        time.sleep(16)
        time_diff = []
        find_logs_results = []
        for _ in range(4):
            start = D_T.now()
            client.run_command("getent netgroup netgrp_nowait")
            end = D_T.now()
            loop_response = end - start
            time_diff.append(loop_response < res_time)
            time.sleep(3)
            find_logs_results.append(find_logs(multihost,
                                               log_nss,
                                               "Performing midpoint cache "
                                               "update of [netgrp_nowait@example1]"))
            client.run_command(f"> {log_nss}")
            time.sleep(15)
        client.run_command(f"tc qdisc del dev {intf} root")
        ldap_inst.del_dn(user_dn)
        ldap_inst.del_dn(f"ou=Netgroup,{ds_suffix}")
        assert all(find_logs_results), "Searched string not found in the logs"
        assert all(time_diff), "Test failed as the cache response time is higher."

    @staticmethod
    @pytest.mark.tier1_2
    def test_0017_filesldap(multihost, backupsssdconf, setup_sssd_krb):
        """
        :title: sssd-be tends to run out of system resources,
            hitting the maximum number of open files
        :id: ad4a4a32-05d7-11ee-9caa-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2195919
        :setup:
            1. Replace /usr/libexec/sssd/krb5_child with a shell script like
                #!/bin/bash
                sleep 10
        :steps:
            1. Login with ldap user and count no of file descriptors before modifying krb5_child
            2. Trigger authentication requests 'sssctl user-checks -a auth
            3. Count no of file descriptors after modifying krb5_child
        :expectedresults:
            1. Login should success
            2. Authentication requests will fail
            3. No of file descriptors should be same as before and after modifying krb5_child
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.clear_sssd_cache()
        user = f'foo1@{ds_instance_name}'
        check_login_client(multihost, user, "Secret123")
        time.sleep(3)
        client.run_command("cp -af /usr/libexec/sssd/krb5_child /usr/libexec/sssd/krb5_child_bkp")
        new_child = textwrap.dedent("""#!/bin/bash\nsleep 10 \n""")
        client.put_file_contents('/usr/libexec/sssd/krb5_child', new_child)
        client.run_command(f"echo 'Secret123'|sssctl user-checks -a auth foo1@{ds_instance_name}")
        time.sleep(3)
        client.run_command('ls -al /proc/$(pidof sssd_be)/fd > /tmp/before_count')
        time.sleep(2)
        n_log_bfr = count_pattern_logs(multihost, "/tmp/before_count", "pipe:")
        for i in range(10):
            client.run_command(f"echo 'Secret123'|sssctl user-checks -a auth foo{i}@{ds_instance_name}")
            time.sleep(3)
            client.run_command(f'ls -al /proc/$(pidof sssd_be)/fd > /tmp/after_count{i}')
        time.sleep(2)
        n_log_afr = []
        for i in range(10):
            n_log_afr.append(count_pattern_logs(multihost, f"/tmp/after_count{i}", "pipe:"))
        client.run_command("cp -a /usr/libexec/sssd/krb5_child_bkp /usr/libexec/sssd/krb5_child")
        for f_file in ["/tmp/before_count", "/usr/libexec/sssd/krb5_child_bkp"]:
            client_remove_file(multihost, f_file)
        for i in range(10):
            client_remove_file(multihost, f"/tmp/after_count{i}")
        for n_n in n_log_afr:
            assert abs(n_log_bfr - n_n) <= 2
