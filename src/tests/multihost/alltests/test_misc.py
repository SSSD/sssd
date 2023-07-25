""" Automation of misc bugs

:requirement: IDM-SSSD-REQ : LDAP Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

from __future__ import print_function
import re
import time
import subprocess
import pytest
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.exceptions import SSHLoginException
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups'
                         )
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
    def test_0002_offbyonereconn(self,
                                 multihost, backupsssdconf):
        """
        :title: off by one in reconnection retries option intepretation
        :id: 85c5357d-0cc4-4a32-b36a-00ed530865ad
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1801401
        """
        tools = sssdTools(multihost.client[0])
        domainname = tools.get_domain_section_name()
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        params = {'debug_level': '9',
                  'reconnection_retries': '1'}
        tools.sssd_conf('nss', params)
        multihost.client[0].service_sssd('start')
        sssd_be = 'sssd_be --domain %s' % domainname
        pid_sssd_be = 'pgrep -f %s' % sssd_be
        kill_sssd_be = 'pkill sssd_be'
        try:
            multihost.client[0].run_command(kill_sssd_be, raiseonerr=False)
        except subprocess.CalledProcessError:
            pytest.fail("Unable to kill the sssd_be process")
        time.sleep(3)
        log_file = '/var/log/sssd/sssd_nss.log'
        log_str = multihost.client[0].get_file_contents(log_file)
        log1 = re.compile(r'Performing\sauto-reconnect')
        result = log1.search(log_str.decode())
        getent = 'getent passwd foo1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(getent, raiseonerr=False)
        multihost.client[0].service_sssd('stop')
        tools.sssd_conf('nss', params, action='delete')
        multihost.client[0].service_sssd('start')
        assert result is not None or cmd.returncode == 0

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
                         'entry_cache_timeout': '5400',
                         'refresh_expired_interval': '4000'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        multihost.client[0].service_sssd('restart')
        user = 'foo1@%s' % domain_name
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret1234', debug=False)
        with pytest.raises(SSHLoginException):
            client.login(login_timeout=10,
                         sync_multiplier=1, auto_prompt_reset=False)
        time.sleep(2)
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login(login_timeout=30,
                         sync_multiplier=5, auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()

        for _ in range(3):
            client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                                 'Secret1234', debug=False)
            with pytest.raises(SSHLoginException):
                client.login(login_timeout=10,
                             sync_multiplier=1, auto_prompt_reset=False)
        time.sleep(2)
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login(login_timeout=30,
                         sync_multiplier=5, auto_prompt_reset=False)
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()
        time.sleep(2)
        cmd_id = 'id %s' % user
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
