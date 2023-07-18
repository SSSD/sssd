""" Automation of password policy test suite

:requirement: password_policy
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import re
import time
import pytest
from constants import ds_instance_name
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client_bool


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_password_check_syntax')
@pytest.mark.passwordcheck
class TestPasswordCheck(object):
    """
    This is test case class for password policy test suite
    """
    @staticmethod
    @pytest.mark.tier2
    def test_0001_changeuserpass(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: password_policy: Change users
         password with ldap_pwmodify_mode in sssd.conf
        :id: dc70641a-bf1b-445c-926c-7ca693a87615
        :customerscenario: True
        """
        # Automation of BZ795044(rhel7) and BZ1695574(rhel8)
        # "exop" will change password with extended operation,
        # "ldap_modify" with direct modification of userPassword attribute.
        tools = sssdTools(multihost.client[0])
        user = 'foo9@%s' % ds_instance_name
        section = "domain/%s" % ds_instance_name
        for value in ['exop', 'ldap_modify']:
            domain_parameter = {'ldap_pwmodify_mode': value}
            tools.sssd_conf(section, domain_parameter, action='update')
            tools.clear_sssd_cache()
            time.sleep(5)
            change_pass = tools.change_user_password(user, 'Secret123',
                                                     'Secret123',
                                                     'bumblebee@123',
                                                     'bumblebee@123')
            assert change_pass == 3
            # Verify the login of user with updated password
            ssh = check_login_client_bool(multihost, user, 'bumblebee@123')

            # Revert back the password to old one
            change_pass_old = tools.change_user_password(user, 'bumblebee@123',
                                                         'bumblebee@123',
                                                         'Secret123',
                                                         'Secret123')
            assert ssh, f'{user} is not able to login.'
            assert change_pass_old == 3

    @staticmethod
    @pytest.mark.tier2
    def test_0002_newpassnotmatch(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: password_policy: New password is
         not matching with retype password with ldap_pwmodify_mode in sssd.conf
        :id: ef5a83f3-4560-46dd-b7e7-c6bbdf0da551
       """
        # Automation of BZ795044(rhel7) and BZ1695574(rhel8)
        # "exop" will change password with extended operation,
        # "ldap_modify" with direct modification of userPassword attribute.
        tools = sssdTools(multihost.client[0])
        user = 'foo9@%s' % ds_instance_name
        section = "domain/%s" % ds_instance_name
        rm_secure_log = 'echo > /var/log/secure'
        for value in ['exop', 'ldap_modify']:
            multihost.client[0].run_command(rm_secure_log)
            domain_parameter = {'ldap_pwmodify_mode': value}
            tools.sssd_conf(section, domain_parameter, action='update')
            tools.clear_sssd_cache()
            change_pass = tools.change_user_password(user, 'Secret123',
                                                     'Secret123',
                                                     'bumblebee@123',
                                                     'bumblebee')
            assert change_pass == 5

    @staticmethod
    @pytest.mark.tier2
    def test_0003_smallnewpass(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: password_policy: Check new
         password quality check with ldap_pwmodify_mode in sssd.conf
        :id: 00c39f98-3420-4e95-ac96-0929fe771eff
       """
        # Automation of BZ795044(rhel7) and BZ1695574(rhel8)
        # "exop" will change password with extended operation,
        # "ldap_modify" with direct modification of userPassword attribute.
        # BZ1795220(rhel8.3)
        tools = sssdTools(multihost.client[0])
        user = 'foo9@%s' % ds_instance_name
        section = "domain/%s" % ds_instance_name
        rm_secure_log = 'echo > /var/log/secure'
        for value in ['exop', 'ldap_modify']:
            multihost.client[0].run_command(rm_secure_log)
            domain_parameter = {'ldap_pwmodify_mode': value}
            tools.sssd_conf(section, domain_parameter, action='update')
            tools.clear_sssd_cache()
            change_pass = tools.change_user_password(user, 'Secret123',
                                                     'Secret123', 'red_32',
                                                     'red_32')
            assert change_pass == 4
            log1 = re.compile(r'pam_sss.passwd:chauthtok.:\sUser\sinfo\s'
                              r'message:\sPassword\schange\sfailed.*')
            time.sleep(5)
            test_str_log = multihost.client[0].get_file_contents(
                '/var/log/secure')
            assert log1.search(test_str_log.decode())

    @staticmethod
    @pytest.mark.tier2
    def test_0004_wrongcurrentpass(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: password_policy: Check wrong
         current password with ldap_pwmodify_mode in sssd.conf
        :id: 12ce875a-d8b9-4165-980a-f649459f45f0
        """
        # Automation of BZ795044(rhel7) and BZ1695574(rhel8)
        # "exop" will change password with extended operation,
        # "ldap_modify" with direct modification of userPassword attribute.
        tools = sssdTools(multihost.client[0])
        user = 'foo9@%s' % ds_instance_name
        section = "domain/%s" % ds_instance_name
        rm_secure_log = 'echo > /var/log/secure'
        for value in ['exop', 'ldap_modify']:
            multihost.client[0].run_command(rm_secure_log)
            domain_parameter = {'ldap_pwmodify_mode': value}
            tools.sssd_conf(section, domain_parameter, action='update')
            tools.clear_sssd_cache()
            change_pass = tools.change_user_password(user, 'Secret123',
                                                     'secret@123',
                                                     'redhat@321',
                                                     'redhat@321')
            assert change_pass == 6
            log1 = re.compile(r'Password\schange\sfailed.\sServer\smessage:\s'
                              r'Old\spassword\snot\saccepted.')
            time.sleep(5)
            test_str_log = multihost.client[0].get_file_contents(
                '/var/log/secure')
            assert log1.search(test_str_log.decode())
