""" Automation of password policy test suite"""
from __future__ import print_function
from constants import ds_instance_name
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSHClient
import pytest
import re
import time


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_password_check_syntax')
@pytest.mark.passwordcheck
class TestPasswordCheck(object):
    """
    This is test case class for password policy test suite
    """
    @pytest.mark.tier2
    def test_0001_chnageuserpass(self, multihost):
        """
        @Title: IDM-SSSD-TC: ldap_provider: password_policy: Change users
        password with ldap_pwmodify_mode in sssd.conf

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
            change_pass = tools.change_user_password(user, 'Secret123',
                                                     'Secret123',
                                                     'bumblebee@123',
                                                     'bumblebee@123')
            assert change_pass == 3
            # Verify the login of user with updated password
            ssh = SSHClient(multihost.client[0].external_hostname,
                            username=user, password='bumblebee@123')
            assert ssh.connect
            ssh.close()

            # Revert back the password to old one
            change_pass_old = tools.change_user_password(user, 'bumblebee@123',
                                                         'bumblebee@123',
                                                         'Secret123',
                                                         'Secret123')
            assert change_pass_old == 3

    @pytest.mark.tier2
    def test_0002_newpassnotmatch(self, multihost):
        """
        @Title: IDM-SSSD-TC: ldap_provider: password_policy: New password is
        not matching with retype password with ldap_pwmodify_mode in sssd.conf
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

    @pytest.mark.tier2
    def test_0003_smallnewpass(self, multihost):
        """
        @Title: IDM-SSSD-TC: ldap_provider: password_policy: Check new
        password quality check with ldap_pwmodify_mode in sssd.conf
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

    @pytest.mark.tier2
    def test_0004_wrongcurrentpass(self, multihost):
        """
        @Title: IDM-SSSD-TC: ldap_provider: password_policy: Check wrong
        current password with ldap_pwmodify_mode in sssd.conf
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
