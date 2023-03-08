"""Automation for krb ldap connection

:requirement: krb_ldap_connection
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import subprocess
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.krbldapconnection
@pytest.mark.tier1_3
@pytest.mark.usefixtures('setup_sssd',
                         'create_posix_usersgroups',
                         'krb_connection_timeout')
class TestKrbLdapConnectionTimeout(object):
    """
    This is test case class for krb_ldap_connection suite

    Test connection expiration between SSSD and LDAP server. Test for
    default connection expire timeout and test for some arbitrary time period,
    (in our case, 100 second), invalid timeout period (-100 second), and 0
    second.

    timeouts that we are testing for. 'default' implies default timeout for
    sssd which is 900 seconds/15 min. 'timeout_out_of_range' is a timeout
    beyond the integer range. Also test the connection timeout between SSSD
    and Kerberos server. So, sssd won't restart succesfully. 'krb' implies
    connection expires when ticket expires (2 min for our test case).
    Connection expires as soon as TGT expires (2 min in our case).
    """
    def test_0001_timeoutdefault(self, multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_ldap_connection:
         Test if connection expires for the default value of ldap connection
         timeout that is 900 seconds(15 minutes) after that it should release
         the connection
        :id: 53ba0b29-f5fc-4daa-8730-04a8aec91829
        """
        domain_params = {'ldap_connection_expire_timeout': None}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params, 'delete')
        multihost.client[0].log.info(
            '\n\n\nTesting for default value of ldap_'
            'connection_expire_timeout; i.e. ldap_connection_'
            'expire_timeout = default')
        domain_params = {
            'ldap_uri': 'ldap://%s' % (multihost.master[0].sys_hostname)}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)
        self.run_test(900, multihost)

    def test_0002_timeout100(self, multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_ldap_connection:
         Test for arbitrary value ldap connection timeout that is 100
         seconds after that it should release the connection
        :id: bb8dee0a-8ade-4618-b616-589bfcd46ef3
        """
        multihost.client[0].log.info(
            '\n\n\nTesting for ldap_connection_expire_'
            'timeout = 100')
        domain_params = {
            'ldap_uri': 'ldap://%s' % (multihost.master[0].sys_hostname)}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)
        domain_params = {'ldap_connection_expire_timeout': 100}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)

        self.run_test(100, multihost)

    def test_0003_timeouttimeoutoutofrange(self, multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_ldap_connection:
         Test for out of range value of ldap connection timeout that
         is value out of range of integer
        :id: a3773739-41c7-4379-82d0-721d6993633c
        :expectedresults: SSSD sevice must fail to restart
         successfully after entering that value in configuration
        """

        multihost.client[0].log.info(
            '\n\n\nTesting for the case where timeout value is'
            'out of range (of integer). ldap_connection_expire_'
            'timeout = timeout_out_of_range')
        cmd_max_value = "echo $((`getconf INT_MAX`+1))"
        cmd = multihost.client[0].run_command(cmd_max_value)
        timeout = int(cmd.stdout_text.replace("\n", ""))
        domain_params = {
            'ldap_uri': 'ldap://%s' % (multihost.master[0].sys_hostname)}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)
        domain_params = {'ldap_connection_expire_timeout': timeout}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)
        tools = sssdTools(multihost.client[0])
        domainname = tools.get_domain_section_name()
        tools.delete_sssd_domain_log(domainname)
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name

        clear_sssd_cache = True
        try:
            # stop sssd service
            multihost.client[0].service_sssd('stop')
            # remove sssd cache
            location = '/var/lib/sss/db/'
            if not sssdTools(multihost.client[0]).remove_sss_cache(location):
                multihost.client[0].log.info('Failed to delete sssd cache')
                assert False
            cmd_start = 'systemctl start sssd'
            multihost.client[0].run_command(cmd_start)

        except subprocess.CalledProcessError:
            clear_sssd_cache = False

        if not clear_sssd_cache:
            string = "Numerical result out of range"
            file_content = multihost.client[0].get_file_contents(logfile)
            x = string.encode('utf-8') in file_content
            if x is True:
                assert True
            else:
                assert False
            return

    def test_0004_timeoutminus100(self, multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_ldap_connection:
         Test of invalid value of ldap connection timeout that is
         -100 in our case.
        :id: d68b6d42-30bd-4abb-bbf4-363388da931d
        :expectedresults: It shoud instatly release the
         connection after establishing
        """
        multihost.client[0].log.info(
            '\n\n\nTesting for ldap_connection_expire_'
            'timeout = -100')
        domain_params = {
            'ldap_uri': 'ldap://%s' % (multihost.master[0].sys_hostname)}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)
        domain_params = {'ldap_connection_expire_timeout': -100}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)

        self.run_test(-100, multihost)

    def test_0005_timeout0(self, multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_ldap_connection:
         Test for value of ldap connection timeout 0.
        :id: 39af02aa-0860-4189-afc9-3ead42fd5fc1
        :expectedresults: It should have to release
         the connection instantly after establishing
        """
        multihost.client[0].log.info(
            '\n\n\nTesting for ldap_connection_expire_'
            'timeout = 0')
        domain_params = {
            'ldap_uri': 'ldap://%s' % (multihost.master[0].sys_hostname)}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)
        domain_params = {'ldap_connection_expire_timeout': 0}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params)

        self.run_test(0, multihost)

    def run_test(self, timeout, multihost):
        """
        Runs the remaining test
        :param str timeout:takes the vlalue of timeout for ldap
         and string 'krb' in case of kerberos
        :param obj multihost: multihost object

        :Steps:
              1. Setup ldap_connection_expire_timeout to a certain timeout. For
              Kerberos, this is redundant as connection expires as soon as the
              ticked expires.
              2. Lookup a user and get the port number and sleep for the
              timeout period.
              3. Lookup another user and get the port number.
              4. Compare the 2 port numbers.
        """
        tools = sssdTools(multihost.client[0])
        domainname = tools.get_domain_section_name()
        tools.delete_sssd_domain_log(domainname)
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name

        sssdTools(multihost.client[0]).clear_sssd_cache()

        if timeout == 'krb':
            timeout = 120
        else:
            string = "Option ldap_connection_expire_timeout has value %s" % \
                     timeout
            file_content = multihost.client[0].get_file_contents(logfile)
            x = string.encode('utf-8') in file_content
            if x is True:
                assert True
            else:
                assert False
        lookup_u = 'getent passwd foo1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(lookup_u)
        assert cmd.returncode == 0

        def find_local_port():
            nsreport = multihost.client[0].run_command(
                ["ss", "-ant"], log_stdout=False).stdout_text
            lines = nsreport.splitlines()
            lines1 = []

            for i in lines:
                if i.find('389') != -1 and i.find('ESTAB') != -1:
                    lines1.append(i)
            del lines

            if len(lines1) > 1:
                assert False

            lines1 = lines1[0]
            port = lines1[
                lines1.find(':') + 1: lines1.find(' ', lines1.find(':'))
            ]
            return int(port)

        localport1 = find_local_port()

        time.sleep(timeout + 5) if timeout > 0 else time.sleep(5)

        lookup_u = 'getent passwd foo2@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(lookup_u)
        assert cmd.returncode == 0

        localport2 = find_local_port()

        assert localport1 != localport2
        if timeout > 0:
            string = "Connection is about to expire, releasing it"
            file_content = multihost.client[0].get_file_contents(logfile)
            x = string.encode('utf-8') in file_content
            if x is True:
                assert True
            else:
                assert False
        cmd_remove_log = "rm /var/log/sssd/sssd_example1.log"
        multihost.client[0].run_command(cmd_remove_log)
