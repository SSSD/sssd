"""Automation for Krb Fast Principal tests ported from bash

:requirement: krb_fast_principal
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import pytest
import time
from constants import ds_instance_name
from sssd.testlib.common.ssh2_python import check_login_client_bool, check_login_client
from sssd.testlib.common.utils import sssdTools


@pytest.fixture(scope='class')
def create_keytab(multihost, request):
    """
    Configure keytab for this test
    """
    client_hostname = multihost.client[0].sys_hostname
    master_hostname = multihost.master[0].sys_hostname
    multihost.master[0].run_command("cp -vfr /opt /tmp/")
    multihost.client[0].run_command("cp -vfr /opt /tmp/")
    multihost.client[0].run_command("cp -vf /etc/krb5.keytab /etc/krb5.keytab_anuj")
    multihost.master[0].run_command("rm -vf /opt/*")
    multihost.client[0].run_command("rm -vf /opt/*")
    for command in [f'kadmin.local -q "addprinc -randkey ldap/{master_hostname}@EXAMPLE.TEST"',
                    f'kadmin.local -q "ktadd -k /etc/krb5.keytab ldap/{master_hostname}@EXAMPLE.TEST"',
                    f'kadmin.local -q "addprinc -randkey host/{client_hostname}@EXAMPLE.TEST"',
                    f'kadmin.local -q "ktadd -k /opt/sssd_client_invalid.keytab host/{client_hostname}@EXAMPLE.TEST"',
                    f'kadmin.local -q "ktadd -k /opt/sssd_client_valid.keytab host/{client_hostname}@EXAMPLE.TEST"',
                    'kadmin.local -q "addprinc -randkey host/invalidhost.redhat.com@EXAMPLE.TEST"',
                    'kadmin.local -q "ktadd -k /opt/invalid.keytab host/invalidhost.redhat.com@EXAMPLE.TEST"',
                    'kadmin.local -q "delprinc -force host/invalidhost.redhat.com@EXAMPLE.TEST"',
                    'chmod 777 /etc/krb5.keytab',
                    'restorecon -v /etc/krb5.keytab']:
        multihost.master[0].run_command(command, raiseonerr=False)
    file_content = multihost.master[0].get_file_contents("/opt/sssd_client_valid.keytab")
    multihost.client[0].put_file_contents("/etc/krb5.keytab", file_content)
    multihost.client[0].run_command("restorecon -v /etc/krb5.keytab")

    def restore():
        """ Restore configuration """
        multihost.master[0].run_command("rm -vf /opt/*")
        multihost.master[0].run_command("cp -vfr /tmp/opt/* /opt")
        multihost.master[0].run_command("rm -vfr /tmp/opt")
        multihost.client[0].run_command("rm -vf /opt/*", raiseonerr=False)
        multihost.client[0].run_command("cp -vfr /tmp/opt/* /opt", raiseonerr=False)
        multihost.client[0].run_command("rm -vfr /tmp/opt", raiseonerr=False)
        multihost.client[0].run_command("cp -vf /etc/krb5.keytab_anuj /etc/krb5.keytab")
        multihost.client[0].run_command("restorecon -v /etc/krb5.keytab")

    request.addfinalizer(restore)


def krb5_fast_setup(client, krb5_use_fast, krb5_fast_principal, **krb5_validate):
    """ To Customize domain parameters for Test Cases
        :client: This will contain client host configuration
        :krb5_use_fast: This will contain value for FAST kerberos pre authentication
                The following options are supported: never/try/demand
        :krb5_fast_principal: This will specify the client principal to use for FAST
                These following options will be tested:
                - Client kerberos principal
                - invalid
                - principal@TEST.TEST
                - null
        :kwargs: This option will append the key value pair (if provided) to sssd.conf, It is expected to get
                key as 'krb5_validate' and 'True' as a value.
    """
    tools = sssdTools(client)
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {
        'krb5_use_fast': krb5_use_fast,
        'krb5_fast_principal': krb5_fast_principal}
    for key, value in krb5_validate.items():
        domain_params[key] = value
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.fixture(scope='class')
def custom_setup(multihost, setup_sssd_krb, create_posix_usersgroups, krb_connection_timeout):
    """ Added neccessary sssd domain parameters """
    tools = sssdTools(multihost.client[0])
    sssd_params = {'services': "nss, pam",
                   'config_file_version': 2}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'access_provider': 'krb5',
                     'use_fully_qualified_names': 'False',
                     'override_homedir': '/home/%u'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.mark.tier2
@pytest.mark.krbfastprincipal
@pytest.mark.usefixtures('custom_setup', 'create_keytab')
class TestKrbFastPrincipal():
    """
    This is test case class for krb_fast_principal suite

    Test FAST pre authentication by kerberos on the basis of krb5_fast_principal.
    Test for valid and invalid principals, Test for principals with only
    kerberos realm, Test for null principals, Tests for all the previous
    scenarios with krb5_validate set to true.
    """
    @staticmethod
    def test_0001_valid_principal(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_fast_principal: krb5_fast_principal is a valid principal
        :id: d8752706-8ddd-4eaa-a84c-b9b136198c1e
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal in sssd.conf \
             and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal host/$Client@EXAMPLE.TEST in keytab
             Principal matched to the sample (host/$Client@EXAMPLE.TEST)
        """
        krb5_fast_setup(multihost.client[0], 'demand', f'host/{multihost.client[0].sys_hostname}')
        ssh = check_login_client_bool(multihost, "foo1", "Secret123")
        time.sleep(3)
        file = '/var/log/sssd/krb5_child.log'
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert ssh, 'foo1 is not able to login.'
        assert f"Trying to find principal host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST in keytab" \
               in krb5_child_log, f"principal host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST not found in keytab"
        assert f"Principal matched to the sample (host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST)" \
               in krb5_child_log, "Principals did not match"

    @staticmethod
    def test_0002_invalid_principal(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_access_provider: krb5_fast_principal is an invalid principal
        :id: 5c676a70-c094-4936-85b4-e25a5c33d735
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal in sssd.conf \
             and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should not be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal invalid@EXAMPLE.TEST in keytab
             No principal matching invalid@EXAMPLE.TEST found in keytab
        """
        krb5_fast_setup(multihost.client[0], 'try', 'invalid')
        with pytest.raises(Exception):
            check_login_client(multihost, "foo1", "Secret123")
        file = '/var/log/sssd/krb5_child.log'
        time.sleep(3)
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert "Trying to find principal invalid@EXAMPLE.TEST in keytab" in krb5_child_log, \
               "principal invalid@EXAMPLE.TEST not found in keytab"
        assert "No principal matching invalid@EXAMPLE.TEST found in keytab" in krb5_child_log, \
               "principal invalid@EXAMPLE.TEST found in keytab"

    @staticmethod
    def test_0003_principal_at_test_test(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_fast_principal: krb5_fast_principal is principal@TEST.TEST
        :id: 4de7beed-24af-4316-9b8f-88b7deb28e0d
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal in sssd.conf \
             and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should not be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal principal@TEST.TEST in keytab
        """
        krb5_fast_setup(multihost.client[0], 'demand', 'principal@TEST.TEST')
        with pytest.raises(Exception):
            check_login_client(multihost, "foo1", "Secret123")
        time.sleep(3)
        file = '/var/log/sssd/krb5_child.log'
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert "Trying to find principal principal@TEST.TEST in keytab" in krb5_child_log, \
               "principal principal@TEST.TEST not found in keytab"

    @staticmethod
    def test_0004_null_principal(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_fast_principal: krb5_fast_principal is null
        :id: 426d9d4d-4a9b-4de9-b3ee-d1d2bab22c67
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal in sssd.conf \
             and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal (null)@EXAMPLE.TEST in keytab
        """
        krb5_fast_setup(multihost.client[0], 'demand', '')
        ssh = check_login_client_bool(multihost, "foo1", "Secret123")
        time.sleep(3)
        file = '/var/log/sssd/krb5_child.log'
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert ssh, 'foo1 is not able to login.'
        assert "Trying to find principal (null)@EXAMPLE.TEST in keytab" in krb5_child_log, \
               "principal (null)@EXAMPLE.TEST not found in keytab"

    @staticmethod
    def test_0005_valid_principal_and_krb5_validate_true(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_fast_principal: krb5_fast_principal is valid \
            and krb5_validate is true
        :id: 35e8a59a-1c81-4836-b5b8-58f66f6369e1
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal and set krb5_validate to true \
            in sssd.conf and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal host/$Client@EXAMPLE.TEST in keytab
             Principal matched to the sample (host/$Client@EXAMPLE.TEST)
             TGT verified using key for [host/$Client@EXAMPLE.TEST]
        """
        krb5_fast_setup(multihost.client[0], 'demand', f'host/{multihost.client[0].sys_hostname}',
                        krb5_validate='true')
        ssh = check_login_client_bool(multihost, "foo1", "Secret123")
        time.sleep(3)
        file = '/var/log/sssd/krb5_child.log'
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert ssh, 'foo1 is not able to login.'
        assert f"Trying to find principal host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST in keytab"\
            in krb5_child_log, f"principal host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST not found in keytab"
        assert f"Principal matched to the sample (host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST)" \
            in krb5_child_log, "Principals did not match"
        assert f"TGT verified using key for [host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST]" \
            in krb5_child_log, f"TGT did not not verify for [host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST]"

    @staticmethod
    def test_0006_invalid_principal_and_krb5_validate_true(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb5_fast_principal: krb5_fast_principal is invalid \
                and krb5_validate is true
        :id: cdda86ae-2418-427c-a64a-4af277f4b11b
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal and set krb5_validate to true \
            in sssd.conf and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should not be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal invalid@EXAMPLE.TEST in keytab
             No principal matching invalid@EXAMPLE.TEST found in keytab
        """
        krb5_fast_setup(multihost.client[0], 'try', 'invalid', krb5_validate='true')
        with pytest.raises(Exception):
            check_login_client(multihost, "foo1", "Secret123")
        file = '/var/log/sssd/krb5_child.log'
        time.sleep(3)
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert "Trying to find principal invalid@EXAMPLE.TEST in keytab" in krb5_child_log, \
            "principal invalid@EXAMPLE.TEST not found in keytab"
        assert "No principal matching invalid@EXAMPLE.TEST found in keytab" in krb5_child_log, \
            "principal matching found in keytab"

    @staticmethod
    def test_0007_principal_at_test_test_and_krb5_validate_true(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb5_fast_principal: krb5_fast_principal is principal@TEST.TEST \
            and krb5_validate is true
        :id: 73f125d4-8e50-4fe5-a3da-074279220251
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal and set krb5_validate to true \
            in sssd.conf and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should not be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal principal@TEST.TEST in keytab
        """
        krb5_fast_setup(multihost.client[0], 'demand', 'principal@TEST.TEST', krb5_validate='true')
        with pytest.raises(Exception):
            check_login_client(multihost, "foo1", "Secret123")
        time.sleep(3)
        file = '/var/log/sssd/krb5_child.log'
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert "Trying to find principal principal@TEST.TEST in keytab" in krb5_child_log, \
            "principal principal@TEST.TEST not found in keytab"

    @staticmethod
    def test_0008_null_principal_and_krb5_validate_true(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb5_fast_principal: krb5_fast_principal is (null)@EXAMPLE.TEST \
            and krb5_validate is true
        :id: 069691bc-3f07-4eac-ad48-c91c56b9a7ba
        :setup:
          1. Set the values of krb5_use_fast and krb5_fast_principal and set krb5_validate to true \
            in sssd.conf and restart sssd.
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check the krb5_child log for expected messages.
        :expectedresults:
          1. User foo1 should be able to successfully login
          2. Krb5_child Log contains the expected lines:
             Trying to find principal (null)@EXAMPLE.TEST in keytab
        """
        krb5_fast_setup(multihost.client[0], 'demand', '', krb5_validate='true')
        ssh = check_login_client_bool(multihost, "foo1", "Secret123")
        file = '/var/log/sssd/krb5_child.log'
        time.sleep(3)
        krb5_child_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        assert ssh, 'foo1 is not able to login.'
        assert "Trying to find principal (null)@EXAMPLE.TEST in keytab" in krb5_child_log, \
            "principal (null)@EXAMPLE.TEST not found in keytab"
        assert f"TGT verified using key for [host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST]"\
            in krb5_child_log, f"TGT did not not verify for [host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST]"
