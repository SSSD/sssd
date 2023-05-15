"""Automation for Krb credential cache tests ported from bash

:requirement: krb_credential_cache
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException
from packaging import version
from constants import ds_instance_name


def krb5_ccache_setup(client, request):
    """ To Customize domain parameter for Test Cases """
    tools = sssdTools(client)
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'krb5_ccachedir': request}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.fixture()
def ldap_krb5_setup(session_multihost, request):
    """ To Customize domain parameter for Test Cases """
    tools = sssdTools(session_multihost.client[0])
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'cache_credentials': 'True',
                     'krb5_validate': request.param,
                     'enumerate': 'True',
                     'ldap_krb5_keytab': '/etc/krb5.keytab'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.fixture()
def bz_setup(session_multihost):
    """ Added neccessary domain parameters """
    tools = sssdTools(session_multihost.client[0])
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'ldap_sasl_mech': 'GSSAPI',
                     'ldap_sasl_authid': f'host/{session_multihost.client[0].sys_hostname}',
                     'ldap_krb5_init_creds': 'true',
                     'ldap_krb5_ticket_lifetime': '120',
                     'krb5_validate': 'True'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.fixture(scope='class')
def custom_setup(session_multihost):
    """ Added neccessary initial domain parameters """
    tools = sssdTools(session_multihost.client[0])
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'use_fully_qualified_names': 'False',
                     'access_provider': 'krb5',
                     'chpass_provider': 'krb5',
                     'cache_credentials': 'True',
                     'krb5_ccname_template': 'FILE:%d/krb5cc_%u',
                     'override_homedir': '/home/%u'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.mark.tier2
@pytest.mark.krbcredentialcache
@pytest.mark.usefixtures('session_multihost', 'setup_sssd_krb', 'create_posix_usersgroups',
                         'krb_connection_timeout', 'custom_setup')
class TestKrbCredentialCache():
    """
    This is test case class for krb_credential_cache suite

    Test credential cache dir existence by kerberos on the basis of krb5_ccachedir parameter.
    Test for authentication with keytab through krb5_validate parameter
    Test for authentication when ldap_sasl_mech is set to GSSAPI also to validate the cache file
    /var/cache/krb5rcache , related to individual Bugzilla
    """
    @staticmethod
    def test_0001_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Access provider is simple\
                                                            and sssd is in krb5 ccachedir
        :id: 644a81e6-9791-442d-8558-2d3689f4b64e
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Execute the ldapsearch for domain config and fetch results in /tmp/output
          2. Check for the krb5_ccachedir in output file.
          3. Check for the krb5_ccname_template in output file.
        :expectedresults:
          1. Command should run successfully and provide domain config
          2. Output file will contain the krb5_ccachedir parameter
          3. Output file will contain the krb5_ccname_template parameter
        :teardown:
          1. Clear the /tmp/krb_cache directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/config.ldb \
                    -b 'cn={ds_instance_name},cn=domain,cn=config' | tee /tmp/output"

        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        output_file = multihost.client[0].get_file_contents('/tmp/output').decode('utf-8')

        multihost.client[0].run_command("rm -Rf /tmp/krb5_cache")
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "krb5_ccachedir: /tmp/krb5_cache" in output_file, f"krb5_ccachedir not found in {output_file}"
        assert "krb5_ccname_template: FILE:%d/krb5cc_%u" in output_file, f"krb5_ccname_template \
                                                                        not found in {output_file}"

    @staticmethod
    def test_0002_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                                                permissions after setting krb5 ccachedir
        :id: d5d796c5-ca30-4e12-ace1-ba71e84bf091
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/krb5_cache.
          3. Check for the file permission for /tmp/krb5_cache/krb5cc_foo1.
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
          3. File permission should be same as expected.
        :teardown:
          1. Clear the /tmp/krb_cache directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/krb5_cache"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        file = "/tmp/krb5_cache/krb5cc_foo1"
        list_cmd = f"ls -ld {file}"
        cmd2 = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        file_permission = cmd2.stdout_text.split(" ")[0]
        exp_permission2 = "-rw-------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission\
                                    not as expected. Got {dir_permission[0]}."
        assert cmd2.returncode == 0, f"{file} - no such file or directory."
        assert file_permission == exp_permission2, f"{file} file permission not as expected. Got {file_permission[0]}"

    @staticmethod
    def test_0003_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                            permissions after setting krb5 ccachedir with percent u option
        :id: 6e7c67ac-3ee2-4fcd-8cd5-d18049e2a1c9
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/krb5_cache_foo1.
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
        :teardown:
          1. Clear the /tmp/krb_cache_foo1 directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%u')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/krb5_cache_foo1"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)

        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission\
                                            not as expected. Got {dir_permission[0]}"

    @staticmethod
    def test_0004_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                             permissions after setting krb5 ccachedir with percent U option"
        :id: d85b7316-65dd-4f15-a739-a9a5a412e458
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/krb5_cache_14583101.
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
        :teardown:
          1. Clear the /tmp/krb_cache_14583101 directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%U')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/krb5_cache_14583101"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)

        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission not as expected. Got {dir}"

    @staticmethod
    def test_0005_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                            permissions after setting krb5 ccachedir with percent p option
        :id: f7fdf4a6-3a8c-4b34-a1b5-6021d59223d9
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/krb5_cache_foo1@EXAMPLE.TEST
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
        :teardown:
          1. Clear the /tmp/krb_cache_foo1@EXAMPLE.TEST directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%p')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/krb5_cache_foo1@EXAMPLE.TEST"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission\
                                    not as expected. Got {dir_permission[0]}."

    @staticmethod
    def test_0006_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                            permissions after setting krb5 ccachedir with percent r option
        :id: 2766a4f7-4043-412f-9954-2638e82cb21e
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/krb5_cache_EXAMPLE.TEST
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
        :teardown:
          1. Clear the /tmp/krb_cache_EXAMPLE.TEST directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%r')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/krb5_cache_EXAMPLE.TEST"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission\
                                    not as expected. Got {dir_permission[0]}."

    @staticmethod
    def test_0007_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                            permissions after setting krb5 ccachedir with percent h option
        :id: 3734a863-17ac-472c-9b72-a32e2b523bb0
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/krb5_cache_/home.
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
        :teardown:
          1. Clear the /tmp/krb_cache_/home directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%h')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/krb5_cache_/home"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission\
                                    not as expected. got {dir_permission[0]}."

    @staticmethod
    def test_0008_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                            permissions after setting krb5 ccachedir with percent d option
        :id: b575919d-03aa-4745-bf89-54feafb681da
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client.
          2. Check the sssd domain log for expected messages.
        :expectedresults:
          1. User foo1 should not be able to login.
          2. SSSD Domain Log contains the expected lines:
             "'%d' is not allowed in this template"
        :teardown:
          1. Clear the SSSD Domain log.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%d')
        file = f"/var/log/sssd/sssd_{ds_instance_name}.log"
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')
        sssd_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        multihost.client[0].run_command(f"truncate -s 0 {file}")
        assert ssh == 10, "foo1 should not be able to login"
        assert "'%d' is not allowed in this template" in sssd_log, f"%d not found in {file}"

    @staticmethod
    def test_0009_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                            permissions after setting krb5 ccachedir with percent P option
        :id: f0739a95-9d63-4455-a3d1-a79d46715ca8
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client.
          2. Check the sssd domain log for expected messages.
        :expectedresults:
          1. User foo1 should not be able to login.
          2. SSSD Domain Log contains the expected lines:
             "'%P' is not allowed in this template"
        :teardown:
          1. Clear the SSSD Domain log.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/krb5_cache_%P')
        file = f"/var/log/sssd/sssd_{ds_instance_name}.log"
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')
        sssd_log = multihost.client[0].get_file_contents(file).decode('utf-8')
        multihost.client[0].run_command(f"truncate -s 0 {file}")
        assert ssh == 10, "foo1 should not be able to login"
        assert "'%P' is not allowed in this template" in sssd_log, f"%P not found in {file}"

    @staticmethod
    def test_0010_krb5_ccachedir(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Check enumeration and file\
                        permissions after setting krb5 ccachedir with double percent option
        :id: 0f364cfa-8e27-4981-bace-a4dc9b7508df
        :setup:
          1. Set the krb5_ccachedir and restart sssd
        :steps:
          1. Authenticate the user foo1 from the client
          2. Check for the directory permission for /tmp/my_%%_krb5.
        :expectedresults:
          1. User foo1 should be able to successfully login.
          2. Directory permission should be same as expected.
        :teardown:
          1. Clear the /tmp/my_%%_krb5 directory.
        """
        krb5_ccache_setup(multihost.client[0], '/tmp/my_%%_krb5')
        client = sssdTools(multihost.client[0])
        ssh = client.auth_from_client('foo1', 'Secret123')

        directory = "/tmp/my_%_krb5"
        list_cmd = f"ls -ld {directory}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        dir_permission = cmd.stdout_text.split(" ")[0]
        exp_permission = "drwx------."

        multihost.client[0].run_command(f"rm -Rf {directory}")
        assert ssh == 3, "foo1 failed to login"
        assert cmd.returncode == 0, f"{directory} - no such file or directory."
        assert dir_permission == exp_permission, f"{directory} directory permission\
                                    not as expected. Got {dir_permission[0]}."

    @staticmethod
    def test_0011_ldap_krb5(multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Creation of lastUpdate Attribute \
                                                                on First Save to Cache
        :id: 0f364cfa-8e27-4981-bace-a4dc9b7508df
        :setup:
          1. Set the cache_credentials to False and restart sssd
        :steps:
          1. Execute the ldapsearch for lastUpdate and fetch results in /tmp/output.
          2. Check the secure log for expected messages.
          3. Check the messages log for expected messages.
        :expectedresults:
          1. Command should run successfully and lsatUpdate should be present.
          2. Secure log should not contain "segfault".
          3. Messages log should not contain "segfault".
        :teardown:
          1. Clear the /tmp/output file.
        """
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'cache_credentials': 'False'}
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()
        multihost.client[0].run_command("getent -s sss passwd foo1")
        sssd_ver = multihost.client[0].run_command("sssd --version").stdout_text[:-1]
        if version.parse(sssd_ver) >= version.parse("1.14.0"):
            ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' | tee /tmp/output"
            cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        else:
            ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1,cn=users,cn={ds_instance_name},cn=sysdb' | tee /tmp/output"
            cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)

        output_file = multihost.client[0].get_file_contents('/tmp/output').decode('utf-8')

        multihost.client[0].run_command("truncate -s 0 /var/log/secure")
        multihost.client[0].run_command("truncate -s 0 /var/log/messages")

        ssh = client.auth_from_client('foo1', 'Secret123')

        secure_log = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        message_log = multihost.client[0].get_file_contents('/var/log/messages').decode('utf-8')

        file = "/var/log/sssd/krb5_child.log"
        list_cmd = f"ls -ld {file}"
        cmd2 = multihost.client[0].run_command(list_cmd, raiseonerr=False)

        multihost.client[0].run_command("rm -f /tmp/output")
        assert cmd.returncode == 0, f"{ldb_cmd} did not execute successfully"
        assert "lastUpdate" in output_file, "ERROR: attribute lastUpdate was not created for the new user"
        assert ssh == 3, "foo1 failed to login"
        assert "segfault" not in secure_log, "segfault found in /var/log/secure"
        assert "segfault" not in message_log, "segfault found in /var/log/messages"
        assert cmd2.returncode == 0, f"{file}- no such file or directory."

    @staticmethod
    @pytest.mark.parametrize("ldap_krb5_setup", [pytest.param('False', id="1"),
                                                 pytest.param('True', id="2")], indirect=True)
    def test_0012_ldap_krb5(multihost, ldap_krb5_setup, backupsssdconf, request):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: krb5 validate is set in sssd conf bz548423
        :id: 0e96a0b0-b8b5-44b6-b25c-f46b7c203a6f
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=548423
        :setup:
          1. Set the krb5_validate and restart sssd
        :steps:
          1. Authenticate user foo1 with missing keytab and check SSSD Domain log
          2. Authenticate user foo1 with invalid keytab & invalid host.
          3. Authenticate user foo1 with invalid keytab & valid host.
          4. Authenticate user foo1 with Valid keytab & valid host.
        :expectedresults:
          1. auth success when krb_validate: False & fail if True
          2. auth success when krb_validate: False & fail if True
          3. auth success when krb_validate: False & fail if True
          4. auth success when krb_validate: False & success if True
        """
        file = f"/var/log/sssd/sssd_{ds_instance_name}.log"
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        secure_log = "/var/log/secure"
        multihost.client[0].run_command("mv /etc/krb5.keytab /root/sssd_client_valid.keytab")
        multihost.client[0].run_command("touch /root/invalid.keytab")
        multihost.client[0].run_command("touch /root/sssd_client_invalid.keytab")

        # Case1
        multihost.client[0].run_command(f"truncate -s 0 {secure_log}")
        ssh = client.auth_from_client('foo1', 'Secret123')
        secure_log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')

        # Case 2
        multihost.client[0].run_command("mv /root/invalid.keytab /etc/krb5.keytab")
        multihost.client[0].run_command("restorecon -v /etc/krb5.keytab")
        multihost.client[0].run_command(f"truncate -s 0 {secure_log}")
        ssh2 = client.auth_from_client('foo1', 'Secret123')
        secure_log_str2 = multihost.client[0].get_file_contents(secure_log).decode('utf-8')
        multihost.client[0].run_command("mv /etc/krb5.keytab /root/invalid.keytab")

        # Case 3
        multihost.client[0].run_command("mv /root/sssd_client_invalid.keytab /etc/krb5.keytab")
        multihost.client[0].run_command("restorecon -v /etc/krb5.keytab")
        multihost.client[0].run_command(f"truncate -s 0 {secure_log}")
        ssh3 = client.auth_from_client('foo1', 'Secret123')
        secure_log_str3 = multihost.client[0].get_file_contents(secure_log).decode('utf-8')
        multihost.client[0].run_command("mv /etc/krb5.keytab /root/sssd_client_invalid.keytab")

        # Case 4
        multihost.client[0].run_command("mv /root/sssd_client_valid.keytab /etc/krb5.keytab")
        multihost.client[0].run_command("restorecon -v /etc/krb5.keytab")
        multihost.client[0].run_command(f"truncate -s 0 {secure_log}")
        ssh4 = client.auth_from_client('foo1', 'Secret123')
        secure_log_str4 = multihost.client[0].get_file_contents(secure_log).decode('utf-8')

        if request.node.name == 'test_0012_ldap_krb5[1]':
            assert ssh == 3, "foo1 failed to login"
            assert "pam_sss(sshd:auth): authentication success" in secure_log_str, \
                f"authentication success not found in {secure_log_str}"
            assert ssh2 == 3, "foo1 failed to login"
            assert "pam_sss(sshd:auth): authentication success" in secure_log_str2, \
                f"authentication success not found in {secure_log_str2}"
            assert ssh3 == 3, "foo1 failed to login"
            assert "pam_sss(sshd:auth): authentication success" in secure_log_str3, \
                f"authentication success not found in {secure_log_str3}"
            assert ssh4 == 3, "foo1 failed to login"
            assert "pam_sss(sshd:auth): authentication success" in secure_log_str4, \
                f"authentication success not found in {secure_log_str4}"
        elif request.node.name == 'test_0012_ldap_krb5[2]':
            assert ssh == 10, "foo1 should not be able to login"
            assert "pam_sss(sshd:auth): authentication failure" in secure_log_str, \
                f"authentication failure not found in {secure_log_str}"
            assert ssh2 == 10, "foo1 should not be able to login"
            assert "pam_sss(sshd:auth): authentication failure" in secure_log_str2, \
                f"authentication failure not found in {secure_log_str2}"
            assert ssh3 == 10, "foo1 should not be able to login"
            assert "pam_sss(sshd:auth): authentication failure" in secure_log_str3, \
                f"authentication failure not found in {secure_log_str3}"
            assert ssh4 == 3, "foo1 failed to login"
            assert "pam_sss(sshd:auth): authentication success" in secure_log_str4, \
                f"authentication success not found in {secure_log_str4}"

    @staticmethod
    def test_0013_ldap_krb5(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Set ldap krb5 ticket lifetime
        :id: d582d7dc-259e-40aa-bf5a-2a32a83beab8
        :setup:
          1. Set the ldap_sasl_mech, authid, init_creds and ticket_lifetime and restart sssd
        :steps:
          1. Execute the ldapsearch for domain config and fetch results in /tmp/output.
          2. Authenticate the user foo1 from the client
          3. Check in SSSD domain log for required principal name for ldap_sasl_authid
        :expectedresults:
          1. Command should run successfully and provide domain config
          2. User foo1 should be able to successfully login.
          3. SSSD domain log contains the required principal name message
        """
        file = f"/var/log/sssd/sssd_{ds_instance_name}.log"
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'ldap_sasl_mech': 'GSSAPI',
                         'ldap_sasl_authid': f"host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST",
                         'ldap_krb5_init_creds': 'true',
                         'ldap_krb5_ticket_lifetime': '120'}
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()

        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/config.ldb \
                    -b 'cn={ds_instance_name},cn=domain,cn=config' | tee /tmp/output"

        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        output_file = multihost.client[0].get_file_contents('/tmp/output').decode('utf-8')

        multihost.client[0].run_command("getent -s sss passwd foo1")
        ssh = client.auth_from_client('foo1', 'Secret123')

        cache_file = "/var/lib/sss/db/ccache_EXAMPLE.TEST"
        cmd2 = multihost.client[0].run_command(f"ls -ld {cache_file}")

        # Case 2
        domain_params = {'ldap_sasl_authid': f"host/{multihost.client[0].sys_hostname}"}
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()
        ssh2 = client.auth_from_client('foo1', 'Secret123')

        assert cmd.returncode == 0, f"{ldb_cmd} did not execute successfully"
        assert "ldap_krb5_ticket_lifetime: 120" in output_file, f"ldap_krb_ticket_lifetime not found in {output_file}"
        assert ssh == 3, "foo1 failed to login"
        assert f"Option ldap_sasl_authid has value host/{multihost.client[0].sys_hostname}@EXAMPLE.TEST" in file, \
            f"Option ldap_sasl_authid not found in {file}"
        assert "Child responded: 0 [FILE:/var/lib/sss/db/ccache_EXAMPLE.TEST], expired on" in file, \
            f"Child responded not found in {file}"
        assert cmd2.returncode == 0, f"{cache_file} - No such file or directory"

        assert ssh2 == 3, "foo1 failed to login"
        assert f"Option ldap_sasl_authid has value host/{multihost.client[0].sys_hostname}" in file, \
            f"Option ldap_sasl_authid not found in {file}"

    @staticmethod
    def test_0014_bz1(multihost, bz_setup):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_credential_cache: Set default krb5rcachedir bz732974
        :id: 6e8ae554-c7b7-4e8c-bff9-3c43278700f0
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=732974
        :setup:
          1. Set the ldap_sasl parameters and krb5_validate to True and restart sssd
        :steps:
          1. Check the existence of /var/tmp/host_0
          2. Authenticate the user foo1 from the client
        :expectedresults:
          1. The required /var/tmp/host_0 file exists
          2. User foo1 should be able to successfully login.
        """
        os_version = [int(s) for s in multihost.client[0].distro if s.isdigit()][0]
        if os_version == 6:
            cmd = multihost.client[0].run_command("ls -lZ /var/tmp/host_0")
            client = sssdTools(multihost.client[0])
            ssh = client.auth_from_client('foo1', 'Secret123')
            cmd2 = multihost.client[0].run_command("ls -lZ /var/tmp/host_0")

            assert cmd.returncode == 0, "/var/tmp/host_0 - No security context found"
            assert ssh == 3, "foo1 failed to login"
            assert cmd2.returncode == 0, "/var/tmp/host_0 - No security context found"

        else:
            assert os_version != 6, "krb5rcachedir should be disabled"

    @staticmethod
    def test_0015_bz2(multihost, bz_setup):
        """
        :title: IDM-SSSD-TC: krb_provider: Set krb5 rcache dir to var cache krb5rcache bz748867
        :id: 2f7b0cef-4bdf-4ac7-9864-4abb4df1fc0f
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748867
        :setup:
          1. Set the ldap_sasl parameters and krb5_rcache_dir and restart sssd
        :steps:
          1. Check the existence of /var/cache/krb5rcache
          2. Authenticate the user foo1 from the client
        :expectedresults:
          1. The required /var/cache/krb5rcache file exists
          2. User foo1 should be able to successfully login.
        """
        client = sssdTools(multihost.client[0])
        sssd_params = {'krb5_rcache_dir': '/var/cache/krb5rcache'}
        client.sssd_conf('sssd', sssd_params)
        client.clear_sssd_cache()
        cmd = multihost.client[0].run_command("ls -lZd /var/cache/krb5rcache")
        cmd2 = multihost.client[0].run_command("ls -lZ /var/cache/krb5rcache")
        ssh = client.auth_from_client('foo1', 'Secret123')
        cmd3 = multihost.client[0].run_command("ls -lZ /var/cache/krb5rcache")

        assert cmd.returncode == 0, "ls -lZd /var/cache/krb5rcache - No security context found"
        assert cmd2.returncode == 0, "ls -lZ /var/cache/krb5rcache - No security context found"
        assert ssh == 3, "foo1 failed to login"
        assert cmd3.returncode == 0, "ls -lZ /var/cache/krb5rcache - No security context found"

    @staticmethod
    def test_0016_bz3(multihost, bz_setup):
        """
        :title: IDM-SSSD-TC: krb_provider: LDAP plus GSSAPI needs explicit Kerberos realm bz748860
        :id: 9bc3d010-85a0-4fe2-8be3-d53ecbe8687d
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748860
        :setup:
          1. Set the ldap_sasl parameters and remove the krb5_realm and restart sssd
        :steps:
          1. Check for Missing krb5_realm option in SSSD log
          2. Check for Will use default realm in SSSD log
        :expectedresults:
          1. SSSD log will contain the required message.
          2. SSSD log will contain the required message.
        """
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'krb5_realm': 'EXAMPLE.TEST'}
        client.sssd_conf(domain_section, domain_params, action="delete")
        try:
            client.clear_sssd_cache()
        except SSSDException:
            sssd_log = f"/var/log/sssd/sssd_{ds_instance_name}.log"
            sssd_log_str = multihost.client[0].get_file_contents(sssd_log).decode('utf-8')
            sssd_ver = multihost.client[0].run_command("sssd --version").stdout_text[:-1]
            assert "Missing krb5_realm option, will use libkrb default" in sssd_log_str, \
                f"Missing krb5_realm not found in {sssd_log_str}"
            assert "Will use default realm EXAMPLE.TEST" in sssd_log_str, \
                f"default realm not found in {sssd_log_str}"
            if version.parse(sssd_ver) >= version.parse("1.14.0"):
                assert "Executing target [id] constructor" in sssd_log_str, \
                    f"Executing target [id] not found in {sssd_log_str}"
            else:
                assert "ID backend target successfully loaded from provider [ldap]" in sssd_log_str, \
                    f"ID backend target successfully loaded not found in {sssd_log_str}"
            assert "Could not initialize backend" not in sssd_log_str, \
                f"Could not initialize backend found in {sssd_log_str}"
            assert "fatal error initializing data providers" not in sssd_log_str, \
                f"fatal error found in {sssd_log_str}"
