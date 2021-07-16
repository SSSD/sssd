""" AD-Provider AD Parameters tests ported from bash

:requirement: ad_parameters
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import time
import random
import re
import pytest

from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSSDException
from sssd.testlib.common.utils import ADOperations


@pytest.fixture(scope="function", name="create_plain_aduser_group")
def fixture_create_plain_aduser_group(session_multihost, request):
    """ Create AD user and group without posix attributes"""
    unique_num = random.randint(9999, 999999)
    ad_user = 'plainuser%d' % unique_num
    ad_group = 'plaingroup%d' % unique_num

    password = session_multihost.ad[0].ssh_password
    domainname = session_multihost.ad[0].domainname.upper()
    # Create user
    session_multihost.client[0].run_command(
        f'adcli create-user {ad_user} -D {domainname} --display-name='
        f'"Plain {ad_user}"', stdin_text=password, raiseonerr=False
    )
    # Create group
    session_multihost.client[0].run_command(
        f'adcli create-group {ad_group} -D {domainname} -z '
        f'"Plain {ad_group}"', stdin_text=password, raiseonerr=False
    )
    # Add member
    session_multihost.client[0].run_command(
        f'adcli add-member -D {domainname} {ad_group} {ad_user}',
        stdin_text=password, raiseonerr=False
    )

    def remove_plain_ad_user_group():
        """ Remove windows AD user and group """
        ad_op = ADOperations(session_multihost.ad[0])
        ad_op.delete_ad_user_group(ad_group)
        ad_op.delete_ad_user_group(ad_user)

    request.addfinalizer(remove_plain_ad_user_group)
    return ad_user, ad_group


@pytest.fixture(scope="class")
def change_client_hostname(session_multihost, request):
    """ Change client hostname to a truncated version in the AD domain"""
    cmd = session_multihost.client[0].run_command('hostname', raiseonerr=False)
    old_hostname = cmd.stdout_text.rstrip()
    ad_domain = session_multihost.ad[0].domainname
    try:
        new_hostname = session_multihost.client[0].external_hostname. \
            split('.')[0]
    except (KeyError, AttributeError):
        new_hostname = old_hostname.split('.')[0]
    if new_hostname.startswith('ci-'):
        new_hostname = new_hostname[3:]
    new_hostname = new_hostname[:15] + "." + ad_domain
    session_multihost.client[0].run_command(
        f'hostname {new_hostname}', raiseonerr=False
    )

    def restore():
        """ Restore hostname """
        session_multihost.client[0].run_command(
            f'hostname {old_hostname}',
            raiseonerr=False
        )
    request.addfinalizer(restore)


@pytest.mark.adparameters
@pytest.mark.usefixtures("change_client_hostname")
class TestADParamsPorted:
    """ BZ Automated Test Cases for AD Parameters ported from bash"""

    @pytest.fixture(autouse=True, scope="class")
    def _setup(self, session_multihost):
        """
        Fixture used instead of init for the test class as pytest ignores
        classes with a constructor.
        """
        # pylint: disable=W0201
        self.ad_realm = session_multihost.ad[0].domainname.upper()
        self.ad_realm_short = self.ad_realm.rsplit('.', 1)[0]
        self.ad_domain = session_multihost.ad[0].domainname

    @pytest.mark.tier1
    def test_0001_ad_parameters_domain(
            self, multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad domain to
          AD DOMAIN1
        :id: 08a256e6-a56e-4726-adba-b9093dce8ede
        :setup:
         1. Configure short domain name, clear cache and restart sssd.
         2. Create AD user and group.
        :steps:
          1. Run getent passwd for the user and group
          2. Run getent group for the group
          3. Run check that su can switch to the ad user in short domain
          4. Check the sssd domain log
        :expectedresults:
          1. User is found
          2. Group is found
          3. Su works as expected
          4. Log contains the expected lines
             Option ad_domain has value ...
             Option krb5_realm set to ...
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': self.ad_realm,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'full_name_format': '%2$s\\%1$s'
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {self.ad_realm_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {self.ad_realm_short}\\\\{adgroup}',
            raiseonerr=False
        )
        # Run su command
        su_cmd = multihost.client[0].run_command(
            f'su - {self.ad_realm_short}\\\\{aduser} -c  whoami',
            raiseonerr=False
        )
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f"Option ad_domain has value {self.ad_realm}" in log_str
        assert f"Option krb5_realm set to {self.ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found."
        assert su_cmd.returncode == 0, "The su command failed!"

    @pytest.mark.tier1
    def test_0002_ad_parameters_junk_domain(
            self, multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad domain to junk
          and first entry in keytab is valid bz1091957
        :id: 760bda92-a67b-42bd-a55f-89d57e16e294
        :setup:
          1. Configure junk domain name, clear cache and restart sssd.
          2. Create AD user.
        :steps:
          1. Check the sssd domain log for expected messages.
          2. Search for a user and check messages for segfault
        :expectedresults:
          1. Log contains the expected lines:
             No principal matching <hostname>$@JUNK found in keytab.
             No principal matching host/*@JUNK found in keytab.
             Selected realm: <ad_realm>
          2. There is no segfault in the /var/log/messages.
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1091957
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to ad_domain = junk
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': 'junk',
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'full_name_format': '%2$s\\%1$s',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Download sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        hostname_cmd = multihost.client[0].run_command(
                'hostname -s', raiseonerr=False)
        shortname = hostname_cmd.stdout_text.rstrip().upper()

        # Run getent passwd
        multihost.client[0].run_command(
                f'getent passwd {self.ad_realm}\\\\{aduser}', raiseonerr=False)
        # Download /var/log/messages
        log_msg_str = multihost.client[0].get_file_contents(
            '/var/log/messages').decode('utf-8')
        # Restore sssd.conf
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        # Evaluate test results
        assert f"No principal matching {shortname}$@JUNK found in keytab." in \
               log_str
        assert "No principal matching host/*@JUNK found in keytab." in log_str
        assert f"Selected realm: {self.ad_realm}" in log_str
        assert "segfault" not in log_msg_str, "Segfault present in the log!"

    @staticmethod
    @pytest.mark.tier1
    def test_0003_ad_parameters_junk_domain_invalid_keytab(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad domain to junk
          and first entry in keytab is invalid
        :id: ed1a1607-f9f1-4d3c-afbe-c6c1a6ce330b
        :setup:
          1. Create an AD user.
          2. Configure junk domain name in sssd.conf.
          3. Create keytab with first item with INVALIDDOMAIN.COM.
          4. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Check the sssd domain log for expected messages.
        :expectedresults:
          1. User is not found.
          2. Log contains the expected lines:
             No principal matching host/*@JUNK found in keytab.
             Selected realm: INVALIDDOMAIN.COM
             Option krb5_realm set to JUNK
        :teardown:
          1. Restore keytab.
          2. Remove AD user.
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1091957
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd with junk domain
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_realm = multihost.ad[0].domainname.upper()
        ad_domain_short = ad_realm.rsplit('.', 1)[0]
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': 'junk',
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'full_name_format': '%2$s\\%1$s',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf(dom_section, {'krb5_realm': 'delme'}, action='delete')
        # Backup keytab
        multihost.client[0].run_command(
            'cp /etc/krb5.keytab /etc/krb5.keytab.working',
            raiseonerr=False
        )
        # Create invalid keytab /tmp/first_invalid.keytab

        hostname_cmd = multihost.client[0].run_command(
            'hostname -s',
            raiseonerr=False
        )
        shortname = hostname_cmd.stdout_text.rstrip().upper()

        ktutil_cmd = f'echo -e "addent -password -p host/{shortname}@' \
                     f'INVALIDDOMAIN.COM -k 2 -e rc4-hmac\\nSecret123\\nrkt ' \
                     f'/etc/krb5.keytab\\nwkt /tmp/first_invalid.' \
                     f'keytab\\nquit\\n" | ktutil'
        multihost.client[0].run_command(ktutil_cmd, raiseonerr=False)
        # Get keytab info for debugging purposes
        multihost.client[0].run_command(
            'file /tmp/first_invalid.keytab',
            raiseonerr=False
        )
        # Place keytab with invalid first item
        multihost.client[0].run_command(
            'cp -f /tmp/first_invalid.keytab /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab; ',
            raiseonerr=False
        )
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {ad_domain_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')
        # Restore keytab before test result evaluation
        multihost.client[0].run_command(
            'cp -f /etc/krb5.keytab.working /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab',
            raiseonerr=False
        )
        # Restore sssd config
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        # Evaluate test results
        assert usr_cmd.returncode == 2, f"{aduser} was unexpectedly found!"
        assert "No principal matching host/*@JUNK found in keytab." in log_str
        assert "Selected realm: INVALIDDOMAIN.COM" in log_str
        assert "Option krb5_realm set to JUNK" in log_str

    @staticmethod
    @pytest.mark.tier1
    def test_0004_ad_parameters_valid_domain_shorthost(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: ad domain is valid
          and principal should default to SHORTHOST bz892197
        :id: 63700bc9-d9f7-4a15-94c8-b6ef23fd329b
        :setup:
          1. Create an AD user.
          2. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Check the sssd domain log for expected messages.
          3. Run su to the user.
        :expectedresults:
          1. User is found.
          2. Log contains the expected line:
             Trying to find principal <HOST_SHORT_PRINC>$@<AD_SERVER1_REALM>
          3. User is switched successfully.
        :teardown:
          1. Remove AD user.
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=892197
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_realm = multihost.ad[0].domainname.upper()
        ad_domain_short = ad_realm.rsplit('.', 1)[0]
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'full_name_format': '%2$s\\%1$s',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        time.sleep(15)
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        hostname_cmd = multihost.client[0].run_command(
            'hostname -s',
            raiseonerr=False
        )
        shortname = hostname_cmd.stdout_text.rstrip().upper()
        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {ad_domain_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Run su
        su_cmd = multihost.client[0].run_command(
            f'su - {ad_domain_short}\\\\{aduser} -c  whoami',
            raiseonerr=False
        )
        # Restore sssd config
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        # Evaluate test results
        assert f"Trying to find principal {shortname}$@{ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0005_ad_parameters_blank_domain(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad domain to blank
          should default to sssd domain
        :id: 18f6ceac-283e-43e7-96b8-e4d8d7bda7d1
        :setup:
          1. Create an AD user.
          2. Configure blank domain name in sssd.conf.
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Check the sssd domain log for expected messages.
          3. Run su to the user.
        :expectedresults:
          1. User is found
          2. Log contains the expected line:
             Trying to find principal <HOST_SHORT_PRINC>$@<AD_SERVER1_REALM>
          3. User is switched successfully.
        :teardown:
          1. Remove AD user.
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=892197
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_realm = multihost.ad[0].domainname.upper()
        ad_domain_short = ad_realm.rsplit('.', 1)[0]
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': '',
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'full_name_format': '%2$s\\%1$s',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        time.sleep(15)
        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {ad_domain_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Search for the AD group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {ad_domain_short}\\\\{adgroup}',
            raiseonerr=False
        )
        # Run su
        su_cmd = multihost.client[0].run_command(
            f'su - {ad_domain_short}\\\\{aduser} -c  whoami',
            raiseonerr=False
        )
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')
        # Restore sssd config
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        # Evaluate test results
        assert "Option ad_domain has no value" in log_str
        assert f"Option krb5_realm set to {ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0006_ad_parameters_homedir_override_nss(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: override homedir to
          UPN and login name in nss section bz1137015
        :id: ea57bb9b-802b-40e4-ad6a-7ae0b4d3f927
        :setup:
         1. Configure homedir override in nss section,
            clear cache and restart sssd.
         2. Create an AD user.
        :steps:
          1. Run getent passwd for the user and verify the home location.
        :expectedresults:
          1. User is found and homedir is overridden.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1137015
        """
        ad_domain = multihost.ad[0].domainname

        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, _) = create_plain_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'

        sssd_params = {
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('nss', {'override_homedir': '/home/%P/%u'})
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}',
            raiseonerr=False
        )
        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f'/home/{aduser}@{ad_domain.upper()}/{aduser}' in \
               usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.tier1
    def test_0007_ad_parameters_homedir_override_domain(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: override homedir
          to UPN and login name in domain section
        :id: 76b021af-37cb-49a4-8109-d2cf99f05c48
        :setup:
         1. Configure homedir override in domain section,
            clear cache and restart sssd.
         2. Create an AD user.
        :steps:
          1. Run getent passwd for the user and verify the home location.
        :expectedresults:
          1. User is found and homedir is overridden.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1137015
        """
        ad_domain = multihost.ad[0].domainname
        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, _) = create_plain_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'override_homedir': '/home/%P/%u'
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f'/home/{aduser}@{ad_domain.upper()}/{aduser}' in \
               usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.tier1
    def test_0008_ad_parameters_homedir_override_both(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: override homedir
          in both nss and domain section
        :id: ffa3f09e-7f16-463f-9828-edf9491bfb2e
        :setup:
         1. Configure homedir override both in nss and domain sections,
            clear cache and restart sssd.
         2. Create an AD user.
        :steps:
          1. Run getent passwd for the user and verify the home location.
        :expectedresults:
          1. User is found and homedir is overridden by domain template.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1137015
        """
        ad_domain = multihost.ad[0].domainname
        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, _) = create_plain_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'override_homedir': '/home/%u/%P',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('nss', {'override_homedir': '/home/%P/%u'})
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f'/home/{aduser}/{aduser}@{ad_domain.upper()}' in \
               usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.broken
    def test_0009_ad_parameters_ldap_sasl_full(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Using full principal
          bz877972
        :id: 9b71822b-09e0-48f9-9163-3b547364364e
        :setup:
         1. Configure ldap_sasl_authid to host/<HOSTNAME>@<AD_REALM>
            clear cache and restart sssd.
         2. Create an AD user.
        :steps:
          1. Run getent passwd for the user.
          2. Run su for the user.
          3. Check sssd domain log for expected messages:
             Option ldap_sasl_authid has value host/<HOSTNAME>@<AD_REALM>
             authid contains realm [<AD_REALM>]
             Will look for host/<HOSTNAME>@<AD_REALM> in
             Trying to find principal host/<HOSTNAME>@<AD_REALM> in keytab
             Principal matched to the sample (host/<HOSTNAME>@<AD_REALM>)
        :expectedresults:
          1. User is found.
          2. Su passes.
          3. Expected lines are in the log.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=877972
        """
        hostname_cmd = multihost.client[0].run_command(
            'hostname',
            raiseonerr=False
        )
        hostname = hostname_cmd.stdout_text.rstrip()
        adjoin(membersw='adcli')
        # Create AD user
        (aduser, _) = create_plain_aduser_group
        # Configure sssd
        ad_realm = multihost.ad[0].domainname.upper()
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'ldap_id_mapping': 'True',
            'ldap_sasl_authid': f'host/{hostname}@{ad_realm}',

        }
        client.sssd_conf(dom_section, sssd_params)
        nss_params = {
            'filter_groups': 'root',
            'filter_users': 'root',
            'default_shell': '/bin/bash',
            'override_homedir': '/home/%u',
        }
        client.sssd_conf('nss', nss_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Run su command
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # TODO: DELETE
        multihost.client[0].run_command(
            f"cat /var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log",
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        assert f"Option ldap_sasl_authid has value host/{hostname}@{ad_realm}" \
               in log_str
        assert "authid contains realm" in log_str
        assert f"Will look for host/{hostname}@{ad_realm} in" in log_str
        assert f"Trying to find principal host/{hostname}@{ad_realm} in " \
               f"keytab" in log_str
        assert f"Principal matched to the sample (host/{hostname}@{ad_realm})" \
               in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert su_cmd.returncode == 0, f"Su for user {aduser} failed!"

    @staticmethod
    @pytest.mark.broken
    def test_0010_ad_parameters_ldap_sasl_short(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Using short principal
        :id: 6f1cc204-0dd3-40eb-a3e2-a113cc7c2df3
        :setup:
         1. Configure ldap_sasl_authid to host/<HOSTNAME>
            clear cache and restart sssd.
         2. Create an AD user.
        :steps:
          1. Run getent passwd for the user.
          2. Run su for the user.
          3. Check sssd domain log for expected/unexpected messages:
             <TBD>
        :expectedresults:
          1. User is found.
          2. Su passes.
          3. Expected lines are in the log.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1137015
        """
        ad_domain = multihost.ad[0].domainname
        hostname_cmd = multihost.client[0].run_command(
            'hostname -s',
            raiseonerr=False
        )
        shortname = hostname_cmd.stdout_text.rstrip()
        adjoin(membersw='adcli')
        # Create AD user
        (aduser, _) = create_aduser_group
        # Configure sssd
        ad_realm = multihost.ad[0].domainname.upper()
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'ldap_sasl_authid': f'host/{shortname}',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Run su command
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # TODO: DELETE
        multihost.client[0].run_command(
            f"cat /var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log",
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f"Option ldap_sasl_authid has value host/{shortname}" in log_str
        assert "authid contains realm" not in log_str
        assert f"Will look for host/{shortname}.{ad_domain}@{ad_realm} in" \
               in log_str
        assert f"Trying to find principal host/{shortname}.{ad_domain}@" \
               f"{ad_realm} in keytab" in log_str
        assert f"Principal matched to the sample (host/{shortname}." \
               f"{ad_domain}@{ad_realm})" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert su_cmd.returncode == 0, f"Su for user {aduser} failed!"

    @pytest.mark.tier1
    def test_0011_ad_parameters_server_resolvable(
            self, multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad server to
          resolvable hostname
        :id: 4493644f-9a03-4c50-9d87-3683d05152a0
        :setup:
         1. Configure, ad_server to resolvable name
            clear cache and restart sssd.
         2. Create an AD user and group.
        :steps:
          1. Run getent passwd for the user and get uid.
          2. Run getent group for the group and get gid.
          3. Run getent passwd with uid.
          4. Run getent passwd with gid.
          5. Run su for the user.
          6. Search logs for specific messages in sssd domain log.
              Option ad_domain has value <AD_DOMAIN1>.
              Option krb5_realm set to <AD_SERVER1_REALM>.
        :expectedresults:
          1. User is found.
          2. Group is found.
          3. User is found by uid.
          4. Group is found by gid.
          5. Su passes.
          6. The lines are present in the log.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        # Create AD user
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user and get its uid
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser} | cut -d: -f3', raiseonerr=False)
        uid = usr_cmd.stdout_text.rstrip()

        # Search for the group and get its gid
        grp_cmd = multihost.client[0].run_command(
                f'getent group {adgroup} | cut -d: -f3', raiseonerr=False)
        gid = grp_cmd.stdout_text.rstrip()
        # Search for the user by uid
        uid_cmd = multihost.client[0].run_command(
                f'getent passwd {uid}', raiseonerr=False)
        # Search for the group by gid
        gid_cmd = multihost.client[0].run_command(
                f'getent group {gid}', raiseonerr=False)
        # Run su command
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        assert f"Option ad_domain has value " \
               f"{multihost.ad[0].domainname.lower()}" in log_str
        assert f"Option krb5_realm set to {self.ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert uid_cmd.returncode == 0, f"User with {uid} was not found!"
        assert gid_cmd.returncode == 0, f"Group with {gid} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0012_ad_parameters_server_unresolvable(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad server to
          unresolvable hostname
        :id: d3e96e63-5e17-4bc9-b35e-86b80fa3bcec
        :setup:
         1. Configure, ad_server to an unresolvable name
            clear cache and restart sssd.
         2. Create an AD user and group.
        :steps:
          1. Run getent passwd for the user.
          2. Search logs for specific message(s) in sssd domain log.
             Failed to resolve server 'unresolved.<AD_DOMAIN1>'
             Going offline
        :expectedresults:
          1. User is not found.
          2. The line(s) are present in the log.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        # Create AD user
        (aduser, _) = create_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': f'unresolved.{multihost.ad[0].domainname.lower()}',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user and get its uid
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        assert f"Failed to resolve server 'unresolved." \
               f"{multihost.ad[0].domainname.lower()}': " \
               f"Domain name not found" in log_str
        assert "Going offline" in log_str
        assert usr_cmd.returncode == 2, f"User {aduser} was found!"

    @staticmethod
    @pytest.mark.tier1
    def test_0013_ad_parameters_server_srv_record(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad server to
          blank which defaults to srv record
        :id: f87672d8-d462-4673-a4d7-6b55a4c05925
        :setup:
         1. Configure, ad_server to _srv_ record
            clear cache and restart sssd.
         2. Create an AD user and group.
        :steps:
          1. Run getent passwd for the user.
          2. Run getent group for the group.
          3. Run su for the user.
          4. Search logs for specific message(s) in sssd domain log.
              Marking SRV lookup of service 'AD' as 'resolved'
        :expectedresults:
          1. User is found.
          2. Group is found.
          3. Su passes.
          4. The line(s) are present in the log.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        # Create AD user
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': '_srv_',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
                f'getent group {adgroup}', raiseonerr=False)
        # Run su command
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        assert "Marking SRV lookup of service 'AD' as 'resolved'" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0014_ad_parameters_server_blank(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad server to
          blank which defaults to srv record
        :id: b7d7b556-22a6-41d8-93db-6834ef3e9688
        :setup:
         1. Configure, ad_server to blank
            clear cache and restart sssd.
         2. Create an AD user and group.
        :steps:
          1. Run getent passwd for the user.
          2. Run getent group for the group.
          3. Run su for the user.
          4. Search logs for specific message(s) in sssd domain log.
              No AD server set, will use service discovery
        :expectedresults:
          1. User is found.
          2. Group is found.
          3. Su passes.
          4. The line(s) are present in the log.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        # Create AD user
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': '',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
                f'getent group {adgroup}', raiseonerr=False)
        # Run su command
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        assert "No AD server set, will use service discovery" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.broken
    def test_0015_ad_parameters_ad_hostname_machine(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Hostname not
          identified on AD
        :id: 5f6e5a03-8617-4a93-a3e8-24efe99554f9
        :setup:
          1. Change hostname to <hostname>.kautest.com.
          2. Create an AD user.
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Check the sssd domain log for expected messages.
          3. Run su to the user.
        :expectedresults:
          1. User is found.
          2. Log contains the expected line and does nota have unexpected one:
             Expected: Will look for <hostname>.kautest.com@<ad_realm>
             Unexpected: Setting ad_hostname to [<hostname>.kautest.com]
          3. User is switched successfully.
        :teardown:
          1. Remove AD user.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()

        hostname_cmd = multihost.client[0].run_command(
                'hostname', raiseonerr=False)
        old_hostname = hostname_cmd.stdout_text.rstrip()

        hostname_cmd = multihost.client[0].run_command(
                'hostname -s', raiseonerr=False)
        shortname = hostname_cmd.stdout_text.rstrip()

        # Set new hostname
        multihost.client[0].run_command(
            f'hostname {shortname}.kautest.com', raiseonerr=False)

        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_realm = multihost.ad[0].domainname.upper()
        sssd_params = {
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'full_name_format': '%2$s\\%1$s',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)

        # Run su
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)

        # TODO: Delete this
        multihost.client[0].run_command(
            f"cp /var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}."
            f"log /root/sssd_dom.log; "
            f"cp /etc/sssd/sssd.conf /root/sssd_dom.conf",
            raiseonerr=False
        )

        # Reset hostname
        multihost.client[0].run_command(
            f'hostname {old_hostname}', raiseonerr=False)
        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f"Setting ad_hostname to [{shortname}.kautest.com]" \
               not in log_str
        assert f"Will look for {shortname}.kautest.com@{ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0016_ad_parameters_ad_hostname_valid(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ad hostname to
          a valid hostname
        :id: a8f03e0e-4712-45a6-82c5-ee57c30a2570
        :setup:
          1. Change hostname to host1.kautest.com, set ad_hostname
            to the old one.
          2. Create an AD user and group.
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Run getent group for the group.
          3. Check the sssd domain log for expected messages.
          4. Run su to the user.
        :expectedresults:
          1. User is found.
          2. Group is found.
          3. Log contains the expected lines and no unexpected ones:
             Option ad_hostname has value <old_hostname>
             Trying to find principal <old_hostname>@<ad_realm>
             Will look for <old_hostname>@<ad_realm>
             Unexpected: Setting ad_hostname to [<old_hostname>]"
          4. User is switched successfully.
        :teardown:
          1. Remove AD user.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()

        hostname_cmd = multihost.client[0].run_command(
                'hostname', raiseonerr=False)
        old_hostname = hostname_cmd.stdout_text.rstrip()

        # Set new hostname
        multihost.client[0].run_command(
                'hostname host1.kautest.com', raiseonerr=False)

        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_realm = multihost.ad[0].domainname.upper()
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'ad_hostname': old_hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        time.sleep(15)
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Search for the group and get its gid
        grp_cmd = multihost.client[0].run_command(
                f'getent group {adgroup}', raiseonerr=False)
        # Run su
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)
        # Reset new hostname
        multihost.client[0].run_command(
                f'hostname {old_hostname}', raiseonerr=False)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert f"Option ad_hostname has value {old_hostname}" in log_str
        assert f"Setting ad_hostname to [{old_hostname}]" not in log_str
        assert f"Will look for {old_hostname}@{ad_realm}" in log_str
        assert f"Trying to find principal {old_hostname}@{ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0017_ad_parameters_krb5_keytab_nonexistent(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set krb5 keytab to
          non existent keytab file
        :id: 0160dc4f-02e7-40d5-a67e-8ce89fe895d0
        :setup:
          1. Set krb5 keytab to non existent keytab file.
          2. Move keytab elsewhere.
          2. Create an AD user.
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Check the sssd domain log for expected messages.
          3. Run su to the user.
        :expectedresults:
          1. User is not found.
          2. Log contains the expected line and does not have unexpected one:
             Option krb5_keytab has value /etc/krb5.keytab.keytabdoesntexist
             Option ldap_krb5_keytab set to /etc/krb5.keytab.keytabdoesntexist
          3. User is switched successfully.
        :teardown:
          1. Remove AD user.
          2. Restore keytab.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Hide keytab
        multihost.client[0].run_command(
            'mv -f /etc/krb5.keytab /etc/krb5.keytab.working',
            raiseonerr=False
        )
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'krb5_keytab': '/etc/krb5.keytab.keytabdoesntexist',
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        try:
            client.clear_sssd_cache()
        except SSSDException:
            # SSSD will not start due to the non-existent keytab.
            pass
        time.sleep(15)
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Restore keytab
        multihost.client[0].run_command(
            'mv -f /etc/krb5.keytab.working /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert "Option krb5_keytab has value /etc/krb5.keytab." \
               "keytabdoesntexist" in log_str
        assert "Option ldap_krb5_keytab set to /etc/krb5.keytab." \
               "keytabdoesntexist" in log_str
        assert "No suitable principal found in keytab" in log_str
        assert usr_cmd.returncode == 2, f"User {aduser} was found."

    @staticmethod
    @pytest.mark.tier1
    def test_0018_ad_parameters_krb5_keytab_elsewhere(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: keytab exists in
          non default location
        :id: d60af4ee-94f0-4c9f-b3b6-2dbd0aed2f00
        :setup:
          1. Move krb5 keytab to non-standard location.
          2. Create an AD user and group.
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Run getent group for the group.
          3. Check the sssd domain log for expected messages.
          4. Run su to the user.
        :expectedresults:
          1. User is found.
          2. Group is found.
          3. Log contains the expected lines:
              Option krb5_keytab has value /usr/local/etc/krb5.keytab
              Option ldap_krb5_keytab set to /usr/local/etc/krb5.keytab
          4. User is switched successfully.
        :teardown:
          1. Remove AD user and group.
          2. Restore keytab.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the configuration because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Move keytab
        multihost.client[0].run_command(
            'mv /etc/krb5.keytab /usr/local/etc/krb5.keytab;'
            'semanage fcontext -a -t krb5_keytab_t /usr/local/etc/krb5.keytab;'
            'restorecon /usr/local/etc/krb5.keytab',
            raiseonerr=False
        )
        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'

        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'krb5_keytab': '/usr/local/etc/krb5.keytab',
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        time.sleep(15)
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Search for the group and get its gid
        grp_cmd = multihost.client[0].run_command(
                f'getent group {adgroup}', raiseonerr=False)
        # Run su
        su_cmd = multihost.client[0].run_command(
            f'su - {aduser} -c  whoami', raiseonerr=False)
        # Restore keytab
        multihost.client[0].run_command(
            'mv /usr/local/etc/krb5.keytab /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert "Option krb5_keytab has value /usr/local/etc/krb5.keytab" \
               in log_str
        assert "Option ldap_krb5_keytab set to /usr/local/etc/krb5.keytab" \
               in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1
    def test_0019_ad_parameters_ldap_id_mapping_false(
            multihost, adjoin, create_aduser_group, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Set ldap id
          mapping to false
        :id: d0693d87-eaf3-4d02-b078-ee5b7dd526f8
        :setup:
          1. Set ldap id mapping to false
          2. Clear cache and restart sssd.
          3. Create an AD user and group with uid and gid.
          4. Create an AD user and group without uid and gid.
        :steps:
          1. Run getent passwd for the user without uid.
          2. Run getent group for the group without gid.
          3. Run getent passwd for uid.
          4. Run getent group for gid.
          5. Run getent passwd for the user with uid.
          6. Run getent group for the group with gid.
          7. Run su to the user with uid.
        :expectedresults:
          1. User is not found.
          2. Group is not found.
          3. User is found.
          4. Group is found.
          5. User is found.
          6. Group is found.
          7. User is switched successfully.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        (userplain, group_plain) = create_plain_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Get uid and gid for the aduser and adgroup
        get_uid_cmd = f"powershell.exe -inputformat none -noprofile 'Get-" \
                      f"ADUser -Identity {aduser} -Properties uidNumber'"
        cmd = multihost.ad[0].run_command(get_uid_cmd, raiseonerr=False)
        uid = re.findall("uidNumber.*:[^0-9]+([0-9]+)", cmd.stdout_text)[0]
        get_gid_cmd = f"powershell.exe -inputformat none -noprofile 'Get-" \
                      f"ADGroup -Identity {adgroup} -Properties gidNumber'"
        cmd = multihost.ad[0].run_command(get_gid_cmd, raiseonerr=False)
        gid = re.findall("gidNumber.*:[^0-9]+([0-9]+)", cmd.stdout_text)[0]

        # Search for the AD user without uid
        plain_usr_cmd = multihost.client[0].run_command(
                f'getent passwd {userplain}', raiseonerr=False)
        # Search for the group without gid
        plain_grp_cmd = multihost.client[0].run_command(
                f'getent group {group_plain}', raiseonerr=False)
        # Search for the AD user by uid
        usr_uid_cmd = multihost.client[0].run_command(
                f'getent passwd {uid}', raiseonerr=False)
        # Search for the group by gid
        grp_gid_cmd = multihost.client[0].run_command(
                f'getent group {gid}', raiseonerr=False)
        # Search for the user with uid
        usr_cmd = multihost.client[0].run_command(
                f'getent passwd {aduser}', raiseonerr=False)
        # Search for the group with gid
        grp_cmd = multihost.client[0].run_command(
                f'getent group {adgroup}', raiseonerr=False)
        # Run su
        su_cmd = multihost.client[0].run_command(
                f'su - {aduser} -c  whoami', raiseonerr=False)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert usr_uid_cmd.returncode == 0, f"User {uid} was not found."
        assert grp_gid_cmd.returncode == 0, f"Group {gid} was not found!"
        assert plain_usr_cmd.returncode == 2, f"User {aduser} was found!"
        assert plain_grp_cmd.returncode == 2, f"Group {adgroup} was found!"
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_cmd.returncode == 0, "The su command failed!"

# TODO: "Account Password Policy Tests"
# test_0020 "Change user password"
# test_0021 "User must change password on next logon bz1078840"
# test_0022 "User account disabled"
# test_0022 "User account is expired bz1081046"

# TODO: "misc.sh"
# test_0023 "getgrgid removes nested group memberships bz887961"
# test_0024 "empty group cannot be resolved using ad matching rule bz1033084"
# test_0025 "SSSD failover does not work bz966757"
# test_0026 "ad group membership is empty when id mapping is off bz1130017"
# test_0027 "enumerate nested groups if they are part of non POSIX
#            groups bz1103487"
# test_0028 "tokengroups do not work with id provider ldap bz1120508"
# test_0029 "Problems with tokengroups and ldap group search base bz1127266"
# test_0030 "sssd does not work with custom value of option re expression
#            bz1165794"
# test_0031 "Does sssd ad use the most suitable attribute for group name
#            bz1199445"
# test_0032 "groups cleanup should sanitize dn of groups bz1364118"
# test_0033 "sssd ad groups work intermittently bz1212610"
# test_0034 "groups get deleted from the cache bz1279971"
# test_0035 "The AD keytab renewal task leaks a file descriptor bz1340176"
# test_0036 "SSSD fails to start when ldap user extra attrs contains mail
#            bz1362023"
# test_0037 "pam sss sshd authentication failure with user from AD bz1182183"
# test_0038 "sssd be keeps crashing if id provider equal to ad and auth
#            provider equal to krb5 bz1396485 bz1392444"

# TODO: sss_ssh_authorizedkeys
# test_0039 "allow newlines in the public key string bz1104145"

# TODO: sss_ssh_knownhostsproxy
# test_0040 "segfault when HostID back end target is not configured bz1071823"
