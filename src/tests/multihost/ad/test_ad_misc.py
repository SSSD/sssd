""" AD-Provider - Miscellaneous tests for bugzillas

:requirement: ad_misc
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import tempfile
import pytest

from sssd.testlib.common.utils import sssdTools


@pytest.mark.tier1_3
@pytest.mark.admisc
class TestADMisc:
    """ Miscellaneous Automated Test Cases for AD integration Bugzillas"""

    @staticmethod
    def test_0001_provider_config_cross_interference(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: Multiple provider configuration interferes
         with each other
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=2026799
          https://bugzilla.redhat.com/show_bug.cgi?id=2070138
        :id: 265288bc-48d9-47f2-b18c-5142925cfeda
        :setup:
          1.Configure sssd with AD.
        :steps:
          1.Run getent passwd command for an AD user.
          2.Add configuration for an additional ldap to use obfuscated
            password. Clear caches and restart SSSD.
          3.Run getent passwd command for an AD user.
          4.Check sssd log.
        :expectedresults:
          1.User should be resolved.
          2.SSSD should start but switch to offline due to ldap.
          3.User will not be resolved.
          4."Invalid authtoken type" error is not in the log.
        """

        adjoin(membersw='adcli')
        hostname = multihost.client[0].run_command(
            'hostname -s', raiseonerr=False).stdout_text.rstrip().upper()

        # Create AD user and group
        (aduser, _) = create_aduser_group

        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()

        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': multihost.ad[0].domainname,
            'krb5_realm': multihost.ad[0].domainname.upper(),
            'realmd_tags': 'manages-system joined-with-adcli',
            'cache_credentials': 'True',
            'id_provider': 'ad',
            'krb5_store_password_if_offline': 'True',
            'default_shell': '/bin/bash',
            'ldap_sasl_authid': f'{hostname}$',
            'ldap_id_mapping': 'False',
            'use_fully_qualified_names': 'False',
            'fallback_homedir': '/home/%u',
            'access_provider': 'simple',
            'ad_maximum_machine_account_password_age': '7',
            'debug_level': '9',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Search for the user before ldap is configured
        usr_cmd_1 = multihost.client[0].run_command(
            f'getent passwd {aduser}', raiseonerr=False)

        # Add external ldap configuration
        basedn = multihost.ad[0].domain_basedn_entry
        sudo_ou = f'ou=Sudoers,CN=Global,{basedn}'
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write(
                f"""
                [sssd]
                services = nss, pam, sudo
                domains = {client.get_domain_section_name()}

                [domain/{client.get_domain_section_name()}]
                subdomains_provider = none
                sudo_provider = ldap
                ldap_sudo_search_base = {sudo_ou}
                ldap_uri = ldaps://{multihost.master[0].external_hostname}:636
                ldap_default_bind_dn = CN=SRVADMSUDORHEL01,OU=Users,"""
                f"""CN=Global,{basedn}
                ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt
                debug_level = 9
                ldap_tls_reqcert = demand
                ldap_default_authtok_type = password
                ldap_default_authtok = "Magic123"
                """
            )
            tfile.flush()
            multihost.client[0].transport.put_file(
                tfile.name, '/etc/sssd/conf.d/99_sudo-ldap.conf')

        multihost.client[0].run_command(
            'cat /etc/sssd/sssd.conf', raiseonerr=False)

        multihost.client[0].run_command(
            'chown root:root /etc/sssd/conf.d/99_sudo-ldap.conf',
            raiseonerr=False)

        multihost.client[0].run_command(
            'chmod 600 /etc/sssd/conf.d/99_sudo-ldap.conf',
            raiseonerr=False)

        # Obfuscate the password
        multihost.client[0].run_command(
            f'echo "Public123" | sss_obfuscate --stdin --domain '
            f'{client.get_domain_section_name()} --file '
            f'/etc/sssd/conf.d/99_sudo-ldap.conf',
            raiseonerr=False
        )

        multihost.client[0].run_command(
            'cat /etc/sssd/conf.d/99_sudo-ldap.conf', raiseonerr=False)

        multihost.client[0].run_command(
            'cat /etc/sssd/sssd.conf', raiseonerr=False)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Search for the user with ldap configured with obfuscated password
        usr_cmd_2 = multihost.client[0].run_command(
            f'getent passwd {aduser}', raiseonerr=False)

        # Give it some time so the log can be written
        time.sleep(5)

        multihost.client[0].run_command(
            f'echo "--- LOG with an obfuscated password ---"; '
            f'cat /var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log',
            raiseonerr=False
        )

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # TEARDOWN
        client.restore_sssd_conf()
        # Delete external ldap configuration
        multihost.client[0].run_command(
            'rm -f /etc/sssd/conf.d/99_sudo-ldap.conf', raiseonerr=False)
        client.clear_sssd_cache()

        # Evaluate test results
        assert usr_cmd_1.returncode == 0,\
            f"getent passwd {aduser} failed (AD without additional LDAP)."
        assert usr_cmd_2.returncode != 0,\
            f"getent passwd {aduser} passed (AD with LDAP with an " \
            f"obfuscated password)."
        assert "[sdap_cli_auth_step] (0x1000): Invalid authtoken type" \
            not in log_str, "The configuration interferes."
        assert "Going offline" in log_str
