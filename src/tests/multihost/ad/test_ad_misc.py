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
import re

from sssd.testlib.common.utils import sssdTools
from pexpect import pxssh


@pytest.mark.tier1_4
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
        assert usr_cmd_1.returncode == 0, \
            f"getent passwd {aduser} failed (AD without additional LDAP)."
        assert usr_cmd_2.returncode != 0, \
            f"getent passwd {aduser} passed (AD with LDAP with an " \
            f"obfuscated password)."
        assert "[sdap_cli_auth_step] (0x1000): Invalid authtoken type" \
            not in log_str, "The configuration interferes."
        assert "Going offline" in log_str

    @pytest.mark.tier2
    @staticmethod
    def test_0002_improved_use_negative_sid_for_sid_lookup(
            multihost, adjoin, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Multiple provider configuration interferes
         with each other
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1766490
        :id: fc07a12b-58de-49f4-93be-4fa2b8cdc6ee
        :setup:
          1. Configure sssd with AD.
          2. Enable debug_level = 9 in the domain section
          3. Transport a python program, to run a lookup using SID, on client
        :steps:
          1. Twice run lookup using sid of non-existing ADuser
        :expectedresults:
          1. domain log file should show that the SID of non-existing does
             not exist in negative cache
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        client.sssd_conf('nss', {'debug_level': '9'}, action='add')
        client.clear_sssd_cache()
        multihost.client[0].run_command('dnf install python3-libsss_nss_idmap -y', raiseonerr=True)
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write('#!/usr/bin/python\n')
            tfile.write('import pysss_nss_idmap as idmap\n')
            tfile.write('import re\n')
            tfile.write('\n')
            tfile.write('def get_good_sid():\n')
            tfile.write(f'    admin = idmap.getsidbyname("administrator@{domain_name}")\n')
            tfile.write(f'    sid = admin["administrator@{domain_name}"]["sid"]\n')
            tfile.write('    return sid\n')
            tfile.write('\n')
            tfile.write('def get_invalid_sid():\n')
            tfile.write('    sid = get_good_sid()\n')
            tfile.write('    i = sid.rindex("-")\n')
            tfile.write('    l = len(sid[i:]) - 1 \n')
            tfile.write('    return sid[:i] + "-" + ("9" * l)\n')
            tfile.write('\n')
            tfile.write('sid = get_invalid_sid()\n')
            tfile.write('idmap.getnamebysid(sid)\n')
            tfile.write('idmap.getnamebysid(sid)\n')
            tfile.flush()
            multihost.client[0].transport.put_file(tfile.name, '/tmp/sss_nss_idmap.py')
        multihost.client[0].run_command('python3 /tmp/sss_nss_idmap.py', raiseonerr=True)
        multihost.client[0].run_command('python3 /tmp/sss_nss_idmap.py', raiseonerr=True)
        time.sleep(2)
        log_str = multihost.client[0].get_file_contents('/var/log/sssd/sssd_nss.log').decode('utf-8')
        patt = re.compile(r'999.*does.not.exist.*negative.cache')
        assert patt.search(log_str)

    @pytest.mark.tier1_3
    def test_0003_gssapi_ssh(self, multihost, adjoin, create_aduser_group):
        """
        :title: gssapi ssh log in with 'krb5_confd_path'
        :description: User should log in with GSSAPI after setting
         'krb5_confd_path' option in sssd.conf
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1961182
        :id: 752b69ab-55a8-464f-814b-4985c06dc49a
        :customerscenario: true
        :steps:
            1. Join rhel-client to AD-domain
            2. restart SSSD and clear cache
            3. Fetch kerberos ticket for user
            4. Check user is able to log in with GSSAPI
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. User should be to log in with GSSAPI
        """
        adjoin(membersw='adcli')
        (aduser, _) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_name = client.get_domain_section_name()
        ad_realm = multihost.ad[0].domainname.upper()
        section = f"domain/{dom_name}"
        section_params = {
            'krb5_confd_path': "/etc/krb5.conf.d/",
            'debug_level': '9',
        }
        client.sssd_conf(section, section_params, action="update")
        client.clear_sssd_cache()
        ad_user = f'{aduser}@{dom_name}'
        ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                          "UserKnownHostsFile": "/dev/null"})
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].sys_hostname, f'{ad_user}', 'Secret123')
            ssh.sendline('kdestroy -A -q')
            ssh.prompt(timeout=5)
            ssh.sendline(f'kinit {aduser}@{ad_realm}')
            ssh.expect('Password for .*:', timeout=10)
            ssh.sendline('Secret123')
            ssh.prompt(timeout=5)
            ssh.sendline('klist -A')
            ssh.prompt(timeout=5)
            ssh.sendline(f'ssh -v -o StrictHostKeyChecking=no -o GSSAPIAuthentication=yes '
                         f'-o PasswordAuthentication=no '
                         f'-o PubkeyAuthentication=no -K -l {ad_user} '
                         f'{multihost.client[0].sys_hostname} id')
            ssh.prompt(timeout=30)
            ssh.sendline('echo "ssh_result:$?"')
            ssh.prompt(timeout=30)
            ssh_output = str(ssh.before)
            ssh.logout()
        except pxssh.ExceptionPxssh:
            pytest.fail("Ssh login failed.")
            ssh_output = 'FAIL'
        assert 'ssh_result:0' in ssh_output, "GSSAPI ssh authentication failed"

    @staticmethod
    def test_0004_bz2110091(multihost, adjoin, create_aduser_group):
        """
        :title: SSSD starts offline after reboot
        :id: 8fe03cef-891d-4cb9-be26-d747cb4d8fd8
        :customerscenario: true
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2110091
                   https://bugzilla.redhat.com/show_bug.cgi?id=2116207
        :steps:
          1. Join sssd client to AD
          2. Lookup AD user
          3. Clear sssd cache and logs
          4. Reboot client
          5. Domain logs should have "Destroying the old c-ares channel"
          6. Domain logs should have "[recreate_ares_channel]: Initializing new c-ares channel"
             Initializing new c-ares channel" 2 times
        :expectedresults:
          1. sssd client is enrolled in AD domain successfully
          2. AD user lookup is successful
          3. sssd cache and logs are cleared
          4. Client reboots successfully
          5. Domain logs has string "Destroying the old c-ares channel"
          6. Domain logs has string "[recreate_ares_channel] (0x0100): Initializing new c-ares channel"
             Initializing new c-ares channel" 2 times
        """
        adjoin(membersw='adcli')
        (ad_user, _) = create_aduser_group
        domainname = multihost.ad[0].domainname
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        client.sssd_conf(dom_section, {'debug_level': '9'})
        client.clear_sssd_cache()
        multihost.client[0].run_command(f'getent passwd {ad_user}@{domainname}')
        client.remove_sss_cache("/var/log/sssd")
        multihost.client[0].run_command('systemctl reboot', raiseonerr=False)
        multihost.client[0].run_command('systemctl start sssd', raiseonerr=False)
        log1 = re.compile(r'Destroying.the.old.c-ares.channel', re.IGNORECASE)
        log2 = re.compile(r'\[recreate_ares_channel.*Initializing.new.c-ares.channel', re.IGNORECASE)
        time.sleep(30)
        # Reboot takes a long time in some cases so we try multiple times.
        for _ in range(1, 10):
            try:
                dom_log = multihost.client[0].get_file_contents(
                    f'/var/log/sssd/sssd_{domainname}.log').decode('utf-8')
                if log2.search(dom_log):
                    break
            except OSError:
                # There is no need to fail here as the assertion will fail anyway.
                dom_log = "Could not pull the log file!"
                time.sleep(30)
        assert log1.search(dom_log), 'Destroying the old c-ares related log missing'
        assert log2.search(dom_log), 'Initializing new c-ares related log missing'

    @staticmethod
    def test_0005_get_sid_by_username(multihost, adjoin, create_aduser_group):
        """
        :title: Add 'getsidbyusername()' and 'getsidbygroupname()
        :id: a2b53a5c-6f67-4fb3-ba37-908d4e4abe45
        :customerscenario: false
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2166627
        :setup:
          1. Configure sssd with AD.
          2. Transport a python program, to run a lookup using userid and groupid, on client
        :steps:
          1. Run lookup using username of existing userid
          2. Run lookup using groupname of existing group
        :expectedresults:
          1. domain log file should show that the SID exists for the username
          2. domain log file should show that the SID exists for the group
        """
        adjoin(membersw='adcli')
        (ad_user, _) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        client.sssd_conf(f'domain/{domain_name}', {'debug_level': '9'})
        client.clear_sssd_cache()
        multihost.client[0].run_command('dnf install python3-libsss_nss_idmap -y', raiseonerr=True)
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write('#!/usr/bin/python\n')
            tfile.write('import pysss_nss_idmap as idmap\n')
            tfile.write(f'idmap.getsidbyusername("{ad_user}@{domain_name}")\n')
            tfile.write(f'idmap.getsidbygroupname("domain users@{domain_name}")\n')
            tfile.flush()
            multihost.client[0].transport.put_file(tfile.name, '/tmp/sss_nss_idmap.py')
        multihost.client[0].run_command('python3 /tmp/sss_nss_idmap.py', raiseonerr=True)
