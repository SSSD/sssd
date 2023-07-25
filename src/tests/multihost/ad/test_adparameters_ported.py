""" AD-Provider AD Parameters tests ported from bash

:requirement: ad_parameters
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
# pylint: disable=too-many-lines
import time
import random
import re
import tempfile
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
        f'"Plain {ad_user}" --stdin-password -v',
        stdin_text=password, raiseonerr=False
    )
    # Create group
    session_multihost.client[0].run_command(
        f'adcli create-group {ad_group} -D {domainname} -z '
        f'"Plain {ad_group}" --stdin-password -v',
        stdin_text=password, raiseonerr=False
    )
    # Add member
    session_multihost.client[0].run_command(
        f'adcli add-member -D {domainname} {ad_group} {ad_user} '
        f' --stdin-password -v', stdin_text=password, raiseonerr=False
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


def ssh_change_password(session_multihost, user, old_pass, new_pass):
    """Helper function to change user password on client machine via ssh
    :param session_multihost: multihost object
    :param user: username including domain if needed
    :param old_pass: current password for the user
    :param new_pass: new password for the user
    :returns whether expect command succeeded
    """
    with tempfile.NamedTemporaryFile(mode='w') as tfile:
        tfile.write('#!/usr/bin/expect\n')
        tfile.write('set timeout 20\n')
        tfile.write(f'set user {user}\n')
        tfile.write(f'set password {old_pass}\n')
        tfile.write(f'set new {new_pass}\n')
        tfile.write('set ip localhost\n')
        tfile.write('spawn -noecho ssh -t -q -o StrictHostKeychecking=no '
                    '"$user\\@$ip" "passwd"\n')
        tfile.write('expect "assword:"\n')
        tfile.write('send "$password\\r"\n')
        tfile.write('expect "assword: "\n')
        tfile.write('send "$password\\r"\n')
        tfile.write('expect "New password: "\n')
        tfile.write('send "$new\\r"\n')
        tfile.write('expect "Retype new password: "\n')
        tfile.write('send "$new\\r"\n')
        tfile.write('expect "passwd: all authentication tokens'
                    ' updated successfully."\n')
        tfile.flush()
        session_multihost.client[0].transport.put_file(
            tfile.name, '/tmp/ssh.exp')
    expect_cmd = 'chmod +x /tmp/ssh.exp; /tmp/ssh.exp; echo $?'
    cmd = session_multihost.client[0].run_command(expect_cmd, raiseonerr=False)
    return cmd.returncode == 0


def ssh_setup(session_multihost, user, group=""):
    """Setup a ssh key for a root and add it to authorized keys for user
    :param group: group used to set file ownership
    :param session_multihost: multihost object
    :param user: username including domain if needed
    :returns whether command succeeded
    """
    with tempfile.NamedTemporaryFile(mode='w') as tfile:
        tfile.write('#!/bin/bash -x\n')
        tfile.write('mkdir -p /root/.ssh\n')
        tfile.write('chmod 0700 /root/.ssh\n')
        tfile.write('ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa'
                    ' -q -N "" <<< y\n')
        tfile.write(f'HOMEDIR="$(getent -s sss passwd {user}|awk -F:'
                    f' \'{{print $6}}\')"\n')
        tfile.write(f'test -z "$HOMEDIR" && export HOMEDIR="/home/{user}"\n')
        tfile.write('mkdir -p $HOMEDIR/.ssh\n')
        tfile.write('chmod 0700 $HOMEDIR/.ssh\n')
        tfile.write('cat /root/.ssh/id_rsa.pub >> $HOMEDIR/.ssh/'
                    'authorized_keys\n')
        tfile.write('chmod 0600 $HOMEDIR/.ssh/authorized_keys\n')
        tfile.write('echo "StrictHostKeyChecking=no" >> $HOMEDIR/.ssh'
                    '/config\n')
        if group:
            tfile.write(f'chown -R {user}:{group} $HOMEDIR/.ssh\n')
        else:
            tfile.write(f'chown -R {user} $HOMEDIR/.ssh\n')
        tfile.flush()
        session_multihost.client[0].transport.put_file(
            tfile.name, '/tmp/ssh_setup.sh')
    sh_cmd = 'chmod +x /tmp/ssh_setup.sh; /tmp/ssh_setup.sh; echo $?'
    cmd = session_multihost.client[0].run_command(sh_cmd, raiseonerr=False)
    return cmd.returncode == 0


def set_ssh_key_ldap(session_multihost, user, pubkey, operation="replace"):
    """Setup a ssh key in ldap for user
    :param session_multihost: multihost object
    :param user: username including domain if needed
    :param pubkey: public key to store in ldap
    :param operation: ldif operation (add or replace)
    :returns whether command succeeded
    """
    myid = random.randint(999, 9999)
    with tempfile.NamedTemporaryFile(mode='w', newline='\n') as tfile:
        tfile.write(pubkey)
        tfile.flush()
        session_multihost.client[0].transport.put_file(
            tfile.name, f'/tmp/pubkey.{myid}')
    with tempfile.NamedTemporaryFile(mode='w', newline='\n') as tfile:
        tfile.write(f"dn: cn={user},cn=Users,"
                    f"{session_multihost.ad[0].domain_basedn_entry}\n")
        tfile.write("changetype: modify\n")
        tfile.write(f"{operation}: msDS-cloudExtensionAttribute1\n")
        tfile.write(f'msDS-cloudExtensionAttribute1:< file:'
                    f'/tmp/pubkey.{myid}\n')
        tfile.flush()
        session_multihost.client[0].transport.put_file(
            tfile.name, f'/tmp/mod.{myid}.ldif')
    ldap_cmd = f'ldapmodify -H ldap://{session_multihost.ad[0].hostname}' \
               f' -v -x -D "cn=Administrator,cn=Users,' \
               f'{session_multihost.ad[0].domain_basedn_entry}" -w ' \
               f'"{session_multihost.ad[0].ssh_password}" ' \
               f'-f /tmp/mod.{myid}.ldif'
    cmd = session_multihost.client[0].run_command(ldap_cmd, raiseonerr=False)
    return cmd.returncode == 0


@pytest.mark.adparameters
@pytest.mark.usefixtures("change_client_hostname")
class TestADParamsPorted:
    """ BZ Automated Test Cases for AD Parameters ported from bash"""
    # pylint: disable=too-many-public-methods

    @staticmethod
    @pytest.mark.tier1_2
    def test_0001_ad_parameters_domain(
            multihost, adjoin, create_aduser_group):
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
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Create AD user and group
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': ad_realm,
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
            f'getent passwd {ad_realm_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {ad_realm_short}\\\\{adgroup}',
            raiseonerr=False
        )
        # Run su command
        su_result = client.su_success(rf'{ad_realm_short}\\{aduser}')

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Evaluate test results
        assert f"Option ad_domain has value {ad_realm}" in log_str
        assert f"Option krb5_realm set to {ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found."
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier2
    def test_0002_ad_parameters_junk_domain(
            multihost, create_aduser_group):
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
          https://bugzilla.redhat.com/show_bug.cgi?id=2098615
        """
        arch = multihost.client[0].run_command(
            'uname -m', raiseonerr=False).stdout_text
        if 'x86_64' not in arch:
            pytest.skip("Test does not work other arch due to beaker being on"
                        "different network that openstack.")
        hostname = multihost.client[0].run_command(
            'hostname', raiseonerr=False).stdout_text.rstrip()
        ad_realm = multihost.ad[0].domainname.upper()
        # Join AD manually to set the user-principal properly
        joincmd = f"realm join --user=Administrator --user-principal=host/" \
                  f"{hostname}@{ad_realm} {multihost.ad[0].domainname.lower()}"
        multihost.client[0].run_command(
            joincmd, stdin_text=multihost.ad[0].ssh_password,
            raiseonerr=False)

        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Backup the config because with broken config we can't leave ad
        client.backup_sssd_conf()
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to ad_domain = junk
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
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {ad_realm}\\\\{aduser}', raiseonerr=False)

        # Download /var/log/messages
        log_msg_str = multihost.client[0].get_file_contents(
            '/var/log/messages').decode('utf-8')
        # Restore sssd.conf
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        multihost.client[0].run_command(
            f"realm leave {ad_realm}", raiseonerr=False)

        # Evaluate test results
        assert f"No principal matching {shortname}$@JUNK found in keytab." in \
               log_str
        assert "No principal matching host/*@JUNK found in keytab." in log_str
        assert f"Selected realm: {ad_realm}" in log_str
        assert "segfault" not in log_msg_str, "Segfault present in the log!"
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."

    @staticmethod
    @pytest.mark.tier2
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

        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd with junk domain
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

        ktutil_cmd = f'{{ echo "addent -password -p host/{shortname}@' \
                     f'INVALIDDOMAIN.COM -k 2 -e rc4-hmac"; sleep 1; echo ' \
                     f'"Secret123"; sleep 1; echo "rkt /etc/krb5.keytab"; ' \
                     f'sleep 1; echo "wkt /tmp/first_invalid.keytab"; ' \
                     f'sleep 1; echo "quit"; }} | ktutil'

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

        # TEARDOWN
        # Restore keytab before test result evaluation
        multihost.client[0].run_command(
            'cp -f /etc/krb5.keytab.working /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab',
            raiseonerr=False
        )
        # Cleanup temporary invalid keytab
        multihost.client[0].run_command(
            'test -e /tmp/first_invalid.keytab && '
            'rm -f /tmp/first_invalid.keytab',
            raiseonerr=False
        )

        # Evaluate test results
        assert usr_cmd.returncode == 2, f"{aduser} was unexpectedly found!"
        assert "No principal matching host/*@JUNK found in keytab." in log_str
        assert "Selected realm: INVALIDDOMAIN.COM" in log_str
        assert "Option krb5_realm set to JUNK" in log_str

    @staticmethod
    @pytest.mark.tier1_2
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
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
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
        su_result = client.su_success(rf'{ad_domain_short}\\{aduser}')

        # Evaluate test results
        assert f"Trying to find principal {shortname}$@{ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier2
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

        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
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
        su_result = client.su_success(rf'{ad_domain_short}\\{aduser}')

        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Evaluate test results
        assert "Option ad_domain has no value" in log_str
        assert f"Option krb5_realm set to {ad_realm}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1_2
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
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

        # Evaluate test results
        assert f'/home/{aduser}@{ad_domain.upper()}/{aduser}' in \
               usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.tier1_2
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
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

        # Evaluate test results
        assert f'/home/{aduser}@{ad_domain.upper()}/{aduser}' in \
               usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.tier2
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
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

        # Evaluate test results
        assert f'/home/{aduser}/{aduser}@{ad_domain.upper()}' in \
               usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.tier1_2
    @pytest.mark.c_ares
    def test_0009_ad_parameters_ldap_sasl_full(
            multihost, create_aduser_group):
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
        hostname = multihost.client[0].run_command(
            'hostname', raiseonerr=False).stdout_text.rstrip()
        ad_realm = multihost.ad[0].domainname.upper()
        # Join AD manually to set the user-principal for sasl
        joincmd = f"realm join --user=Administrator --user-principal=host/" \
                  f"{hostname}@{ad_realm} {multihost.ad[0].domainname.lower()}"
        multihost.client[0].run_command(
            joincmd, stdin_text=multihost.ad[0].ssh_password,
            raiseonerr=False)
        # Create AD user
        (aduser, _) = create_aduser_group
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'id_provider': 'ad',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'ldap_id_mapping': 'True',
            'ldap_sasl_authid': f'host/{hostname}@{ad_realm}',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_realm}', raiseonerr=False)
        # Run su command
        su_result = client.su_success(f'{aduser}@{ad_realm}',
                                      with_password=False)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # TEARDOWN
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        multihost.client[0].run_command(
            f"realm leave {ad_realm}", raiseonerr=False)

        # EVALUATION
        assert f"Option ldap_sasl_authid has value " \
               f"host/{hostname}@{ad_realm}" in log_str
        assert "authid contains realm" in log_str
        assert f"Will look for host/{hostname}@{ad_realm} in" in log_str
        assert f"Trying to find principal host/{hostname}@{ad_realm} in " \
               f"keytab" in log_str
        assert f"Principal matched to the sample " \
               f"(host/{hostname}@{ad_realm})" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert su_result, f"Su for user {aduser} failed!"

    @staticmethod
    @pytest.mark.tier2
    @pytest.mark.c_ares
    def test_0010_ad_parameters_ldap_sasl_short(
            multihost, create_aduser_group):
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
             Option ldap_sasl_authid has value host/<HOSTNAME>
             Will look for host/<HOSTNAME>@<AD_REALM> in
             Trying to find principal host/<HOSTNAME>@<AD_REALM> in keytab
             Principal matched to the sample (host/<HOSTNAME>@<AD_REALM>)
             "authid contains realm [<AD_REALM>]" should not be in the log
        :expectedresults:
          1. User is found.
          2. Su passes.
          3. Expected lines are in the log.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1137015
        """

        hostname = multihost.client[0].run_command(
            'hostname', raiseonerr=False).stdout_text.rstrip()
        ad_realm = multihost.ad[0].domainname.upper()

        # Join AD manually to set the user-principal for sasl
        joincmd = f"realm join --user=Administrator --user-principal=host/" \
                  f"{hostname}@{ad_realm} {multihost.ad[0].domainname.lower()}"
        multihost.client[0].run_command(
            joincmd, stdin_text=multihost.ad[0].ssh_password,
            raiseonerr=False)
        # Create AD user
        (aduser, _) = create_aduser_group
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'id_provider': 'ad',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'ldap_id_mapping': 'True',
            'ldap_sasl_authid': f'host/{hostname}',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_realm}', raiseonerr=False)
        # Run su command
        su_result = client.su_success(f'{aduser}@{ad_realm}',
                                      with_password=False)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # TEARDOWN
        client.restore_sssd_conf()
        client.clear_sssd_cache()
        multihost.client[0].run_command(
            f"realm leave {ad_realm}", raiseonerr=False)

        # EVALUATION
        assert f"Option ldap_sasl_authid has value " \
               f"host/{hostname}" in log_str
        assert "authid contains realm" not in log_str
        assert f"Will look for host/{hostname}@{ad_realm} in" in log_str
        assert f"Trying to find principal host/{hostname}@{ad_realm} in " \
               f"keytab" in log_str
        assert f"Principal matched to the sample " \
               f"(host/{hostname}@{ad_realm})" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert su_result, f"Su for user {aduser} failed!"

    @staticmethod
    @pytest.mark.tier1_2
    @pytest.mark.c_ares
    def test_0011_ad_parameters_server_resolvable(
            multihost, adjoin, create_aduser_group):
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
        sssd_params = {
            'debug_level': '9',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
        }
        client.sssd_conf(
            f'domain/{client.get_domain_section_name()}', sssd_params)
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
        su_result = client.su_success(aduser)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        assert f"Option ad_domain has value " \
               f"{multihost.ad[0].domainname.lower()}" in log_str
        assert f"Option krb5_realm set to " \
               f"{multihost.ad[0].domainname.upper()}" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert uid_cmd.returncode == 0, f"User with {uid} was not found!"
        assert gid_cmd.returncode == 0, f"Group with {gid} was not found!"
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier2
    @pytest.mark.c_ares
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
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

        assert f"Failed to resolve server 'unresolved." \
               f"{multihost.ad[0].domainname.lower()}': " \
               f"Domain name not found" in log_str
        assert "Going offline" in log_str
        assert usr_cmd.returncode == 2, f"User {aduser} was found!"

    @staticmethod
    @pytest.mark.tier1_2
    @pytest.mark.c_ares
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
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
        su_result = client.su_success(aduser)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        assert "Marking SRV lookup of service 'AD' as 'resolved'" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1_2
    @pytest.mark.c_ares
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
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
        su_result = client.su_success(aduser)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        assert "No AD server set, will use service discovery" in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.flaky(reruns=5, reruns_delay=30)
    @pytest.mark.tier2
    def test_0015_ad_parameters_ad_hostname_machine(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Hostname not
          identified on AD
        :id: 5f6e5a03-8617-4a93-a3e8-24efe99554f9
        :setup:
          1. Change hostname to host1.kautest.com.
          2. Create an AD user.
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent passwd for the user.
          2. Check the sssd domain log for expected messages.
          3. Run su to the user.
        :expectedresults:
          1. User is found.
          2. Log contains the expected line and does not have unexpected one:
             Expected: Will look for host1.kautest.com@<ad_realm>
             Unexpected: Setting ad_hostname to [host1.kautest.com]
          3. User is switched successfully.
        :teardown:
          1. Remove AD user.
        :customerscenario: False
        """
        arch = multihost.client[0].run_command(
            'uname -m', raiseonerr=False).stdout_text
        if 'x86_64' not in arch:
            pytest.skip("Test is unstable on architectures other than x86_64.")

        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        hostname_cmd = multihost.client[0].run_command(
            'hostname', raiseonerr=False)
        old_hostname = hostname_cmd.stdout_text.rstrip()

        # Set new hostname
        multihost.client[0].run_command(
            'hostname host1.kautest.com', raiseonerr=False)

        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group

        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_realm = multihost.ad[0].domainname.upper()
        sssd_params = {
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

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}', raiseonerr=False)

        # Run su
        su_result = client.su_success(aduser)

        # Download sssd log
        for _ in range(1, 3):
            # Wait for log to be written
            time.sleep(15)
            log_str = multihost.client[0].get_file_contents(
                f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
                decode('utf-8')
            if "kautest.com" in log_str:
                break

        # Reset hostname
        multihost.client[0].run_command(
            f'hostname {old_hostname}', raiseonerr=False)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_result, "The su command failed!"
        assert "Setting ad_hostname to [host1.kautest.com]" in log_str
        assert f"Will look for host1.kautest.com@{ad_realm}" in log_str


    @staticmethod
    @pytest.mark.tier1_2
    @pytest.mark.c_ares
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
        arch = multihost.client[0].run_command(
            'uname -m', raiseonerr=False).stdout_text
        if 'x86_64' not in arch:
            pytest.skip("Test is unstable on architectures other than x86_64.")
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        hostname_cmd = multihost.client[0].run_command(
            'hostname', raiseonerr=False)
        old_hostname = hostname_cmd.stdout_text.rstrip()

        # Set new hostname
        multihost.client[0].run_command(
            'hostname host1.kautest.com', raiseonerr=False)

        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
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

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}', raiseonerr=False)
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {adgroup}', raiseonerr=False)
        # Run su
        su_result = client.su_success(aduser)
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')
        # Reset new hostname
        multihost.client[0].run_command(
            f'hostname {old_hostname}', raiseonerr=False)
        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_result, "The su command failed!"
        assert f"Option ad_hostname has value {old_hostname}" in log_str
        assert f"Setting ad_hostname to [{old_hostname}]" not in log_str
        assert f"Will look for {old_hostname}@{ad_realm}" in log_str
        assert f"Trying to find principal {old_hostname}@{ad_realm}" in log_str

    @staticmethod
    @pytest.mark.tier2
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
        # Hide keytab
        multihost.client[0].run_command(
            'mv -f /etc/krb5.keytab /etc/krb5.keytab.working',
            raiseonerr=False
        )
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
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

        # Evaluate test results
        assert "Option krb5_keytab has value /etc/krb5.keytab." \
               "keytabdoesntexist" in log_str
        assert "Option ldap_krb5_keytab set to /etc/krb5.keytab." \
               "keytabdoesntexist" in log_str
        assert "No suitable principal found in keytab" in log_str
        assert usr_cmd.returncode == 2, f"User {aduser} was found."

    @staticmethod
    @pytest.mark.tier2
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
        su_result = client.su_success(aduser)
        # Restore keytab
        multihost.client[0].run_command(
            'mv /usr/local/etc/krb5.keytab /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab',
            raiseonerr=False
        )

        # Evaluate test results
        assert "Option krb5_keytab has value /usr/local/etc/krb5.keytab" \
               in log_str
        assert "Option ldap_krb5_keytab set to /usr/local/etc/krb5.keytab" \
               in log_str
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1_2
    def test_0019_ad_parameters_ldap_id_mapping_false(
            multihost, adjoin, create_aduser_group, create_plain_aduser_group
    ):
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
        # pylint: disable=too-many-locals
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        (userplain, group_plain) = create_plain_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
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
        su_result = client.su_success(aduser)

        # Evaluate test results
        assert usr_uid_cmd.returncode == 0, f"User {uid} was not found."
        assert grp_gid_cmd.returncode == 0, f"Group {gid} was not found!"
        assert plain_usr_cmd.returncode == 2, f"User {aduser} was found!"
        assert plain_grp_cmd.returncode == 2, f"Group {adgroup} was found!"
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1_2
    def test_0020_ad_parameters_ssh_change_password(
            multihost, adjoin, create_aduser_group
    ):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Change user password
        :id: c72a5e3c-1e81-4333-ba72-de11720ca629
        :setup:
          1. Configure logging, clear cache and restart sssd.
          2. Create an AD user and group.
        :steps:
          1. Run getent passwd for the user.
          2. Change user password.
          3. Run su to the user with the new password.
        :expectedresults:
          1. User is found.
          2. Password is changed.
          3. Su succeeds.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Make sure that AD server allows password change
        multihost.ad[0].run_command(
            f"powershell 'Import-Module ActiveDirectory; "
            f"Set-ADDefaultDomainPasswordPolicy -Identity "
            f"{multihost.ad[0].domainname} -MinPasswordAge 00.00:00:00'",
            raiseonerr=False
        )

        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to enable logging
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
        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}', raiseonerr=False)
        # Change user password via expect + ssh + passwd
        exp_result = client.change_user_password(
            aduser, 'Secret123', 'Secret123', 'NewPass1_123!', 'NewPass1_123!'
        ) == 3

        # Wait a bit for password change to propagate
        time.sleep(10)
        # Run su
        su_result = client.su_success(aduser, password='NewPass1_123!')

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert exp_result, "Password change failed."
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1_2
    def test_0021_ad_parameters_ssh_change_password_logon(
            multihost, adjoin, create_aduser_group
    ):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: User must change
         password on next logon bz1078840
        :id: e3f7cd31-035b-4820-8b39-9d703a6060d4
        :setup:
          1. Configure logging, clear cache and restart sssd.
          2. Create an AD user.
        :steps:
          1. Set password expiration for user.
          2. Change user password via ssh.
          3. Run su to the user with the new password.
          4. Check the /var/log/secure log for expected messages.
        :expectedresults:
          1. Expiration configured.
          2. Password is changed.
          3. Su succeeds.
          4. Message "system error" is not in log.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1078840
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to enable logging
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

        # Expire user password
        ad_op = ADOperations(multihost.ad[0])
        ad_op.expire_account_password(aduser)

        # Change user password via expect + ssh + passwd
        exp_result = ssh_change_password(
            multihost, aduser, 'Secret123', 'NewPass1_123')
        # exp_result = client.change_user_password(
        #     aduser, 'Secret123', 'Secret123', 'NewPass1_123', 'NewPass1_123'
        # ) == 3
        # Wait a bit for password change to propagate
        time.sleep(10)
        # Run su
        su_result = client.su_success(aduser, password='NewPass1_123')

        # Download log
        log_str = multihost.client[0].get_file_contents(
            "/var/log/secure").decode('utf-8')

        # Teardown
        ad_op.unexpire_account_password(aduser)

        # Evaluate test results
        assert exp_result, "Password change failed."
        assert su_result, "The su command failed!"
        assert "system error" not in log_str

    @staticmethod
    @pytest.mark.tier1_2
    def test_0022_ad_parameters_account_disabled(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: User account disabled
        :id: e577001f-11f7-43a6-abc9-75bd5c98dd4c
        :setup:
          1. Configure logging, clear cache and restart sssd.
          2. Create an AD user.
          3. Configure ssh key for root as authorized key for AD user
        :steps:
          1. Run ssh login with key to the AD user.
          2. Disable AD user account.
          3. Run ssh login with key to the AD user.
          4. Run ssh login with password to the AD user.
          5. Log /var/log/secure contains expected messages.
        :expectedresults:
          1. Login succeeds.
          2. Account is disabled.
          3. Login fails.
          4. Login fails.
          5. Log contains:
             user <user>: 6 (Permission denied)
             The user account is disabled on the AD server
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1078840
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to enable logging
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
            'ad_enable_gc': 'False',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        ssh_setup(multihost, aduser)
        first_login_result = client.auth_from_client_key(aduser)

        # Disable AD account
        ad_op = ADOperations(multihost.ad[0])
        ad_op.disable_account(aduser)

        client.clear_sssd_cache()
        second_login_result = client.auth_from_client_key(aduser)

        password_login_res = client.auth_from_client(aduser, 'Secret123') == 3

        # We need to wait for the event to be written to the log,
        # otherwise test randomly fails.
        time.sleep(15)

        # Download log
        log_str = multihost.client[0].get_file_contents(
            "/var/log/secure").decode('utf-8')

        # Teardown
        ad_op.enable_account(aduser)

        # Evaluate test results
        assert first_login_result, "Could not login over ssh before."
        assert not second_login_result, "Disabled user logged via ssh key!"
        assert not password_login_res, "Disabled user logged via password!"
        assert f"user {aduser}: 6 (Permission denied)" in log_str
        assert "The user account is disabled on the AD server" in log_str

    @staticmethod
    @pytest.mark.tier1_2
    def test_0023_ad_parameters_account_expired(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: User account is
         expired bz1081046
        :id: be930f04-ba84-4de4-b7b8-6ed39711bafe
        :setup:
          1. Configure logging, clear cache and restart sssd.
          2. Create an AD user.
          3. Configure ssh key for root as authorized key for AD user
        :steps:
          1. Run ssh login with key to the AD user.
          2. Expire user account.
          3. Run ssh login with key to the AD user.
          4. Run ssh login with password to the AD user.
          5. Log /var/log/secure contains expected messages.
        :expectedresults:
          1. Login succeeds.
          2. Account expired.
          3. Login fails.
          4. Login fails.
          5. Log contains:
             <user>: 13 (User account has expired)
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1081046
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to enable logging
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
            'ad_enable_gc': 'False',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        ssh_setup(multihost, aduser)
        first_login_result = client.auth_from_client_key(aduser)

        # Expire account on AD
        ad_op = ADOperations(multihost.ad[0])
        ad_op.expire_account(aduser)

        client.clear_sssd_cache()
        second_login_result = client.auth_from_client_key(aduser)
        password_login_res = client.auth_from_client(aduser, 'Secret123') == 3

        # We need to wait for the event to be written to the log,
        # otherwise test randomly fails.
        time.sleep(15)

        # Download log
        log_str = multihost.client[0].get_file_contents(
            "/var/log/secure").decode('utf-8')

        # Teardown
        ad_op.unexpire_account(aduser)

        # Evaluate test results
        assert first_login_result, "Could not login over ssh before."
        assert not second_login_result, "Expired user logged via ssh key!"
        assert not password_login_res, "Expired user logged via password!"
        assert f"{aduser}: 13 (User account has expired)" in log_str

    @staticmethod
    @pytest.mark.tier1_2
    def test_0024_ad_parameters_getgrgid_nested(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: getgrgid removes
          nested group memberships bz887961
        :id: 62abb34d-790a-4169-8653-41e3d176246f
        :setup:
          1. Create parent group and add "Domain Users" group as a member
          2. Create an AD user and group without uid and gid.
          3. Get gids for parent group and Domain Users groups
        :steps:
          1. Check output of id -G for user
          2. Check output of id for user
          3. Check output of id -G for user
        :expectedresults:
          1. Parent group and "Domain Users" gids are in the output.
          2. Parent group and "Domain Users" are in the output.
          3. Parent group and "Domain Users" gids are in the output.
        :teardown:
          1. Remove AD users and groups.
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=887961
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user without posix attributes
        (userplain, _) = create_plain_aduser_group
        # Configure sssd
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(
            f'domain/{client.get_domain_section_name()}', sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Create parent group and add "domain users" to this group
        parent_grp = f'parent_group-{random.randint(9999, 999999)}'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_nonposix_group(parent_grp)
        ad_op.add_user_member_of_group(parent_grp, "Domain Users")

        # Get GIDs
        dom_usr_gid = multihost.client[0].run_command(
            'getent group "domain users" | cut -d: -f3',
            raiseonerr=False).stdout_text.rstrip()

        par_grp_gid = multihost.client[0].run_command(
            f'getent group "{parent_grp}" | cut -d: -f3',
            raiseonerr=False).stdout_text.rstrip()

        test1_cmd = multihost.client[0].run_command(
            f'id -G {userplain} | grep {dom_usr_gid} | grep {par_grp_gid}',
            raiseonerr=False
        )
        test2_cmd = multihost.client[0].run_command(
            f'id {userplain} | grep {parent_grp} | grep domain',
            raiseonerr=False
        )
        test3_cmd = multihost.client[0].run_command(
            f'id -G {userplain} | grep {dom_usr_gid} | grep {par_grp_gid}',
            raiseonerr=False
        )

        # Teardown
        ad_op.delete_ad_user_group(parent_grp)

        # Evaluate test results
        assert test1_cmd.returncode == 0, "Gid of expected group missing."
        assert test2_cmd.returncode == 0, "Name of expected group missing."
        assert test3_cmd.returncode == 0, "Gid of expected group missing."

    @staticmethod
    @pytest.mark.tier1_2
    def test_0025_ad_parameters_empty_group(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: empty group cannot
         be resolved using ad matching rule bz1033084
        :id: 25f059f6-dbe6-4341-98e8-d85a4955a3cb
        :setup:
          1. Create new empty group
          2. Configure ldap_groups_use_matching_rule_in_chain
          3. Clear cache and restart sssd.
        :steps:
          1. Run getent group for empty group
        :expectedresults:
          1. Group is found.
        :teardown:
          1. Remove AD users and groups.
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1033084
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Configure sssd
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'ldap_groups_use_matching_rule_in_chain': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Create empty group
        empty_grp = f'empty_group-{random.randint(9999, 999999)}'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_nonposix_group(empty_grp)

        # Get GIDs
        getent_cmd = multihost.client[0].run_command(
            f'getent group {empty_grp}', raiseonerr=False)

        # Teardown
        ad_op.delete_ad_user_group(empty_grp)

        # Evaluate test results
        assert getent_cmd.returncode == 0, "Group not found!"

    @staticmethod
    @pytest.mark.tier2
    @pytest.mark.c_ares
    def test_0026_ad_parameters_dns_failover(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: SSSD failover
         does not work bz966757
        :id: a30ce99a-eaea-4694-98b4-e7e74aa3fa7d
        :setup:
          1. Configure first dns server to unavailable one
          2. Create an AD user and group without uid and gid.
          3. Clear cache and restart sssd.
        :steps:
          1. Search for the user
        :expectedresults:
          1. SSSD does failover an user is found
        :teardown:
          1. Remove AD users and groups.
          2. Restore dns configuration.
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=966757
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Create AD user with no posix attributes
        (userplain, _) = create_plain_aduser_group
        # Configure sssd
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Backup and change resolv.conf
        multihost.client[0].run_command(
            'cp -f /etc/resolv.conf /etc/resolv.conf.orig',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            f'echo -n "nameserver 10.10.10.10\nnameserver '
            f'{multihost.ad[0].ip}\n"> /etc/resolv.conf',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            'cat /etc/resolv.conf',
            raiseonerr=False
        )
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Search for an user
        getent_cmd = multihost.client[0].run_command(
            f'getent passwd {userplain}',
            raiseonerr=False
        )

        # Teardown
        # Restore resolv.conf
        multihost.client[0].run_command(
            'cp -f /etc/resolv.conf.orig /etc/resolv.conf',
            raiseonerr=False
        )

        # Evaluate test results
        assert getent_cmd.returncode == 0, "User not found."

    @staticmethod
    @pytest.mark.tier1_2
    def test_0027_ad_parameters_group_membership_empty(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: ad group membership
         is empty when id mapping is off bz1130017
        :id: 8079f0be-ff77-41a7-ad72-9d3e345ff401
        :setup:
          1. Configure ldap_is_mapping to False
          2. Create a posix AD user and group.
          3. Add two more posix groups and user to them.
          4. Clear cache and restart sssd.
        :steps:
          1. Run id for the user.
          2. Run getent group for the group.
        :expectedresults:
          1. User is found, groups are listed for the user.
          2. Group is found, user is listed as a member.
        :teardown:
          1. Remove AD user and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1130017
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to disable ldap_id_mapping and enable logging
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

        # Create additional groups and add aduser to them
        group_1 = f'{adgroup}-1'
        group_2 = f'{adgroup}-2'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_unix_group(group_1)
        ad_op.create_ad_unix_group(group_2)
        ad_op.add_user_member_of_group(group_1, aduser)
        ad_op.add_user_member_of_group(group_2, aduser)

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'id {aduser}', raiseonerr=False)
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {adgroup}', raiseonerr=False)

        # Teardown
        ad_op.delete_ad_user_group(group_1)
        ad_op.delete_ad_user_group(group_2)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert adgroup in usr_cmd.stdout_text, f"{adgroup} not in id output."
        assert group_1 in usr_cmd.stdout_text, f"{group_1} not in id output."
        assert group_2 in usr_cmd.stdout_text, f"{group_2} not in id output."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found!"
        assert aduser in grp_cmd.stdout_text, f"{aduser} not in getent out."

    @staticmethod
    @pytest.mark.flaky(reruns=5, reruns_delay=30)
    @pytest.mark.tier2
    def test_0028_ad_parameters_nested_in_nonposix_group(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: enumerate nested
         groups if they are part of non POSIX groups bz1103487
        :id: 00f5eb1a-c8fe-4370-8fe7-9c76a16bd226
        :setup:
          1. Configure sssd to use AD as ldap
          2. Create a posix AD user and usergroup.
          3. Create non-posix and posix groups and nest them:
             group2(posix)->group1(nonposix)->usergroup(posix)->user(posix)
          4. Clear cache and restart sssd.
        :steps:
          1. Run id for the user.
        :expectedresults:
          1. User is found, group2 is listed for the user in id output.
        :teardown:
          1. Remove AD user and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1103487
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Create AD user with posix attributes
        (aduser, adgroup) = create_aduser_group
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'id_provider': 'ldap',
            'ldap_schema': 'ad',
            'ldap_id_use_start_tls': 'False',
            'ldap_default_bind_dn': f'CN=administrator,CN=Users'
                                    f',{multihost.ad[0].domain_basedn_entry}',
            'ldap_default_authtok_type': 'password',
            'ldap_default_authtok': f'{multihost.ad[0].ssh_password}',
            'ldap_referrals': 'false',
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Create additional groups and memberships
        group_1 = f'{adgroup}-1'
        group_2 = f'{adgroup}-2'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_nonposix_group(group_1)
        ad_op.add_user_member_of_group(group_1, adgroup)
        ad_op.create_ad_unix_group(group_2)
        ad_op.add_user_member_of_group(group_2, group_1)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'id {aduser}', raiseonerr=False)

        # Teardown
        ad_op.delete_ad_user_group(group_1)
        ad_op.delete_ad_user_group(group_2)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert group_2 in usr_cmd.stdout_text, f"{group_2} not in id output."

    @staticmethod
    @pytest.mark.flaky(reruns=5, reruns_delay=30)
    @pytest.mark.tier2
    def test_0029_ad_parameters_tokengroups_with_ldap(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: tokengroups do not
         work with id provider ldap bz1120508
        :id: f46ddf73-472a-4575-8bc0-63dce4f77b16
        :setup:
          1. Configure sssd to use AD as ldap and use_fully_qualified_names
          2. Create a posix AD user and group.
          3. Clear cache and restart sssd.
        :steps:
          1. Run id for the user with fully qualified name.
        :expectedresults:
          1. User is found.
        :teardown:
          1. Remove AD user and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1120508
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_domain = multihost.ad[0].domainname
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'id_provider': 'ldap',
            'ldap_schema': 'ad',
            'ldap_id_use_start_tls': 'False',
            'ldap_default_bind_dn': f'CN=administrator,CN=Users'
                                    f',{multihost.ad[0].domain_basedn_entry}',
            'ldap_default_authtok_type': 'password',
            'ldap_default_authtok': f'{multihost.ad[0].ssh_password}',
            'ldap_referrals': 'false',
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'id {aduser}@{ad_domain}', raiseonerr=False)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert f'No ID ctx available for [{multihost.ad[0].domainname}]'\
               not in log_str

    @staticmethod
    @pytest.mark.flaky(reruns=5, reruns_delay=30)
    @pytest.mark.tier2
    def test_0030_ad_parameters_tokengroups_searchbase(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Problems with
         tokengroups and ldap group search base bz1127266
        :id: d2bc17f2-bd09-4f94-9ba2-20cbc22eb39d
        :setup:
          1. Create a subtree in ldap
          2. Configure sssd to use AD as ldap with subtree.
          3. Create a posix AD user and group.
          4. Clear cache and restart sssd.
        :steps:
          1. Run id for the user with fully qualified name.
        :expectedresults:
          1. User is found.
        :teardown:
          1. Remove AD user and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1120508
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_domain = multihost.ad[0].domainname
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group

        # Create a subtree
        subtree = f'subtree-{random.randint(999,9999)}'
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write(f"dn: OU={subtree},"
                        f"{multihost.ad[0].domain_basedn_entry}\n")
            tfile.write("objectClass: top\n")
            tfile.write("objectClass: organizationalUnit\n")
            tfile.write(f"ou: {subtree}\n")
            tfile.write(f"distinguishedName: OU={subtree},"
                        f"{multihost.ad[0].domain_basedn_entry}\n")
            tfile.write(f"name: {subtree}\n")
            tfile.flush()
            multihost.client[0].transport.put_file(tfile.name, '/tmp/mod.ldif')
        ldap_cmd = f'ldapadd -a -v -x -H ldap://{multihost.ad[0].hostname}' \
                   f' -D "cn=Administrator,cn=Users,' \
                   f'{multihost.ad[0].domain_basedn_entry}" -w ' \
                   f'"{multihost.ad[0].ssh_password}" -f /tmp/mod.ldif'

        multihost.client[0].run_command(ldap_cmd)

        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'id_provider': 'ldap',
            'ldap_schema': 'ad',
            'ldap_id_use_start_tls': 'False',
            'ldap_default_bind_dn': f'CN=administrator,CN=Users'
                                    f',{multihost.ad[0].domain_basedn_entry}',
            'ldap_default_authtok_type': 'password',
            'ldap_default_authtok': f'{multihost.ad[0].ssh_password}',
            'ldap_referrals': 'false',
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
            'ldap_group_search_base':
                f'OU={subtree},{multihost.ad[0].domain_basedn_entry}',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Search for the AD user
        usr_cmd = multihost.client[0].run_command(
            f'id {aduser}@{ad_domain}', raiseonerr=False)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Teardown
        # Remove subtree from ldap
        ldap_cmd = f'ldapdelete -v -x -H ldap://{multihost.ad[0].hostname}' \
                   f' -D "cn=Administrator,cn=Users,' \
                   f'{multihost.ad[0].domain_basedn_entry}" -w ' \
                   f'"{multihost.ad[0].ssh_password}" "OU={subtree},' \
                   f'{multihost.ad[0].domain_basedn_entry}"'

        multihost.client[0].run_command(ldap_cmd, raiseonerr=False)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert f'No ID ctx available for [{multihost.ad[0].domainname}]'\
               not in log_str

    @staticmethod
    @pytest.mark.tier1_2
    def test_0031_ad_parameters_custom_re(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: sssd does not work
         with custom value of option re expression bz1165794
        :id: 335d0cd4-8278-4c82-93fa-61236fa3e967
        :setup:
         1. Configure custom regex, clear cache and restart sssd.
         2. Create AD user and group.
        :steps:
          1. Run getent passwd for the user
          2. Run getent group for the group
          3. Run check that su can switch to the ad user
        :expectedresults:
          1. User is found
          2. Group is found
          3. Su works as expected
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1165794
        """
        adjoin(membersw='adcli')
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Create AD user and group
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'full_name_format': '%2$s\\%1$s',
            're_expression': r'(?P<domain>[^\\]+)\\(?P<name>[^\\]+)',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {ad_realm_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {ad_realm_short}\\\\{adgroup}',
            raiseonerr=False
        )
        # Run su command
        su_result = client.su_success(rf'{ad_realm_short}\\{aduser}')

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found."
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier1_2
    def test_0032_ad_parameters_group_name_attribute(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Does sssd ad use
         the most suitable attribute for group name bz1199445
        :id: 421e8617-cd13-484a-b1eb-2b3a4ac06ad8
        :setup:
          1. Configure sssd for use_fully_qualified_names
          2. Create a posix group with space in name.
          3. Change the group sAMAccountName removing the space.
          4. Clear cache and restart sssd.
        :steps:
          1. Run getent group for the group name with space.
          2. Run getent group for the group name without space.
        :expectedresults:
          1. Group with space in name is not found.
          2. Group without space in name is found.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1199445
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'krb5_realm': f'{ad_realm_short}',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Create group
        rand_num = random.randint(999, 9999)
        test_group = f'Test grp-{rand_num}'
        test_group_mod = f'Testgrp-{rand_num}'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_unix_group(test_group)
        # Modify group
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write(f"dn: cn={test_group},cn=Users,"
                        f"{multihost.ad[0].domain_basedn_entry}\n")
            tfile.write("replace: sAMAccountName\n")
            tfile.write(f"sAMAccountName: {test_group_mod}\n")
            tfile.flush()
            multihost.client[0].transport.put_file(tfile.name, '/tmp/mod.ldif')
        ldap_cmd = f'ldapmodify -v -x -H ldap://{multihost.ad[0].hostname}' \
                   f' -D "cn=Administrator,cn=Users,' \
                   f'{multihost.ad[0].domain_basedn_entry}" -w ' \
                   f'"{multihost.ad[0].ssh_password}" -f /tmp/mod.ldif'
        multihost.client[0].run_command(ldap_cmd)

        # Search for the AD group
        grp1_cmd = multihost.client[0].run_command(
            f'getent group "{test_group}"@{multihost.ad[0].domainname}',
            raiseonerr=False)

        grp2_cmd = multihost.client[0].run_command(
            f'getent group {test_group_mod}@{multihost.ad[0].domainname}',
            raiseonerr=False)

        # Teardown
        ad_op.delete_ad_user_group(test_group)

        # Evaluate test results
        assert grp1_cmd.returncode == 2, f"{test_group} was found."
        assert grp2_cmd.returncode == 0, f"{test_group_mod} was not found."

    @staticmethod
    @pytest.mark.tier1_2
    def test_0033_ad_parameters_group_cleanup_sanitize(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: groups cleanup
         should sanitize dn of groups bz1364118
        :id: c3b68db0-59c5-43fd-9b6c-fb92d17152f6
        :setup:
          1. Configure sssd cache timeouts
          2. Create a posix user and group with ( in name
          3. Change the group sAMAccountName to the name with (.
          4. Clear cache and restart sssd.
        :steps:
          1. Run getent passwdp for the user.
          2. Run getent group for the group.
          3. Check log for a specific message.
        :expectedresults:
          1. User is found.
          2. Group is found.
          3. Log does not contain error about failed cache cleanup.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1364118
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_realm_short = multihost.ad[0].domainname.upper().rsplit('.', 1)[0]
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'krb5_realm': f'{ad_realm_short}',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'entry_cache_timeout': '20',
            'ldap_purge_cache_timeout': '20',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Create user and group
        rand_num = random.randint(999, 9999)
        test_group = f'testgrp-({rand_num})'
        test_user = f'testusr-({rand_num})'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_unix_user_group(test_user, test_group)

        # Modify group
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write(f"dn: cn={test_group},cn=Users,"
                        f"{multihost.ad[0].domain_basedn_entry}\n")
            tfile.write("replace: sAMAccountName\n")
            tfile.write(f"sAMAccountName: {test_group}\n")
            tfile.flush()
            multihost.client[0].transport.put_file(tfile.name, '/tmp/mod.ldif')
        ldap_cmd = f'ldapmodify -v -x -H ldap://{multihost.ad[0].hostname}' \
                   f' -D "cn=Administrator,cn=Users,' \
                   f'{multihost.ad[0].domain_basedn_entry}" -w ' \
                   f'"{multihost.ad[0].ssh_password}" -f /tmp/mod.ldif'
        multihost.client[0].run_command(ldap_cmd)

        # Search for the AD user and group
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd "{test_user}"@{multihost.ad[0].domainname}',
            raiseonerr=False)

        grp_cmd = multihost.client[0].run_command(
            f'getent group "{test_group}"@{multihost.ad[0].domainname}',
            raiseonerr=False)
        time.sleep(20)

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # Teardown
        ad_op.delete_ad_user_group(test_group)
        ad_op.delete_ad_user_group(test_user)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {test_user} was not found."
        assert grp_cmd.returncode == 0, f"Group {test_group} was not found."
        assert f'Task [Cleanup of {multihost.ad[0].domainname}]: failed' \
               f' with [5]: Input/output error' not in log_str

    @staticmethod
    @pytest.mark.tier2
    def test_0034_ad_parameters_group_work_intermittently(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: sssd ad groups
         work intermittently bz1212610
        :id: 649b507e-1c23-41a7-80a6-91994bd67361
        :setup:
          1. Configure sssd to ignore_group_members = true
          2. Clear cache and restart sssd.
          3. Create a posix user and group
          4. Create extra groups and add user to them
        :steps:
          1. Run getent passwd for the user.
          2. Clear cache and restart sssd.
          3. Run getent passwd for the user.
        :expectedresults:
          1. User is found and all groups are present in the output.
          2. SSSD restarted.
          3. User is found and all groups are present in the output.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1212610
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_realm_short = multihost.ad[0].domainname.upper().rsplit('.', 1)[0]
        # Configure sssd to enable logging
        sssd_params = {
            'ldap_id_mapping': 'True',
            'krb5_realm': f'{ad_realm_short}',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'ignore_group_members': 'True',
        }
        client.sssd_conf(
            f'domain/{client.get_domain_section_name()}', sssd_params)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Create user and group
        rand_num = random.randint(999, 9999)
        test_group = f'testgrp-{rand_num}-1'
        test_user = f'testusr-{rand_num}'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_unix_user_group(test_user, test_group)

        # Create additional 8 groups
        groups = [test_group, ]
        for idx in range(2, 10):
            group_name = f'testgrp-{rand_num}-{idx}'
            ad_op.create_ad_nonposix_group(group_name)
            ad_op.add_user_member_of_group(group_name, test_user)
            groups.append(group_name)

        usr_cmd = multihost.client[0].run_command(
            f'id "{test_user}"@{multihost.ad[0].domainname}', raiseonerr=False)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        usr2_cmd = multihost.client[0].run_command(
            f'id "{test_user}"@{multihost.ad[0].domainname}', raiseonerr=False)

        # Teardown
        ad_op.delete_ad_user_group(test_user)
        for group in groups:
            ad_op.delete_ad_user_group(group)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {test_user} was not found.(1)"
        assert usr2_cmd.returncode == 0, f"User {test_user} was not found.(3)"
        for group in groups:
            assert group in usr_cmd.stdout_text, "{group} is missing.(1)"
            assert group in usr2_cmd.stdout_text, "{group} is missing.(3)"

    @staticmethod
    @pytest.mark.tier2
    def test_0035_ad_parameters_delete_cache(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: groups get deleted
          from the cache bz1279971
        :id: 630c7fbe-3f02-438c-8ae0-7f99347cfa18
        :setup:
         1. Configure custom regex, clear cache and restart sssd.
         2. Create AD user and group (user1).
         3. Create additional AD user (user2) and group (group2)
            and set its group as primary.
        :steps:
          1. Run getent passwd for user1 user.
          2. Run getent passwd for user2 user.
          3. Set sssd offline by manipulating iptables.
          4. Run getent passwd for user2 user.
        :expectedresults:
          1. User 1 is found and is member of domain users .
          2. Users primary group is group2 and is in domain users.
          3. SSSD is offline according the log.
          4. User 2 is found and is member of domain users .
        :teardown:
          1. Delete users and groups.
          2. Restore network via iptables.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1279971
        """
        # pylint: disable=too-many-locals
        adjoin(membersw='adcli')
        ad_domain = multihost.ad[0].domainname
        ad_realm = ad_domain.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Create AD user and group
        (user1, _) = create_aduser_group
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': ad_domain,
            'krb5_realm': f'{ad_realm_short}',
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'ldap_schema': 'ad',
            'default_shell': '/bin/bash',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        rand_num = random.randint(999, 9999)
        user2 = f'testusr_2_{rand_num}'
        multihost.client[0].run_command(
            f'adcli create-user {user2} -D {ad_domain} --display-name='
            f'"Plain {user2}" --stdin-password -v',
            stdin_text=multihost.ad[0].ssh_password, raiseonerr=False
        )

        group2 = f'testgrp_2_{rand_num}'
        ad_op = ADOperations(multihost.ad[0])
        ad_op.create_ad_nonposix_group(group2)
        ad_op.add_user_member_of_group(group2, user2)

        # Configure user2 primary group to group2
        get_group_cmd = multihost.ad[0].run_command(
            f"powershell 'Import-Module ActiveDirectory; Get-ADGroup "
            f"\"{group2}\" -Properties PrimaryGroupToken'", raiseonerr=False
        )
        primary_grp_token = re.findall("PrimaryGroupToken.*:[^0-9]+([0-9]+)",
                                       get_group_cmd.stdout_text)[0]
        multihost.ad[0].run_command(
            f"powershell 'Import-Module ActiveDirectory; Set-ADUser -identity"
            f" \"{user2}\" -Replace @{{PrimaryGroupID="
            f"{primary_grp_token}}}'",
            raiseonerr=False
        )

        # Search for the users
        usr_cmd_1 = multihost.client[0].run_command(
            f'id {user1}@{ad_domain} | grep -i "domain users"',
            raiseonerr=False
        )
        usr_cmd_2 = multihost.client[0].run_command(
            f'id {user2}@{ad_domain} | cut -f2 -d " " | grep "{group2}"',
            raiseonerr=False
        )
        usr_cmd_3 = multihost.client[0].run_command(
            f'id {user2}@{ad_domain} | grep -i "domain users"',
            raiseonerr=False
        )

        # Make SSSD offline
        multihost.client[0].run_command(
            'which iptables || yum install -y iptables',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            f'iptables -F; iptables -A INPUT -s {multihost.ad[0].ip} -j DROP;'
            f'iptables -A OUTPUT -d {multihost.ad[0].ip} -j DROP',
            raiseonerr=False
        )
        time.sleep(30)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        usr_cmd_4 = multihost.client[0].run_command(
            f'id {user2}@{ad_domain} | grep -i "domain users"',
            raiseonerr=False
        )
        # Teardown
        multihost.client[0].run_command('iptables -F', raiseonerr=False)
        ad_op.delete_ad_user_group(user2)
        ad_op.delete_ad_user_group(group2)

        # Evaluate test results
        assert usr_cmd_1.returncode == 0, f"{user1} is not in domain users."
        assert usr_cmd_2.returncode == 0, f"{user2} is not in {group2}."
        assert usr_cmd_3.returncode == 0, f"{user2} is not in domain users."
        assert "offline" in log_str, "SSSD is not offline!"
        assert usr_cmd_4.returncode == 0, f"{user2} is not in domain users"

    @staticmethod
    @pytest.mark.tier2
    def test_0036_ad_parameters_renewal_leaks_descriptors(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: The AD keytab
         renewal task leaks a file descriptor bz1340176
        :id: 2f05d6ac-8f26-4f50-bf4f-1eaa0eeeb76f
        :setup:
          1. Configure short ad_machine_account_password_renewal_opts
          2. Clear cache and restart sssd.
        :steps:
          1. Count number of file descriptors, after 2 and 4 minutes.
        :expectedresults:
          1. The number has not grown after two minutes.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1340176
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'krb5_realm': f'{ad_realm_short}',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'ad_machine_account_password_renewal_opts': '10:30',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        pid_cmd = multihost.client[0].run_command(
            'pidof sssd_be', raiseonerr=False
        )
        time.sleep(15)
        pid = int(pid_cmd.stdout_text.strip().split()[0])
        initial_cmd = multihost.client[0].run_command(
            f'ls -ltrh /proc/{pid}/fd | grep pipe | wc -l',
            raiseonerr=False
        )
        time.sleep(120)
        stable_cmd = multihost.client[0].run_command(
            f'ls -ltrh /proc/{pid}/fd | grep pipe | wc -l',
            raiseonerr=False
        )
        time.sleep(120)
        final_cmd = multihost.client[0].run_command(
            f'ls -ltrh /proc/{pid}/fd | grep pipe | wc -l',
            raiseonerr=False
        )
        initial = int(initial_cmd.stdout_text.strip())
        stable = int(stable_cmd.stdout_text.strip())
        final = int(final_cmd.stdout_text.strip())

        # Evaluate test results
        print(f'Descriptors: initial:{initial}, stable:{stable},'
              f' final: {final}.')
        assert stable >= final, f"File descriptors are increasing!\n" \
                                f"Descriptors: initial:{initial}," \
                                f" stable:{stable}, final: {final}."

    @staticmethod
    @pytest.mark.tier1_2
    @pytest.mark.converted('test_ldap_extra_attrs.py', 'test_ldap_extra_attrs__filled')
    def test_0037_ad_parameters_extra_attrs_mail(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: SSSD fails to start
         when ldap user extra attrs contains mail bz1362023
        :id: c250bf95-6bc8-44bb-a91c-705a142d6350
        :setup:
          1. Add mail to ldap_user_extra_attrs
        :steps:
          1. Clear cache and restart sssd.
        :expectedresults:
          1. SSSD starts.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1362023
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'krb5_realm': f'{ad_realm_short}',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'ldap_user_extra_attrs': 'mail, firstname:givenname, lastname:sn',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

    @staticmethod
    @pytest.mark.tier2
    def test_0038_ad_parameters_authentication_failure_invalid_keytab(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: pam sss sshd
         authentication failure with user from AD bz1182183
        :id: 0e56397b-0be8-479c-ab89-79fef413ecd5
        :setup:
          1. Create an AD user.
          2. Create keytab with first item with
          3. Clear cache and restart sssd.
        :steps:
          1. Run klist.
          2. Run getent passwd for the user.
          3. Run check that su can switch to the ad user.
          4. Check the /var/log/secure log for expected messages.
        :expectedresults:
          1. Klist works.
          2. User is found.
          3. Su works as expected.
          4. Log contains the expected lines:
             session opened for user <aduser>@<ad_domain>
        :teardown:
          1. Restore keytab.
          2. Remove AD user.
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1182183
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_domain = multihost.ad[0].domainname
        ad_realm_short = ad_domain.upper().rsplit('.', 1)[0]
        sssd_params = {
            'ldap_id_mapping': 'False',
            'krb5_realm': ad_realm_short,
            'ad_domain': ad_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Backup keytab
        multihost.client[0].run_command(
            'cp /etc/krb5.keytab /etc/krb5.keytab.working',
            raiseonerr=False
        )

        # With ktutil add invalid principle in the keytab file.
        ktutil_cmd = f'{{ echo "addent -password -p Test1337@{ad_domain} -k' \
                     f' 3 -e aes128-cts-hmac-sha1-96"; sleep 1; echo "Secret' \
                     f'123"; echo "rkt /etc/krb5.keytab"; sleep 1; echo "wkt' \
                     f' /tmp/first_invalid.keytab"; sleep 1; echo "quit"; }}' \
                     f' | ktutil'

        multihost.client[0].run_command(ktutil_cmd, raiseonerr=False)

        # Get keytab info for debugging purposes
        multihost.client[0].run_command(
            'file /tmp/first_invalid.keytab', raiseonerr=False)

        multihost.client[0].run_command('kdestroy', raiseonerr=False)

        # Place keytab with invalid first item
        multihost.client[0].run_command(
            'cp -f /tmp/first_invalid.keytab /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab; ',
            raiseonerr=False
        )

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        klist_cmd = multihost.client[0].run_command(
            f'klist -ekt | grep "Test1337@{ad_domain}"',
            raiseonerr=False
        )

        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}',
            raiseonerr=False
        )
        su_result = client.su_success(rf'{aduser}@{ad_domain}')

        time.sleep(10)

        # Download log
        log_str = multihost.client[0].get_file_contents(
            "/var/log/secure").decode('utf-8')

        # TEARDOWN
        # Restore keytab before test result evaluation
        multihost.client[0].run_command(
            'cp -f /etc/krb5.keytab.working /etc/krb5.keytab; '
            'restorecon /etc/krb5.keytab',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            'test -e /tmp/first_invalid.keytab && '
            'rm -f /tmp/first_invalid.keytab',
            raiseonerr=False
        )

        # Evaluate test results
        assert klist_cmd.returncode == 0, "Klist failed!"
        assert usr_cmd.returncode == 0, f"{aduser} was not found!"
        assert su_result, f"{aduser} su failed!"
        assert re.search(f"authentication success.*{aduser}@"
                         f"{ad_domain}", log_str)
        assert re.search(f"session opened for user.*{aduser}@"
                         f"{ad_domain}", log_str)

    @staticmethod
    @pytest.mark.tier1_2
    def test_0039_ad_parameters_auth_krb5(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: sssd be keeps
         crashing if id provider equal to ad and auth provider equal
         to krb5 bz1396485 bz1392444
        :id: cc9d4b15-3bfb-4e2b-b4c2-bd8fe0791a17
        :setup:
          1. Set id_provider to ad and auth_provider to krb5
          2. Create a AD user and group
          3. Clear cache and restart sssd
        :steps:
          1. Run getent passwd for the user
          2. Run check that su can switch to the ad user
        :expectedresults:
          1. User is found
          2. Su works as expected
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1396485
          https://bugzilla.redhat.com/show_bug.cgi?id=1392444
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'krb5_realm': ad_realm_short,
            'ad_domain': multihost.ad[0].domainname,
            'access_provider': 'ad',
            'auth_provider': 'krb5',
            'krb5_server': multihost.ad[0].domainname,
            'ad_server': multihost.ad[0].hostname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Create AD user and group
        (aduser, _) = create_aduser_group
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{multihost.ad[0].domainname}',
            raiseonerr=False
        )
        # Run su command
        su_result = client.su_success(
            rf'{aduser}@{multihost.ad[0].domainname}',
            with_password=False)

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_result, "The su command failed!"

    @staticmethod
    @pytest.mark.tier2
    def test_0040_ad_parameters_newline_ssh_key(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: allow newlines
         in the public
        :id: 2b09e7a0-c2ea-4f75-8f88-92967087817a
        :setup:
          1. Configure logging, clear cache and restart sssd.
          2. Create an AD user.
          3. Configure ssh key for root as authorized key for AD user
        :steps:
          1. Run ssh login with key to the AD user.
          2. Add one or two new lines to beginning or end of the key in ldap.
          3. Restart sssd and run ssh login with the key.
        :expectedresults:
          1. Login succeeds.
          2. Key is added and sssd is restarted.
          3. All login attempts with extra newlines fail.
        :teardown:
          1. Remove AD users and groups.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1104145
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd to enable logging
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'id_provider': 'ad',
            'auth_provider': 'ad',
            'ad_domain': multihost.ad[0].domainname,
            'override_homedir': '/home/%u',
            'default_shell': '/bin/bash',
            'use_fully_qualified_names': 'False',
            'ad_enable_gc': 'False',
            'ldap_user_ssh_public_key': 'msDS-cloudExtensionAttribute1',
            'ldap_user_search_base': f'CN=Users,'
                                     f'{multihost.ad[0].domain_basedn_entry}',
            'ldap_id_mapping': 'False',
            'debug_level': '9',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})

        # Clear cache and restart SSSD
        client.clear_sssd_cache()
        ssh_setup(multihost, user='root')

        # Get ssh key
        pub_key = multihost.client[0].run_command(
            'cat /root/.ssh/id_rsa.pub', raiseonerr=False).stdout_text

        # Backup sshd config
        multihost.client[0].run_command(
            'cp /etc/ssh/sshd_config /etc/ssh/sshd_config.working',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            'echo "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys"'
            ' >> /etc/ssh/sshd_config; echo "AuthorizedKeysCommandUser'
            ' nobody" >> /etc/ssh/sshd_config;'
            'service sshd restart',
            raiseonerr=False
        )

        # Set ssh key in ldap, restart sssd, run ssh login with key
        set_ssh_key_ldap(multihost, aduser, pub_key, operation="add")
        client.clear_sssd_cache()
        ssh1 = client.auth_from_client_key(aduser)
        set_ssh_key_ldap(multihost, aduser, f"{pub_key}\n")
        client.clear_sssd_cache()
        ssh2 = client.auth_from_client_key(aduser)
        set_ssh_key_ldap(multihost, aduser, f"{pub_key}\n\n")
        client.clear_sssd_cache()
        ssh3 = client.auth_from_client_key(aduser)
        set_ssh_key_ldap(multihost, aduser, f"\n{pub_key}")
        client.clear_sssd_cache()
        ssh4 = client.auth_from_client_key(aduser)
        set_ssh_key_ldap(multihost, aduser, f"\n\n{pub_key}")
        client.clear_sssd_cache()
        ssh5 = client.auth_from_client_key(aduser)
        set_ssh_key_ldap(multihost, aduser, f"\n{pub_key}\n")
        client.clear_sssd_cache()
        ssh6 = client.auth_from_client_key(aduser)

        # Teardown
        # Restore sshd config
        multihost.client[0].run_command(
            'cp -f /etc/ssh/sshd_config.working /etc/ssh/sshd_config',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            'service sshd restart',
            raiseonerr=False
        )

        # Evaluate test results
        assert ssh1, "Failed: ssh key without newline."
        assert not ssh2, "Failed: ssh key test with one ending newline."
        assert not ssh3, "Failed: ssh key test two ending newlines."
        assert not ssh4, "Failed: ssh key test one beginning newline."
        assert not ssh5, "Failed: ssh key test two beginning newlines."
        assert not ssh6, "Failed: ssh key test one beginning and" \
                         " ending newline."

    @staticmethod
    @pytest.mark.tier1_2
    def test_0041_ad_parameters_sss_ssh_knownhostsproxy(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: segfault when
         HostID back end target is not configured bz1071823
        :id: b853e926-30ee-4cf5-960d-7a5bf36f25f3
        :setup:
          1. Configure sssd for ssh with known hosts proxy
          2. Clear cache and restart sssd.
          3. Create an AD user.
        :steps:
          1. Login via ssh as the AD user.
          2. Check the /var/log/messages log for segfault message.
          3. Check the sssd domain log for expected messages.
        :expectedresults:
          1. Login over ssh works.
          2. Segfault error is not present.
          3. Log contains the expected lines:
             HostID back end target is not configured...
        :teardown:
          1. Restore ssh config.
          2. Remove AD user.
        :customerscenario: False
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1071823
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        # Create AD user with posix attributes
        (aduser, _) = create_aduser_group
        # Configure sssd with know hosts proxy
        dom_section = f'domain/{client.get_domain_section_name()}'
        ad_domain = multihost.ad[0].domainname
        ad_realm = ad_domain.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        sssd_params = {
            'ldap_id_mapping': 'False',
            'krb5_realm': ad_realm_short,
            'ad_domain': ad_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'fallback_homedir': '/home/%d/%u',
        }
        client.sssd_conf(dom_section, sssd_params)

        # Backup sshd config
        multihost.client[0].run_command(
            'cp /etc/ssh/ssh_config /etc/ssh/ssh_config.working',
            raiseonerr=False
        )
        # Configure known hosts proxy
        multihost.client[0].run_command(
            r'echo -e "\tGlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts'
            r'" >> /etc/ssh/ssh_config; echo -e "\tPubkeyAuthentication yes"'
            r' >> /etc/ssh/ssh_config; echo -e "\tProxyCommand /usr/bin/'
            r'sss_ssh_knownhostsproxy -p %p %h" >> /etc/ssh/ssh_config',
            raiseonerr=False
        )
        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # SSH as aduser
        ssh_cmd = client.auth_from_client(
            f'{aduser}@{ad_domain}', 'Secret123') == 3
        # Download message log
        message_log_str = multihost.client[0].get_file_contents(
            "/var/log/messages").decode('utf-8')

        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[0].domainname.lower()}.log"). \
            decode('utf-8')

        # TEARDOWN
        # Restore ssh_config before test result evaluation
        multihost.client[0].run_command(
            'cp -f /etc/ssh/ssh_config.working /etc/ssh/ssh_config;'
            'restorecon /etc/ssh/ssh_config',
            raiseonerr=False
        )

        # Evaluate test results
        assert ssh_cmd, "Ssh failed!"
        assert not re.search(r"sssd_be\[[0-9]*\]: segfault", message_log_str)
        assert re.search(r"(HostID back end target is not configured|Target "
                         r"\[hostid\] is not supported by module \[ad\])",
                         log_str)

    @staticmethod
    @pytest.mark.tier1_2
    def test_0042_ad_parameters_nonroot_user_sssd(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: SSSD runs and works
         correctly under non-root user
        :id: ef36052d-d526-4a25-aa60-d607a78164ca
        :setup:
         1. Configure sssd to run under sssd user, restart sssd.
         2. Create AD user and group.
        :steps:
          1. Run getent passwd for the user
          2. Run getent group for the group
          3. Check that sssd runs under specified user.
        :expectedresults:
          1. User is found
          2. Group is found
          3. Sssd runs under specified user (sssd).
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        ad_realm = multihost.ad[0].domainname.upper()
        ad_realm_short = ad_realm.rsplit('.', 1)[0]
        # Create AD user and group
        (aduser, adgroup) = create_aduser_group
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
            'full_name_format': '%2$s\\%1$s',
        }
        # Configure sssd to run onder sssd user
        sssd_sect = {
            'user': 'sssd',
        }
        client.sssd_conf('sssd', sssd_sect)
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {ad_realm_short}\\\\{aduser}',
            raiseonerr=False
        )
        # Search for the group
        grp_cmd = multihost.client[0].run_command(
            f'getent group {ad_realm_short}\\\\{adgroup}',
            raiseonerr=False
        )
        # check the sssd process user
        ps_cmd = multihost.client[0].run_command(
            r"ps auxZ | grep sssd | awk '{print $2}' | grep sssd",
            raiseonerr=False
        )
        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert grp_cmd.returncode == 0, f"Group {adgroup} was not found."
        assert ps_cmd.returncode == 0, "Sssd is not running under user!"

    @staticmethod
    @pytest.mark.tier2
    def test_0043_sssd_not_using_given_krb_port(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: SSSD does not use kerberos port that is set.
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1859315
          https://bugzilla.redhat.com/show_bug.cgi?id=2041560
        :id: 558f692b-01c5-46f4-ad39-6b190dd7c017
        :setup:
          1. Configure alternate kerberos port on AD
        :steps:
          1. Start SSSD with alternate port in config
          2. Call 'kinit username@domain'
          3. Call 'ssh -l username@domain localhost' and check sssd logs
        :expectedresults:
          1. SSSD should start
          2. Should succeed
          3. Logs contain info about right port being used
             Logs do not contain wrong (default) port being used
        """

        adjoin(membersw='adcli')
        ad_realm = multihost.ad[0].domainname.upper()

        # Create AD user and group
        (aduser, _) = create_aduser_group

        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '0x4000',
            'cache_credentials': 'True',
            'ad_server': multihost.ad[0].hostname,
            'krb5_store_password_if_offline': 'True',
            'krb5_server': f'{multihost.ad[0].hostname}:6666',
            'id_provider': 'ldap',
            'auth_provider': 'krb5',
            'access_provider': 'ad',
            'krb5_realm': ad_realm,
            'ldap_sasl_mech': 'GSSAPI',
            'fallback_homedir': '/home/%u',
        }
        client.sssd_conf(dom_section, sssd_params)

        multihost.client[0].run_command(
            "semanage port -a -t kerberos_port_t -p tcp 6666;"
            " semanage port -a -t kerberos_port_t -p udp 6666",
            raiseonerr=False
        )

        # Forward ports on AD machine so 6666 works
        multihost.ad[0].run_command(
            "netsh interface portproxy add v4tov4 listenaddress=0.0.0.0"
            " listenport=6666 connectaddress=127.0.0.1 connectport=88; "
            " netsh interface portproxy show all",
            raiseonerr=False
        )

        # Allow 6666 on firewall
        fw_cmd = "powershell.exe -inputformat none -noprofile \"New-NetFire" \
                 "wallRule -DisplayName 'alt-krb-Inbound' -Profile @(" \
                 "'Domain', 'Private', 'Public') -Direction Inbound -Action " \
                 "Allow -Protocol TCP -LocalPort 6666\""
        multihost.ad[0].run_command(fw_cmd, raiseonerr=False)

        # Workaround for DNS
        multihost.client[0].run_command(
            f'grep "{multihost.ad[0].hostname}" /etc/hosts || echo -n "'
            f'\n{multihost.ad[0].ip} {multihost.ad[0].hostname}\n'
            f'">> /etc/hosts',
            raiseonerr=False
        )

        # Clear cache and restart SSSD
        client.clear_sssd_cache()

        # Run kinit for the user
        kinit_cmd = multihost.client[0].run_command(
            f'kinit {aduser}@{ad_realm}', stdin_text='Secret123',
            raiseonerr=False)

        # Run ssh
        multihost.client[0].run_command(
            f'ssh -o StrictHostKeychecking=no -o NumberOfPasswordPrompts=1 '
            f'-o UserKnownHostsFile=/dev/null -l {aduser}@{ad_realm} '
            f'localhost whoami',
            stdin_text='Secret123',
            raiseonerr=False)

        # Give it some time so the log can be written
        time.sleep(10)

        # Download all logs
        log_str = multihost.client[0].run_command(
            "cat /var/log/sssd/*.log").stdout_text

        # Remove forward ports on AD machine
        multihost.ad[0].run_command(
            "netsh interface portproxy reset",
            raiseonerr=False
        )

        # Disallow 6666 on firewall on AD
        fw_cmd = "powershell.exe -inputformat none -noprofile " \
                 "\"Remove-NetFirewallRule -Name alt-krb-Inbound\""
        multihost.ad[0].run_command(fw_cmd, raiseonerr=False)

        # Evaluate test results
        assert f"Option krb5_server has value " \
               f"{multihost.ad[0].sys_hostname}:6666" in log_str
        assert f"Initiating TCP connection to stream " \
               f"{multihost.ad[0].ip}:6666" in log_str or \
               f"Sending initial UDP request to dgram " \
               f"{multihost.ad[0].ip}:6666" in log_str
        assert f"Sending initial UDP request to dgram " \
               f"{multihost.ad[0].ip}:88" not in log_str
        assert f"Initiating TCP connection to stream {multihost.ad[0].ip}:88" \
               not in log_str
        assert kinit_cmd.returncode == 0, "kinit failed."

    @staticmethod
    @pytest.mark.tier2
    def test_0044_ad_parameters_homedir_override_lowercase(
            multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: override homedir
          to lowercase
        :id: c8f6f2f9-f8d1-441c-9fba-ec9da9de3df4
        :setup:
         1. Configure homedir override to lowercase in domain section,
            clear cache and restart sssd.
         2. Create an AD user.
        :steps:
          1. Run getent passwd for the user and verify the home location.
        :expectedresults:
          1. User is found and homedir is overridden.
        :customerscenario: False
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1964121
        """
        ad_domain = multihost.ad[0].domainname
        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, _) = create_aduser_group

        # Modify user homedir to uppercase
        multihost.ad[0].run_command(
            f"powershell 'Import-Module ActiveDirectory; Set-ADUser -identity"
            f" \"{aduser}\" -Replace @{{unixHomeDirectory="
            f"\"/home/{aduser.upper()}\"}}'",
            raiseonerr=False
        )

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'override_homedir': '%h'
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}',
            raiseonerr=False
        )

        # Evaluate test results
        assert f'/home/{aduser.lower()}' in usr_cmd.stdout_text

    @staticmethod
    @pytest.mark.tier2
    def test_0045_ad_parameters_upn_mismatch_check(
            multihost, adjoin, create_aduser_group):
        """ UPN check cannot be disabled explicitly but requires krb5_validate

        :title: IDM-SSSD-TC: ad_provider: ad_parameters: UPN mismatch
        :id: ea445810-8bec-4a4c-924b-ec527e60b14b
        :setup:
         1. Create an AD user, set its upn to other domain.
        :steps:
          1. Set `ldap_user_principal = mail`, pac_check = no_check.
             Clear cache and restart sssd.
          2. Run getent passwd for the user.
          4. Run su for the user.
          5. Check that pac.log contains info about mismatch that is ignored.
        :expectedresults:
          1. Sssd starts.
          2. User is found.
          4. Su for the uses succeeds.
          5. Log does contain the expected message.
        :customerscenario: True
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=2148737
          https://bugzilla.redhat.com/show_bug.cgi?id=2144491
          https://bugzilla.redhat.com/show_bug.cgi?id=2148989
          https://bugzilla.redhat.com/show_bug.cgi?id=2148988
        """
        # Note: The IPA server was guessing the UPN based on samAccountName
        # in the past which was failing the check in sssd if the user
        # had a different UPN on the AD side with the message:
        # UPN of user entry and PAC do not match.
        # To validate the fix we are skipping the whole IPA part and
        # forcing sssd to use mismatched parameter for UPN instead.

        ad_domain = multihost.ad[0].domainname
        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, _) = create_aduser_group

        # Modify UPN for aduser
        multihost.ad[0].run_command(
            f"powershell -inputformat none -noprofile 'Import-Module "
            f"ActiveDirectory; Set-ADUser -Identity {aduser} "
            f"-UserPrincipalName \"{aduser}@otherdomain.com\"'",
            raiseonerr=False
        )

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'ldap_user_principal': 'mail',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('pac', {'pac_check': 'no_check'})
        client.clear_sssd_cache()

        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}', raiseonerr=False
        )

        su_result = client.su_success(f'{aduser}@{ad_domain}')

        # Pull sssd_pac.log
        time.sleep(5)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            "/var/log/sssd/sssd_pac.log"). \
            decode('utf-8')

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert f"UPN of user entry [{aduser}@{ad_domain.upper()}] and PAC " \
               f"[{aduser}@otherdomain.com] do not match, ignored." in log_str
        assert su_result, f"su to user {aduser} with mismatched UPN failed!"

    @staticmethod
    @pytest.mark.tier2
    def test_0046_ad_parameters_upn_empty_skip_check(
            multihost, adjoin, create_aduser_group):
        """ UPN check in pac is skipped when upn is empty be default

        :title: IDM-SSSD-TC: ad_provider: ad_parameters: UPN empty
        :id: 8792541c-7bf9-433e-a81d-088b0e118236
        :setup:
         1. Create an AD user, set its upn to other domain.
        :steps:
          1. Set `ldap_user_principal = non-existent-attr`.
             Clear cache and restart sssd.
          2. Run getent passwd for the user.
          4. Run su for the user.
          5. Check that pac.log contains info about empty UPN that is ignored.
        :expectedresults:
          1. Sssd starts.
          2. User is found.
          4. su for the uses succeeds.
          5. Log does contain the expected message.
        :customerscenario: True
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=2148737
          https://bugzilla.redhat.com/show_bug.cgi?id=2144491
          https://bugzilla.redhat.com/show_bug.cgi?id=2148989
          https://bugzilla.redhat.com/show_bug.cgi?id=2148988

        """
        # Note: The IPA server was guessing the UPN based on samAccountName
        # in the past which was failing the check in sssd if the user
        # had a different UPN on the AD side with the message:
        # UPN of user entry and PAC do not match.
        # To validate the fix we are skipping the whole IPA part and
        # forcing sssd to use empty parameter for UPN instead.
        # SSSD should recognize missing/empty upn and skip the check
        # by default now.

        ad_domain = multihost.ad[0].domainname
        adjoin(membersw='adcli')
        # Create AD user and group
        (aduser, _) = create_aduser_group

        # Modify UPN for aduser
        multihost.ad[0].run_command(
            f"powershell -inputformat none -noprofile 'Import-Module "
            f"ActiveDirectory; Set-ADUser -Identity {aduser} "
            f"-UserPrincipalName \"{aduser}@otherdomain.com\"'",
            raiseonerr=False
        )

        # Display aduser
        multihost.ad[0].run_command(
            f"powershell -inputformat none -noprofile 'Import-Module "
            f"ActiveDirectory; Get-ADUser -Identity {aduser} "
            f"-Properties *'",
            raiseonerr=False
        )

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'ldap_user_principal': 'non-existent-attr',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}@{ad_domain}', raiseonerr=False
        )

        su_result = client.su_success(f'{aduser}@{ad_domain}')

        # Pull sssd_pac.log
        time.sleep(5)
        # Download the sssd domain log
        log_str = multihost.client[0].get_file_contents(
            "/var/log/sssd/sssd_pac.log"). \
            decode('utf-8')

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found!"
        assert su_result, f"su to user {aduser} with empty UPN failed!"
        assert "UPN is missing but PAC UPN check required, PAC validation" \
               " failed. However, 'check_upn_allow_missing' is set and" \
               " the error is ignored." in log_str

    @staticmethod
    @pytest.mark.tier1_2
    def test_0047_ad_parameters_filter_group(
            multihost, adjoin, create_plain_aduser_group):
        """
        :title: Filtered group GID in not present in id output
        :id: 57a34316-e4b7-4abf-903c-5948cb93dd5a
        :setup:
         1. Configure sssd with id mapping True
         2. Create AD user and group.
         3. Get adgroup (mapped) gid
        :steps:
          1. Configure sssd to filter adgroup and restart sssd
          2. Run id command for aduser.
        :expectedresults:
          1. SSSD starts properly
          2. The gid of the ad group is not present in the id output.
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1913839
        """
        adjoin(membersw='adcli')
        ad_realm = multihost.ad[0].domainname.upper()
        # Create AD user and group
        (aduser, adgroup) = create_plain_aduser_group
        # Configure sssd with idmapping true
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'ad_domain': multihost.ad[0].domainname,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'krb5_store_password_if_offline': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Get adgroup info including gid
        try:
            getent_groupinfo = client.get_getent_group(f"{adgroup}@{ad_realm}")
        except IndexError:
            getent_groupinfo = {}

        # Configure filter for adgroup and restart sssd
        client.sssd_conf(
            dom_section, {'filter_groups': f'{adgroup}@{ad_realm}'}
        )
        client.clear_sssd_cache()

        id_cmd = multihost.client[0].run_command(
            f'id {aduser}@{ad_realm}',
            raiseonerr=False
        )
        # Evaluate test results
        assert getent_groupinfo, f"Could not find group {adgroup}!"
        assert id_cmd.returncode == 0, f"User {aduser} was not found!"
        assert getent_groupinfo['gid'] not in id_cmd.stdout_text,\
            f"{adgroup} gid was not filtered!"
