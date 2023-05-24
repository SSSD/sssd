""" Miscellaneous IPA Bug Automations

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import datetime
import re
import time
import subprocess
import pexpect
import pexpect.pxssh
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException


@pytest.mark.usefixtures('default_ipa_users', 'reset_password')
@pytest.mark.tier1
class Testipabz(object):
    """ IPA BZ Automations """

    @staticmethod
    def test_blank_kinit(multihost):
        """
        :title: verify sssd fails to start with
         invalid default keytab file
        :id: 525cbe28-f835-4d2e-9583-d3f614b8486e
        :requirement: IDM-SSSD-REQ : KRB5 Provider
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1748292
        :description: systemctl status sssd says No such file or
         directory about "default" when keytab exists but is empty file
        """
        # stop sssd
        multihost.client[0].service_sssd('stop')
        # backup /etc/krb5.keytab
        backup = 'mv /etc/krb5.keytab /etc/krb5.keytab.orig'
        multihost.client[0].run_command(backup)
        # create an empty keytab
        empty_keytab = 'echo -n > /etc/krb5.keytab'
        multihost.client[0].run_command(empty_keytab)
        # start sssd
        try:
            multihost.client[0].service_sssd('start')
        except SSSDException:
            status = 'PASS'
            logs = 'journalctl -x -n 50 --no-pager'
            cmd = multihost.client[0].run_command(logs, raiseonerr=False)
            search_txt = 'krb5_kt_start_seq_get failed: '\
                         'Unsupported key table format version number'
            check = re.compile(r'%s' % search_txt)
            if not check.search(cmd.stdout_text):
                status = 'FAIL'
        else:
            status = 'FAIL'
            pytest.fail("sssd should fail to restart")
        # restore /etc/krb5.keytab
        restore = 'mv /etc/krb5.keytab.orig /etc/krb5.keytab'
        multihost.client[0].run_command(restore)
        assert status == 'PASS'

    @staticmethod
    def test_2f_auth_prompt(multihost, backupsssdconf):
        """
        :title: 2f authentication prompt
        :id: cc596a8a-27d6-48f2-8d6c-c821ebfffd63
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1749279
        :steps:
            1. Set authentication of a ipa-user to the OTP
            2. Add otptoken for that user
            3. Add a section 'prompting/2fa' in sssd.conf and
               add prompt related options
            4. Confirm that when intended user tries to log in via ssh, the end
               part of login prompt is as per option set in step3.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
        :customerscenario: True
        :description: 2F auth prompt should be as per the
         option set in 'prompting/2fa' section of sssd.conf
        """
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        client_ip = multihost.client[0].ip
        k_admin = 'kinit admin'
        multihost.client[0].run_command(k_admin,
                                        stdin_text='Secret123',
                                        raiseonerr=False)
        usr = 'fubar'
        cmd = f"echo 'Secret123' | ipa user-add --first fu --last" \
              f" bar --password {usr}"
        multihost.client[0].run_command(cmd, raiseonerr=False)
        try:
            multihost.client[0].run_command(
                f'ipa user-mod --user-auth-type=otp {usr}')
        except subprocess.CalledProcessError:
            pytest.fail(f"Failed to modify user-auth-type of {usr}")
        try:
            multihost.client[0].run_command(f'ipa otptoken-add --owner={usr}')
        except subprocess.CalledProcessError:
            pytest.fail(f"Failed to add otptoken of user {usr}")
        try:
            client.sssd_conf('prompting/password', None, 'delete')
        except SSSDException as err:
            if 'section do not exist' in str(err):
                print(f'{err}.  nothing to delete')
            else:
                print(f'unexpected exception: {err}')
                raise SSSDException(str(err))
        sec = 'prompting/2fa'
        params = {'single_prompt': 'True',
                  'first_prompt': 'Password + OTP:'}
        client.sssd_conf(sec, params)
        client.clear_sssd_cache()
        ssh_cmd = f'ssh -o StrictHostKeyChecking=no -l {usr}@{domain_name}' \
                  f' {client_ip}'
        child = pexpect.spawn(ssh_cmd)
        index = child.expect(['.*assword:', '.*Password.*OTP:',
                              '.*First.*Factor:'])
        child.sendcontrol('c')
        multihost.client[0].run_command(f'ipa user-del {usr}', raiseonerr=False)
        assert index == 1, \
            "Authentication prompt does contain Password + OTP combination"

    @staticmethod
    def test_sssdconfig_remove_domains(multihost):
        """
        :title: Verify SSSDConfig.save_domain API removes
         all autofs entries from sssd.conf
        :id: 3efaf0af-58a7-4631-8555-da8a7bbcf351
        :description:
         SSSDConfig.save_domain(domain) does not always
         remove all entries removed from domain
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1796989
        """
        setup_automount = "ipa-client-automount --location default -U " \
                          "--server %s" % multihost.master[0].sys_hostname
        uninstall_automount = "ipa-client-automount --uninstall -U " \
                              "--server %s" % multihost.master[0].sys_hostname
        for _ in range(5):
            cmd1 = multihost.client[0].run_command(setup_automount,
                                                   raiseonerr=False)
            time.sleep(5)
            cmd2 = multihost.client[0].run_command(uninstall_automount,
                                                   raiseonerr=False)
            assert cmd1.returncode == 0
            assert cmd2.returncode == 0

    @staticmethod
    def test_filter_groups(multihost, default_ipa_groups,
                           add_group_member, backupsssdconf):
        """
        :title:  filter_groups option partially filters the group from id
         output of the user because gidNumber still appears in id output
        :id: 8babb6ee-7141-4723-a79d-c5cf7879a9b4
        :customerscenario: True
        :description:
         filter_groups option partially filters the group from 'id' output
         of the user because gidNumber still appears in 'id' output
        :steps:
          1. Create IPA users, groups and add users in groups.
          2. Add filter_groups in sssd.conf.
          3. Check filter_groups option filters the group from 'id' output.
        :expectedresults:
          1. Successfully add users, groups and users added in groups.
          2. Successfully added filter_groups in sssd.conf.
          3. Successfully filter out the groups.
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1876658
        """
        gid_start = default_ipa_groups
        sssd_client = sssdTools(multihost.client[0])
        domain_name = '%s/%s' % ('domain',
                                 sssd_client.get_domain_section_name())
        enable_filtergroups1 = {'filter_groups': 'ipa-group1, ipa-group2'}
        sssd_client.sssd_conf(domain_name, enable_filtergroups1)
        sssd_client.clear_sssd_cache()
        lk_cmd1 = 'id foobar1'
        cmd1 = multihost.client[0].run_command(lk_cmd1, raiseonerr=False)
        assert cmd1.returncode == 0
        assert all(x not in cmd1.stdout_text for x in ["ipa-group1",
                                                       "ipa-group2"]), \
            "The unexpected group name found in the id output!"
        assert all(x not in cmd1.stdout_text for x in [str(gid_start + 1),
                                                       str(gid_start + 2)]), \
            "The unexpected gid found in the id output!"
        enable_filtergroups2 = {'filter_groups': 'ipa-group3, ipa-group4, '
                                                 'ipa-group5'}
        sssd_client.sssd_conf(domain_name, enable_filtergroups2)
        sssd_client.clear_sssd_cache()
        lk_cmd2 = 'id foobar2'
        cmd2 = multihost.client[0].run_command(lk_cmd2, raiseonerr=False)
        assert cmd2.returncode == 0
        assert all(x not in cmd2.stdout_text for x in ["ipa-group3",
                                                       "ipa-group4",
                                                       "ipa-group5"]), \
            "The unexpected group name found in the id output!"
        assert all(x not in cmd2.stdout_text for x in [str(gid_start + 3),
                                                       str(gid_start + 4),
                                                       str(gid_start + 5)]), \
            "The unexpected gid found in the id output!"

    @staticmethod
    def test_asymmetric_auth_for_nsupdate(multihost, create_reverse_zone):
        """
        :title: Support asymmetric auth for nsupdate
        :id: 2bc5c4c7-7296-434b-8f38-2b7297b32b9b
        :requirement: dyndns
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1884301
        """
        client = sssdTools(multihost.client[0])
        client_hostname = multihost.client[0].sys_hostname
        server_hostname = multihost.master[0].sys_hostname
        client_l = client_hostname.split('.', 1)
        client_hostname_short = client_l[0]
        client_ip = multihost.client[0].ip
        subnet = client_ip.split('.', 3)
        del subnet[-1]
        subnet.reverse()

        domain_name = client.get_domain_section_name()
        client.sssd_conf(
            'domain/%s' % domain_name,
            {'dyndns_force_tcp': 'true',
             'dyndns_update': 'true',
             'dyndns_update_ptr': 'true',
             'dyndns_refresh_interval': '5',
             'dyndns_auth_ptr': 'None',
             'dyndns_server': '%s' % server_hostname})
        cmd_del_record = 'ipa dnsrecord-del %s %s --del-all' % \
                         (domain_name, client_hostname_short)
        multihost.master[0].run_command(cmd_del_record, raiseonerr=False)

        client.remove_sss_cache('/var/lib/sss/db')
        multihost.client[0].service_sssd('restart')
        time.sleep(10)

        cmd_check_arecord = 'nslookup %s' % client_hostname
        cmd_check_ptrrecord = 'nslookup %s' % client_ip

        rc_arecord = multihost.client[0].run_command(cmd_check_arecord,
                                                     raiseonerr=False)
        rc_ptrrecord = multihost.client[0].run_command(cmd_check_ptrrecord,
                                                       raiseonerr=False)
        assert rc_arecord.returncode == 0
        assert client_ip in rc_arecord.stdout_text
        assert rc_ptrrecord.returncode == 0
        assert client_hostname in rc_ptrrecord.stdout_text

    @staticmethod
    def test_authentication_indicators(multihost, backupsssdconf):
        """
        :title: Add support to verify authentication
         indicators in pam_sss_gss
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1926622
        :id: 4891ed62-7fc8-11eb-98be-002b677efe14
        :steps:
            1. Add pam_sss_gss configuration to /etc/sssd/sssd.conf
            2. Add pam_sss_gss.so to /etc/pam.d/sudo
            3. Restart SSSD
            4. Enable SSSD debug logs
            5. Switch to 'admin' user
            6. obtain Kerberos ticket and check that it
               was obtained using SPAKE pre-authentication.
            7. Create sudo configuration that allows an admin to
               run SUDO rules
            8. Try 'sudo -l' as admin
            9. As root, check content of sssd_pam.log
           10. Check if acquired service ticket has req. indicators: 0
           11. Add pam_sss_gss configuration to /etc/sssd/sssd.conf
           12. Check if acquired service ticket has req.
               indicators: 2
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
            8. Should succeed
            9. Should succeed
           10. Should succeed
           11. Should succeed
           12. Should succeed
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'pam_gssapi_services': 'sudo, sudo-i',
                         'pam_gssapi_indicators_map': 'hardened, '
                                                      'sudo:pkinit, '
                                                      'sudo-i:otp'}
        client.sssd_conf('pam', domain_params)
        multihost.client[0].run_command(
            'cp -vf /etc/pam.d/sudo /etc/pam.d/sudo_indicators')
        multihost.client[0].run_command("sed -i "
                                        "'2s/^/auth sufficient "
                                        "pam_sss_gss.so debug\\n/' "
                                        "/etc/pam.d/sudo")
        multihost.client[0].run_command(
            'cp -vf /etc/pam.d/sudo-i /etc/pam.d/sudo-i_indicators')
        multihost.client[0].run_command("sed -i "
                                        "'2s/^/auth sufficient "
                                        "pam_sss_gss.so debug\\n/' "
                                        "/etc/pam.d/sudo-i")
        client.clear_sssd_cache()
        multihost.client[0].run_command("sssctl debug-level 9")
        user = 'admin'
        test_password = "Secret123"
        multihost.client[0].run_command(
            f'su -l {user} -c "kinit"', stdin_text=test_password,
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "klist"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudocmd-add ALL2"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add testrule2"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-allow-command testrule2 '
            f'--sudocmds \'ALL2\'"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-mod testrule2 --hostcat=all"',
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-user testrule2 --users admin"',
            raiseonerr=False)
        ssh_error = ""
        ssh = pexpect.pxssh.pxssh(
            options={"StrictHostKeyChecking": "no",
                     "UserKnownHostsFile": "/dev/null"}, timeout=600)
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].ip, user, test_password)
            ssh.sendline('sudo -l')
            ssh.prompt(timeout=600)
            ssh.logout()
        except pexpect.pxssh.ExceptionPxssh:
            ssh_error += "Could not login via ssh first time."

        search = multihost.client[0].run_command(
            'fgrep gssapi_ /var/log/sssd/sssd_pam.log | tail -10')

        domain_params = {'pam_gssapi_services': 'sudo, sudo-i',
                         'pam_gssapi_indicators_map': 'sudo-i:hardened'}
        client.sssd_conf('pam', domain_params)
        client.clear_sssd_cache()
        multihost.client[0].run_command("sssctl debug-level 9")
        multihost.client[0].run_command(
            f'su -l {user} -c "kinit admin"', stdin_text=test_password,
            raiseonerr=False)

        ssh = pexpect.pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                                           "UserKnownHostsFile": "/dev/null"},
                                  timeout=600)
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].ip, user, test_password)
            ssh.sendline('sudo -l')
            ssh.prompt(timeout=600)
            ssh.logout()
        except pexpect.pxssh.ExceptionPxssh:
            ssh_error += "\nCould not login via ssh second time."

        multihost.client[0].run_command(
            f'su -l {user} -c "klist"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-del testrule2"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudocmd-del ALL2"', raiseonerr=False)
        multihost.client[0].run_command(
            'cp -vf /etc/pam.d/sudo_indicators /etc/pam.d/sudo')
        multihost.client[0].run_command(
            'cp -vf /etc/pam.d/sudo-i_indicators /etc/pam.d/sudo-i')
        search2 = multihost.client[0].run_command(
            'fgrep gssapi_ /var/log/sssd/sssd_pam.log | tail -10')

        assert not ssh_error, ssh_error
        assert 'indicators: 0' in search.stdout_text
        assert 'indicators: 2' in search2.stdout_text

    @staticmethod
    def test_pass_krb5cname_to_pam(multihost,
                                   backupsssdconf,
                                   backup_config_pam_gssapi_services):
        """
        :title: pass KRB5CCNAME to pam_authenticate environment
         if available
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1917379
        :id: e3a6accc-781d-11ec-a83c-845cf3eff344
        :steps:
            1. Take backup of files
            2. Configure domain_params
            3. Configure /etc/pam.d/sudo
            4. Configur /etc/pam.d/sudo-i
            5. Create IPA sudo rule of /usr/sbin/sssctl
               for user admin
            6. Check user admin can use sudo command
            7. Restore of files
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Should succeed
            7. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        tools.clear_sssd_cache()
        domain_name = tools.get_domain_section_name()
        user = "admin"
        test_password = "Secret123"
        sys_hostname = multihost.client[0].sys_hostname
        multihost.client[0].run_command(
            f'su -l {user} -c "kinit"', stdin_text=test_password,
            raiseonerr=False)

        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudocmd-add /usr/sbin/sssctl"',
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add idm_user_sssctl"',
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-allow-command idm_user_sssctl'
            f' --sudocmds \'/usr/sbin/sssctl\'"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-host idm_user_sssctl --hosts'
            f' {sys_hostname}"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-user idm_user_sssctl --users'
            f' admin"', raiseonerr=False)
        tools.clear_sssd_cache()
        multihost.client[0].run_command(
            f'su -l {user} -c "kinit"', stdin_text=test_password,
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "sudo -S -l"', stdin_text=test_password,
            raiseonerr=False)
        file_name = 'domain_list_' + str(time.time())
        ssh_error = ""
        ssh = pexpect.pxssh.pxssh(
            options={"StrictHostKeyChecking": "no",
                     "UserKnownHostsFile": "/dev/null"}, timeout=600)
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].ip, user, test_password)
            ssh.sendline(f'sudo -S /usr/sbin/sssctl domain-list > '
                         f'/tmp/{file_name}')
            ssh.expect(".*:", timeout=10)
            ssh.sendline(test_password)
            ssh.prompt(timeout=60)
            ssh.logout()
        except pexpect.pxssh.ExceptionPxssh:
            ssh_error += "Could not login via ssh."
        result = multihost.client[0].run_command(f"cat /tmp/{file_name}"
                                                 ).stdout_text
        assert domain_name in result

    @staticmethod
    def test_ssh_hash_knownhosts(multihost, reset_password, backupsssdconf):
        """
        :title: Current value of ssh_hash_known_hosts causes error in
         the default configuration in FIPS mode.
        :description: In SSSD the default value for ssh_hash_known_hosts
         is set to true, It should be changed to false for consistency with
         the OpenSSH setting that does not hashes host names by default
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2014249
        :id: 1cee74c8-a0ad-44d4-8287-a32e3266de22
        :customerscenario: false
        :steps:
            1. Stop SSSD
            2. Configure SSSD with ssh having default value of
               ssh_hash_known_hosts / ssh_hash_known_hosts = True /
               ssh_hash_known_hosts = False
            3. Remove /var/lib/sss/pubconf/known_hosts file
            4. Start SSSD
            5. Perform SSH using IPA user
            6. Check if hostnames are hashed/unhashed in
               /var/lib/sss/pubconf/known_hosts
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
            6. Hostnames should be hashed/unhashed as per the value of
               ssh_hash_known_hosts
        """
        tools = sssdTools(multihost.client[0])
        server_host = multihost.master[0].sys_hostname

        def check_hostname_hash(hash_value=None):
            """no hash_value or hash_value = True or hash_value = False"""
            multihost.client[0].service_sssd("stop")
            if hash_value is None:
                tools.sssd_conf(
                    "ssh", {"ssh_hash_known_hosts": ""}, action="delete")
            else:
                tools.sssd_conf(
                    "ssh", {"ssh_hash_known_hosts": hash_value},
                    action="update")
            multihost.client[0].run_command(r"rm -rf /var/lib/sss/pubconf"
                                            r"/known_hosts")
            multihost.client[0].service_sssd("start")
            cmd = f"ssh -l -q foobar0@{server_host} echo 'login successful'"
            multihost.client[0].run_command(cmd, stdin_text="Secret123",
                                            raiseonerr=False)
            known_hosts = multihost.client[0].run_command(r"cat /var/lib/sss"
                                                          r"/pubconf"
                                                          r"/known_hosts")

            print(f'cat /var/lib/sss/pubconf/known_hosts\n'
                  f'{known_hosts.stdout_text}')
            if re.search(fr'^{server_host}', known_hosts.stdout_text):
                return 0   # hostname not hashed
            return 1   # hostname hashed
        # ssh_hash_known_hosts is not used, default value is False
        hashing_not_defined = check_hostname_hash() == 0
        # ssh_hash_known_hosts = True
        hashing_true = check_hostname_hash("True") == 1
        # ssh_hash_known_hosts = False
        hashing_false = check_hostname_hash("False") == 0
        # Cleanup
        multihost.client[0].run_command(r"rm -rf /var/lib/sss/pubconf"
                                        r"/known_hosts")
        # Test result evaluation
        assert hashing_not_defined, "Hostnames hashed - Bugzilla " \
                                    "2014249/2015070"
        assert hashing_true, "Hostnames not hashed"
        assert hashing_false, "Hostnames hashed"

    @staticmethod
    def test_ssh_expiration_warning(multihost, reset_password, hbac_sshd_rule,
                                    setup_ipa_client, backupsssdconf):
        """test_ssh_expiration_warning

        :title: IDM-SSSD-TC: ipa_provider: Show password expiration warning
          when IdM users login with SSH keys
        :description: When an IdM user logs in with SSH key based
          authentication, they should see password expiration warnings.
          Customer would like to see password expiration warnings even when
          logging in with SSH keys so users can proactively change their
          passwords before they expire.
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1765354
        :id: c1c20cff-edb4-41cd-a879-0eeb98a9c53a
        :customerscenario: true
        :setup:
          1. Generate ssh keys for an user.
          2. Upload public key to ipa for the user.
          3. Change the password expiration to tomorrow for the user.
          4. Configure hbac rule for the user enabling sshd service.
          5. Configure ipa_access_order and pwd_expiration_warning
          6. Set user password to expire in one day.
        :steps:
          1. Login using ssh key as the user to the client machine.
          2. Check the output of the ssh.
        :expectedresults:
          1. User is logged in.
          2. Password expiration message is shown.
        """
        # pylint: disable=W0613

        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        client.sssd_conf(
            'domain/%s' % domain_name,
            {'ipa_access_order': 'pwd_expire_policy_warn',
             'pwd_expiration_warning': '3'}
        )

        client.clear_sssd_cache()

        # Make sure that user home is not present with unwanted files and
        # possibly wrong ownership
        multihost.client[0].run_command(
            'rm -rf /home/foobar1', raiseonerr=False)

        multihost.client[0].run_command(
            'getent passwd foobar1@testrealm.test', raiseonerr=False)

        # Generate keypair
        multihost.client[0].run_command(
            r"""su -l foobar1@testrealm.test -c 'ssh-keygen -b 2048 -t rsa"""
            r""" -q -f /home/foobar1/.ssh/id_rsa -N ""' """, raiseonerr=False)

        # Get the pubkey
        pubkey = multihost.client[0].get_file_contents(
            "/home/foobar1/.ssh/id_rsa.pub").decode('utf-8').strip()

        multihost.master[0].run_command('kinit admin', stdin_text='Secret123',
                                        raiseonerr=False)
        # Upload the pubkey to IPA
        multihost.master[0].run_command(
            f'ipa user-mod foobar1 --sshpubkey="{pubkey}"', raiseonerr=False)

        # Make password expiring tomorrow
        tomorrow = datetime.date.today() + datetime.timedelta(days=1)
        date_for_ipa = tomorrow.strftime("%Y%m%d%H%M%SZ")
        multihost.master[0].run_command(
            f'ipa user-mod foobar1 --setattr=krbPasswordExpiration='
            f'"{date_for_ipa}"', raiseonerr=False)

        client.clear_sssd_cache()

        # Run ssh
        # This one does not work RHEL 8
        # cmd = 'su - foobar1@testrealm.test -c " ssh -v ' \
        #       '-o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null ' \
        #       '-o GSSAPIAuthentication=no -o PasswordAuthentication=no ' \
        #       '-l foobar1@testrealm.test localhost \'whoami\' " 2>&1'

        cmd = 'sudo -u foobar1@testrealm.test ssh -v ' \
              '-o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null ' \
              '-o GSSAPIAuthentication=no -o PasswordAuthentication=no ' \
              '-l foobar1@testrealm.test localhost <<< whoami 2>&1'

        ssh_cmd = multihost.client[0].run_command(cmd, raiseonerr=False)

        # Teardown
        multihost.master[0].run_command(
            'ipa user-mod foobar1 --setattr=krbPasswordExpiration='
            '"20370101000000Z"', raiseonerr=False)

        multihost.master[0].run_command(
            'ipa user-mod foobar1 --sshpubkey=""', raiseonerr=False)

        multihost.client[0].run_command(
            'rm -rf /home/foobar1', raiseonerr=False)

        # Test result evaluation
        assert ssh_cmd.returncode == 0, "Ssh login failed."
        assert "Your password will expire in " in ssh_cmd.stdout_text,\
            "The password expiration notice was not shown."

    @staticmethod
    def test_ssh_expired_warning(multihost, reset_password, hbac_sshd_rule,
                                 setup_ipa_client, backupsssdconf):
        """test_ssh_expired_warning

        :title: IDM-SSSD-TC: ipa_provider: Show password expired warning
          when IdM users login with SSH keys
        :description: When an IdM user logs in with SSH key based
          authentication, they should see password warning if
          their psssword is expired.
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1765354
        :id: 2fe08fa9-6491-46df-81a6-4c5e80d8e671
        :customerscenario: true
        :setup:
          1. Generate ssh keys for an user.
          2. Upload public key to ipa for the user.
          3. Change the password expiration to tomorrow for the user.
          4. Configure hbac rule for the user enabling sshd service.
          5. Configure ipa_access_order and pwd_expiration_warning
          6. Expire user password
        :steps:
          1. Login using ssh key as the user to the client machine.
          2. Check the output of the ssh.
        :expectedresults:
          1. User is logged in.
          2. Password expiration message is shown.
        """
        # pylint: disable=W0613

        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        client.sssd_conf(
            'domain/%s' % domain_name,
            {'ipa_access_order': 'pwd_expire_policy_warn',
             'pwd_expiration_warning': '3'}
        )

        client.clear_sssd_cache()

        # Make sure that user home is not present with unwanted files and
        # possibly wrong ownership
        multihost.client[0].run_command(
            'rm -rf /home/foobar1', raiseonerr=False)

        multihost.client[0].run_command(
            'getent passwd foobar1@testrealm.test', raiseonerr=False)

        # Generate keypair
        multihost.client[0].run_command(
            r"""su -l foobar1@testrealm.test -c 'ssh-keygen -b 2048 -t rsa"""
            r""" -q -f /home/foobar1/.ssh/id_rsa -N ""' """, raiseonerr=False)

        # Get the pubkey
        pubkey = multihost.client[0].get_file_contents(
            "/home/foobar1/.ssh/id_rsa.pub").decode('utf-8').strip()

        multihost.master[0].run_command('kinit admin', stdin_text='Secret123',
                                        raiseonerr=False)
        # Upload the pubkey to IPA
        multihost.master[0].run_command(
            f'ipa user-mod foobar1 --sshpubkey="{pubkey}"', raiseonerr=False)

        # Make password expired yesterday
        yesterday = datetime.date.today() - datetime.timedelta(days=1)
        date_for_ipa = yesterday.strftime("%Y%m%d%H%M%SZ")
        multihost.master[0].run_command(
            f'ipa user-mod foobar1 --setattr=krbPasswordExpiration='
            f'"{date_for_ipa}"', raiseonerr=False)

        client.clear_sssd_cache()

        # Run ssh
        # This one does not work RHEL 8
        # cmd = 'su - foobar1@testrealm.test -c " ssh -v ' \
        #       '-o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null ' \
        #       '-o GSSAPIAuthentication=no -o PasswordAuthentication=no ' \
        #       '-l foobar1@testrealm.test localhost \'whoami\' " 2>&1'

        cmd = 'sudo -u foobar1@testrealm.test ssh -v ' \
              '-o StrictHostKeychecking=no -o UserKnownHostsFile=/dev/null ' \
              '-o GSSAPIAuthentication=no -o PasswordAuthentication=no ' \
              '-l foobar1@testrealm.test localhost <<< whoami 2>&1'

        ssh_cmd = multihost.client[0].run_command(cmd, raiseonerr=False)

        # Teardown
        multihost.master[0].run_command(
            'ipa user-mod foobar1 --setattr=krbPasswordExpiration='
            '"20370101000000Z"', raiseonerr=False)

        multihost.master[0].run_command(
            'ipa user-mod foobar1 --sshpubkey=""', raiseonerr=False)

        multihost.client[0].run_command(
            'rm -rf /home/foobar1', raiseonerr=False)

        # Test result evaluation
        assert ssh_cmd.returncode == 0, "Ssh login failed."
        assert "Your password has expired" in ssh_cmd.stdout_text, \
            "The password expiration notice was not shown."

    def test_anonymous_pkinit_for_fast(self, multihost, backupsssdconf):
        """
        :title: Allow SSSD to use anonymous pkinit for FAST
        :id: 4a3ecc11-0d5b-4dce-bd08-5b1f47164b44
        :customerscenario: True
        :description:
         For SSSD to use FAST a Kerberos keytab and service principal must
         exist. SSSD to be enhanced to allow for the use of anonymous pkinit
         to create the FAST session.
        :steps:
          1. Setup a IPA server/client with default setting.
          2. Call anonymous processing using #kinit -n.
          3. Set 'krb5_fast_use_anonymous_pkinit = True' in sssd.conf.
          4. Login to the IPA user.
          5. Check a ccache file with the FAST armor ticket.
        :expectedresults:
          1. Successfully setup the IPA server/client.
          2. Successfully called anonymous processing.
          3. Successfully set the option in sssd.conf.
          4. Successfully logged in to IPA user.
          5. Successfully get a ccache file with the FAST armor ticket
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1859751
        """
        multihost.client[0].run_command('yum install krb5-pkinit -y')
        sssd_client = sssdTools(multihost.client[0])
        domain_name = f'domain/{sssd_client.get_domain_section_name()}'
        add_anony_pkinit = {'krb5_fast_use_anonymous_pkinit': 'True'}
        sssd_client.sssd_conf(domain_name, add_anony_pkinit)
        sssd_client.clear_sssd_cache()
        cmd_kinit = multihost.client[0].run_command('kinit -n')
        assert cmd_kinit.returncode == 0
        sssd_client.auth_from_client('foobar0', "Secret123")
        cmd_klist = f'klist /var/lib/sss/db/fast_ccache_' \
                    f'{sssd_client.get_domain_section_name().upper()}'
        output = multihost.client[0].run_command(cmd_klist).stdout_text
        principal = 'WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS'
        assert principal in output

    def test_anonymous_pkinit_for_fast_false(self, multihost, backupsssdconf):
        """
        :title: Negative test for allow SSSD to use anonymous pkinit for FAST
        :id: de823122-af88-41f6-b762-63083fccaa87
        :customerscenario: True
        :description:
         For SSSD to use FAST a Kerberos keytab and service principal must
         exist. SSSD to be enhanced to allow for the use of anonymous pkinit
         to create the FAST session. With
         'krb5_fast_use_anonymous_pkinit = False' the ccache will have a
         ticket for the host principal.
        :steps:
          1. Setup a IPA server/client with default setting.
          2. Call anonymous processing using #kinit -n.
          3. Set 'krb5_fast_use_anonymous_pkinit = False' in sssd.conf.
          4. Login to the IPA user.
          5. Check a ccache file for the host principal.
        :expectedresults:
          1. Successfully setup the IPA server/client.
          2. Successfully called anonymous processing.
          3. Successfully set the option in sssd.conf.
          4. Successfully logged in to IPA user.
          5. Successfully get a ccache file with the host principal.
        :bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1859751
        """
        sssd_client = sssdTools(multihost.client[0])
        domain_section = sssd_client.get_domain_section_name()
        domain_name = f'domain/{domain_section}'
        add_anony_pkinit = {'krb5_fast_use_anonymous_pkinit': 'False'}
        sssd_client.sssd_conf(domain_name, add_anony_pkinit)
        sssd_client.clear_sssd_cache()
        cmd_kinit = multihost.client[0].run_command('kinit -n')
        assert cmd_kinit.returncode == 0
        sssd_client.auth_from_client('foobar1', "Secret123")
        cmd_klist = f'klist /var/lib/sss/db/' \
                    f'fast_ccache_{domain_section.upper()}'
        output = multihost.client[0].run_command(cmd_klist).stdout_text
        principal = re.compile(rf'principal:.host.'
                               rf'{multihost.client[0].sys_hostname}@'
                               rf'{domain_section.upper()}')
        assert principal.search(output)
