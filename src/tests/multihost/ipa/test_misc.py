""" Miscellaneous IPA Bug Automations

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

import pytest
import time
from sssd.testlib.common.utils import sssdTools, SSHClient
from sssd.testlib.common.exceptions import SSSDException
import re


@pytest.mark.usefixtures('default_ipa_users', 'reset_password')
@pytest.mark.tier1
class Testipabz(object):
    """ IPA BZ Automations """
    def test_blank_kinit(self, multihost):
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
            STATUS = 'PASS'
            logs = 'journalctl -x -n 50 --no-pager'
            cmd = multihost.client[0].run_command(logs, raiseonerr=False)
            search_txt = 'krb5_kt_start_seq_get failed: '\
                         'Unsupported key table format version number'
            check = re.compile(r'%s' % search_txt)
            if not check.search(cmd.stdout_text):
                STATUS = 'FAIL'
        else:
            STATUS = 'FAIL'
            pytest.fail("sssd should fail to restart")
        # restore /etc/krb5.keytab
        restore = 'mv /etc/krb5.keytab.orig /etc/krb5.keytab'
        multihost.client[0].run_command(restore)
        assert STATUS == 'PASS'

    def test_sssdConfig_remove_Domains(self, multihost):
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
        for i in range(5):
            cmd1 = multihost.client[0].run_command(setup_automount,
                                                   raiseonerr=False)
            time.sleep(5)
            cmd2 = multihost.client[0].run_command(uninstall_automount,
                                                   raiseonerr=False)
            assert cmd1.returncode == 0
            assert cmd2.returncode == 0

    def test_filter_groups(self, multihost, default_ipa_groups,
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
        assert all(x not in cmd1.stdout_text for x in [str(gid_start+1),
                                                       str(gid_start+2)]), \
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
        assert all(x not in cmd2.stdout_text for x in [str(gid_start+3),
                                                       str(gid_start+4),
                                                       str(gid_start+5)]), \
            "The unexpected gid found in the id output!"

    def test_asymmetric_auth_for_nsupdate(self, multihost,
                                          create_reverse_zone):
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

    def test_authentication_indicators(self, multihost):
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
        multihost.client[0].run_command('cp -vf '
                                        '/etc/pam.d/sudo '
                                        '/etc/pam.d/sudo_indicators')
        multihost.client[0].run_command("sed -i "
                                        "'2s/^/auth sufficient "
                                        "pam_sss_gss.so debug\\n/' "
                                        "/etc/pam.d/sudo")
        multihost.client[0].run_command('cp -vf '
                                        '/etc/pam.d/sudo-i '
                                        '/etc/pam.d/sudo-i_indicators')
        multihost.client[0].run_command("sed -i "
                                        "'2s/^/auth sufficient "
                                        "pam_sss_gss.so debug\\n/' "
                                        "/etc/pam.d/sudo-i")
        multihost.client[0].run_command('systemctl stop sssd ; '
                                        'rm -rf /var/log/sssd/* ; '
                                        'rm -rf /var/lib/sss/db/* ; '
                                        'systemctl start sssd')
        multihost.client[0].run_command("sssctl debug-level 9")
        ssh = SSHClient(multihost.client[0].ip,
                        username='admin', password='Secret123')
        (_, _, exit_status) = ssh.execute_cmd('kinit admin',
                                              stdin='Secret123')
        (result, errors, exit_status) = ssh.exec_command('klist')
        (result, errors, exit_status) = ssh.execute_cmd('ipa '
                                                        'sudocmd-add ALL2')
        (result, errors, exit_status) = ssh.execute_cmd('ipa '
                                                        'sudorule-add '
                                                        'testrule2')
        (result, errors, exit_status) = ssh.execute_cmd("ipa sudorule-add"
                                                        "-allow-command "
                                                        "testrule2 "
                                                        "--sudocmds 'ALL2'")
        (result, errors, exit_status) = ssh.execute_cmd('ipa '
                                                        'sudorule-mod '
                                                        'testrule2 '
                                                        '--hostcat=all')
        (result, errors, exit_status) = ssh.execute_cmd('ipa '
                                                        'sudorule-add-user '
                                                        'testrule2 '
                                                        '--users admin')
        (result, errors, exit_status) = ssh.execute_cmd('sudo -l')
        ssh.close()
        search = multihost.client[0].run_command('fgrep '
                                                 'gssapi_ '
                                                 '/var/log/sssd/sssd_pam.log '
                                                 '|tail -10')
        assert 'indicators: 0' in search.stdout_text
        client = sssdTools(multihost.client[0])
        domain_params = {'pam_gssapi_services': 'sudo, sudo-i',
                         'pam_gssapi_indicators_map': 'sudo-i:hardened'}
        client.sssd_conf('pam', domain_params)
        multihost.client[0].run_command('systemctl stop sssd ; '
                                        'rm -rf /var/log/sssd/* ; '
                                        'rm -rf /var/lib/sss/db/* ; '
                                        'systemctl start sssd')
        ssh = SSHClient(multihost.client[0].ip,
                        username='admin', password='Secret123')
        (_, _, exit_status) = ssh.execute_cmd('kinit admin',
                                              stdin='Secret123')
        multihost.client[0].run_command("sssctl debug-level 9")
        (result, errors, exit_status) = ssh.execute_cmd('sudo -l')
        (result, errors, exit_status) = ssh.exec_command('klist')
        (result, errors, exit_status) = ssh.execute_cmd('ipa '
                                                        'sudocmd-del ALL2')
        (result, errors, exit_status) = ssh.execute_cmd('ipa '
                                                        'sudorule-del '
                                                        'testrule2')
        multihost.client[0].run_command('cp -vf /etc/pam.d/sudo_indicators '
                                        '/etc/pam.d/sudo')
        multihost.client[0].run_command('cp -vf /etc/pam.d/sudo-i_indicators '
                                        '/etc/pam.d/sudo-i')
        search = multihost.client[0].run_command('fgrep gssapi_ '
                                                 '/var/log/sssd/sssd_pam.log'
                                                 ' |tail -10')
        ssh.close()
        assert 'indicators: 2' in search.stdout_text

    def test_pass_krb5cname_to_pam(self, multihost,
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
        tools.service_ctrl('restart', 'sssd')
        domain_name = tools.get_domain_section_name()
        user = "admin"
        test_password = "Secret123"
        sys_hostname = multihost.client[0].sys_hostname
        ssh1 = SSHClient(multihost.client[0].ip, username=user,
                         password=test_password)
        (_, _, exit_status) = ssh1.execute_cmd('kinit',
                                               stdin=test_password)
        assert exit_status == 0
        (_, _, _) = ssh1.execute_cmd("ipa sudocmd-add /usr/sbin/sssctl")
        (_, _, _) = ssh1.execute_cmd("ipa sudorule-add idm_user_sssctl")
        (_, _, _) = ssh1.execute_cmd("ipa sudorule-add-allow-command "
                                     "idm_user_sssctl --sudocmds "
                                     "'/usr/sbin/sssctl'")
        (_, _, _) = ssh1.execute_cmd(f"ipa sudorule-add-host "
                                     f"idm_user_sssctl "
                                     f"--hosts {sys_hostname}")
        (_, _, _) = ssh1.execute_cmd("ipa sudorule-add-user "
                                     "idm_user_sssctl "
                                     "--users admin")
        tools.clear_sssd_cache()
        ssh2 = SSHClient(multihost.client[0].ip, username=user,
                         password=test_password)
        (_, _, _) = ssh2.execute_cmd('kinit', stdin=test_password)
        (_, _, _) = ssh2.execute_cmd('sudo -S -l', stdin=test_password)
        file_name = 'domain_list_' + str(time.time())
        (_, _, _) = ssh2.execute_cmd(f"sudo -S /usr/sbin/sssctl domain-list > "
                                     f"/tmp/{file_name}", stdin=test_password)
        result = multihost.client[0].run_command(f"cat /tmp/{file_name}"
                                                 ).stdout_text
        assert domain_name in result

    def test_ssh_hash_knownhosts(self, multihost, reset_password, backupsssdconf):
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
            #  no hash_value or hash_value = True or hash_value = False
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
        sssd_client = sssdTools(multihost.client[0])
        domain_name = f'domain/{sssd_client.get_domain_section_name()}'
        add_anony_pkinit = {'krb5_fast_use_anonymous_pkinit': 'True'}
        sssd_client.sssd_conf(domain_name, add_anony_pkinit)
        sssd_client.clear_sssd_cache()
        cmd_kinit = multihost.client[0].run_command('kinit -n')
        assert cmd_kinit.returncode == 0
        ssh = SSHClient(multihost.client[0].ip,
                        username='foobar0', password='Secret123')
        ssh.close()
        cmd_klist = f'klist /var/lib/sss/db/fast_ccache_{sssd_client.get_domain_section_name().upper()}'
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
        ssh = SSHClient(multihost.client[0].ip,
                        username='foobar1', password='Secret123')
        ssh.close()
        cmd_klist = f'klist /var/lib/sss/db/fast_ccache_{domain_section.upper()}'
        output = multihost.client[0].run_command(cmd_klist).stdout_text
        principal = re.compile(rf'principal:.host.{multihost.client[0].sys_hostname}@{domain_section.upper()}')
        assert principal.search(output)
