""" Basic fips sanity test cases for sssd

:requirement: IDM-SSSD-REQ : KRB5 Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import time
import re
import pytest
import ldap
from pexpect import pxssh
from constants import ds_suffix, krb_realm
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import LdapOperations
from sssd.testlib.common.exceptions import SSHLoginException
from sssd.testlib.common.libkrb5 import krb5srv


@pytest.mark.usefixtures('setup_sssd_gssapi', 'create_posix_usersgroups')
@pytest.mark.fips
class Testkrbfips(object):
    """ Testing fips """

    @staticmethod
    @pytest.mark.tier1
    def test_krb_ptr_hash_crash_1792331(multihost):
        """
        :title: sssd_be crashes when krb5_realm and krb5_server
         is omitted and auth_provider is krb5
        :id: b1321b02-4a29-4285-8c85-36f925496463
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1792331
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        multihost.client[0].service_sssd('stop')
        multihost.client[0].run_command(['cat', '/etc/sssd/sssd.conf'])
        kerberos_server = multihost.master[0].sys_hostname
        domain_params = {'krb5_realm': '%s' % krb_realm,
                         'krb5_server': kerberos_server}
        section = 'domain/%s' % domain_name
        tools.sssd_conf(section, domain_params, action='delete')
        start_sssd = 'systemctl start sssd'
        cmd = multihost.client[0].run_command(start_sssd, raiseonerr=False)
        journalctl = 'journalctl -x -n 50 --no-pager'
        crash_msg = "Job for sssd.service failed because a fatal signal"\
                    " was delivered causing the control process to dump core"
        err_msg = "Job for sssd.service failed because the control process "\
                  "exited with error code."
        check1 = re.compile(r'%s' % crash_msg)
        check2 = re.compile(r'%s' % err_msg)
        if check1.search(cmd.stderr_text):
            multihost.client[0].run_command(journalctl)
            tools.sssd_conf(section, domain_params)
            pytest.fail("sssd crashed")
        else:
            tools.sssd_conf(section, domain_params)
            multihost.client[0].run_command(journalctl)
            assert check2.search(cmd.stderr_text)
        multihost.client[0].service_sssd('restart')

    @staticmethod
    def test_fips_login(multihost):
        """
        :title: Verify kerberos user can login successfully in fips mode
        :id: 0ec0efc9-85dd-4a66-9802-65f3b122b7da
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo1@%s' % domain_name
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()

    @staticmethod
    @pytest.mark.tier1_2
    def test_kcm_not_store_tgt(multihost, backupsssdconf):
        """
        :title: sssd-kcm does not store TGT with ssh
         login using GSSAPI
        :id: 9a79474c-26c5-4aeb-9f26-f2ada0e9f453
        :customerscenario: True
        :requirement:
         IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1722842
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'debug_level': '10',
                         'ccache_storage': 'memory'}
        client.sssd_conf('kcm', domain_params)
        multihost.client[0].service_sssd('restart')
        multihost.client[0].run_command("systemctl "
                                        "restart sssd-kcm")

        ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                          "UserKnownHostsFile": "/dev/null"})
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].sys_hostname, 'foo3', 'Secret123')
            ssh.sendline('kdestroy -A -q')
            ssh.prompt(timeout=5)
            ssh.sendline('kinit foo3')
            ssh.expect('Password for .*:', timeout=10)
            ssh.sendline('Secret123')
            ssh.prompt(timeout=5)
            ssh.sendline('klist')
            ssh.prompt(timeout=5)
            klist = str(ssh.before)
            ssh.sendline(f'ssh -v -o StrictHostKeyChecking=no -K -l foo3 '
                         f'{multihost.client[0].sys_hostname} klist')
            ssh.prompt(timeout=30)
            ssh_output = str(ssh.before)
            ssh.logout()
        except pxssh.ExceptionPxssh:
            pytest.fail("Ssh login failed.")

        assert 'KCM:14583103' in klist, "kinit did not work!"
        assert 'KCM:14583103' in ssh_output, "Ticket not forwarded!"

    @staticmethod
    def test_child_logs_after_receiving_hup(multihost):
        """
        :title: sssd fails to release file descriptor on child
         logs after receiving hup
        :id: 3e28f453-fae8-4f52-82d0-757a5bdd0b06
        :customerscenario: True
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1544457
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo1@%s' % domain_name
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()
        time.sleep(2)
        ps_cmd = "mv /var/log/sssd/krb5_child.log  " \
                 "/var/log/sssd/krb5_child.log.old"
        cmd = multihost.client[0].run_command(ps_cmd)
        ps_cmd = "pgrep sssd"
        cmd = multihost.client[0].run_command(ps_cmd)
        sssd_pid = cmd.stdout_text.split('\n')[0]
        ps_cmd = f"/bin/kill -HUP {sssd_pid}"
        cmd = multihost.client[0].run_command(ps_cmd)
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()
        time.sleep(2)
        cmd = multihost.client[0].run_command(ps_cmd)
        for file in ['krb5_child.log', 'krb5_child.log.old']:
            ps_cmd = f"ls -l /var/log/sssd/{file}"
            cmd = multihost.client[0].run_command(ps_cmd)
            if f'/var/log/sssd/{file}' in cmd.stdout_text:
                status = 'PASS'
            else:
                status = 'FAIL'
        assert status == 'PASS'

    @staticmethod
    @pytest.mark.tier1
    def test_sssd_not_check_gss_spengo(multihost, backupsssdconf):
        """
        :title: krb5/fips: sssd does not properly check GSS-SPNEGO
        :id: 8ba5427e-8abe-44b9-adaa-878d2418b189
        :customerscenario: True
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1868054
        """
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        del_params = {'ldap_sasl_mech': 'GSSAPI'}
        client.sssd_conf('domain/%s' % domain_name,
                         del_params, action='delete')
        domain_params = {'ldap_sasl_mech': 'GSS-SPNEGO'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        user = 'foo1@%s' % domain_name
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()
        ps_grep = "grep GSS /var/log/sssd/*.log"
        cmd = multihost.client[0].run_command(ps_grep)
        err_msg = "SPNEGO cannot find mechanisms to negotiate"
        assert err_msg not in cmd.stdout_text

    @staticmethod
    def test_fips_as_req(multihost):
        """
        :title: krb5/fips: verify sssd accepts only elisted fips approved types
        :id: c5ab16d5-8636-4f50-992b-aa0f05e1a9e5
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo2@%s' % domain_name
        ldap_host = multihost.master[0].sys_hostname
        pcapfile = '/tmp/krb1.pcap'
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        pkill = 'pkill tcpdump'
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            multihost.client[0].run_command(pkill)
            tshark_cmd = "tshark -r %s -V -2 -R 'kerberos.ENCTYPE'" % pcapfile
            cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
            pytest.fail("%s failed to login" % user)
        else:
            time.sleep(5)
            client.logout()
            multihost.client[0].run_command(pkill)
            # check as_req
            tshark_cmd = "tshark -r %s -V -2 -R 'kerberos.ENCTYPE'" % pcapfile
            cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
            valid_etypes = ['AES128-CTS-HMAC-SHA256-128',
                            'AES256-CTS-HMAC-SHA1-96',
                            'AES128-CTS-HMAC-SHA1-96',
                            'AES256-CTS-HMAC-SHA384-192']
            for etype in valid_etypes:
                check = re.compile(r'%s' % etype)
                assert check.search(cmd.stdout_text)
        rm_pcap_file = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    @staticmethod
    def test_fips_as_rep(multihost):
        """
        :title: krb5/fips: verify sssd accepts only elisted fips approved types
        :id: f8452ecd-e13c-4485-83d3-83e25d7d544a
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo3@%s' % domain_name
        pcapfile = '/tmp/krb1.pcap'
        tcpdump_cmd = f'tcpdump -s0 host {multihost.master[0].sys_hostname}' \
                      f' -w {pcapfile}'
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        pkill = 'pkill tcpdump'
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            multihost.client[0].run_command(pkill)
            print("SSH Login failed")
            tshark_cmd = "tshark -r %s -V -2 -R"\
                         " 'kerberos.msg_type == 11'" % pcapfile
            multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
            pytest.fail("%s failed to login" % user)
        else:
            time.sleep(5)
            client.logout()
            multihost.client[0].run_command(pkill)
            # check as_rep
            tshark_cmd = "tshark -r %s -V -2 -R"\
                         " 'kerberos.msg_type == 11'" % pcapfile
            cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
            valid_etypes = ['AES256-CTS-HMAC-SHA1-96',
                            'AES128-CTS-HMAC-SHA1-96',
                            'AES256-CTS-HMAC-SHA384-192',
                            'AES128-CTS-HMAC-SHA256-128']
            count = 0
            for etype in valid_etypes:
                check = re.compile(r'%s' % etype)
                if check.search(cmd.stdout_text):
                    count += 1
        assert count == 1
        rm_pcap_file = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    @staticmethod
    def test_login_fips_weak_crypto(multihost):
        """
        :title: krb5/fips: verify login fails when weak crypto is presented
        :id: cdd2ef0d-4921-40b3-b61e-0b271b2d5e00
        """
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        tools.clear_sssd_cache()
        user = 'cracker@%s' % domain_name
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        krb = krb5srv(multihost.master[0], 'EXAMPLE.TEST')
        user_info = {'cn': 'cracker',
                     'uid': 'cracker',
                     'uidNumber': '19583100',
                     'gidNumber': '14564100'}
        if ldap_inst.posix_user("ou=People", "dc=example,dc=test", user_info):
            krb.add_principal('cracker', 'user', 'Secret123',
                              etype='arcfour-hmac')
        else:
            pytest.fail("Failed to add user cracker")
        user_dn = 'uid=cracker,ou=People,%s' % ds_suffix
        group_dn = 'cn=ldapusers,ou=Groups,%s' % ds_suffix
        add_member = [(ldap.MOD_ADD, 'uniqueMember', user_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(group_dn, add_member)
        assert ret == 'Success'
        tools.clear_sssd_cache()
        ldap_host = multihost.master[0].sys_hostname
        pcapfile = '/tmp/krb1.pcap'
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        pkill = 'pkill tcpdump'
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            multihost.client[0].run_command(pkill)
            tshark_cmd = "tshark -r %s -V -2 -R"\
                         " 'kerberos.msg_type == 30'" % pcapfile
            cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
            journalctl_cmd = 'journalctl --no-pager -n 150'
            cmd = multihost.client[0].run_command(journalctl_cmd)
            check = re.compile(r'KDC has no support for encryption type')
            assert check.search(cmd.stdout_text)
        else:
            pytest.fail("%s Login successfull")
        ldap_inst.del_dn(user_dn)
        krb.delete_principal('cracker')
        rm_pcap_file = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    @staticmethod
    def test_ldap_gssapi(multihost):
        """
        :title: krb5/fips: verify sssd is able to create gssapi connection
         with fips approved etype.
        :id: 8e80ddc7-fe6a-4729-91b6-f1fbae0dad73
        """
        cmd = 'cat /etc/sssd/sssd.conf'
        multihost.client[0].run_command(cmd)
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo1@%s' % domain_name
        ldap_host = multihost.master[0].sys_hostname
        pcapfile = '/tmp/ldapgssapi.pcap'
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        pkill = 'pkill tcpdump'
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            multihost.client[0].run_command(pkill)
            pytest.fail("%s failed to login" % user)
        else:
            ldapsearch = 'ldapsearch -Y GSSAPI -H ldap://%s' % ldap_host
            client.command(ldapsearch)
            client.logout()
            multihost.client[0].run_command(pkill)
            tshark_cmd = "tshark -r %s -V -2 -R"\
                         " 'kerberos.msg_type == 13'" % pcapfile
            multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
        rm_pcap_file = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    @staticmethod
    def test_tgs_nonfips(multihost):
        """
        :title: krb5/fips: Verify sssd fails to create gssapi connection
         with weak etypes
        :id: f9623bc8-6305-45f1-ab6c-b9c2d18cdb8e
        """
        tools = sssdTools(multihost.client[0])
        host = multihost.client[0].sys_hostname
        domain_name = tools.get_domain_section_name()
        user = 'foo1@%s' % domain_name
        # stop the sssd service
        multihost.client[0].service_sssd('stop')
        add_principal = "add_principal -clearpolicy"\
                        " -e arcfour-hmac -randkey host/%s" % host
        cmd1 = "kadmin -p root/admin -w Secret123 -q '%s'" % add_principal
        multihost.client[0].run_command(cmd1, raiseonerr=False)
        ktadd = 'ktadd -k /etc/krb5.keytab -e arcfour-hmac host/%s' % host
        cmd2 = "kadmin -p root/admin -w Secret123 -q '%s'" % ktadd
        multihost.client[0].run_command(cmd2)
        klist = 'klist -kte /etc/krb5.keytab'
        multihost.client[0].run_command(klist)
        # start the sssd service
        tools.clear_sssd_cache()
        # verify ldap_child.log
        kdc_str = "KDC has no support for encryption type."\
                  " Unable to create GSSAPI-encrypted LDAP connection"
        check = re.compile(r'%s' % kdc_str)
        # check the ldap_child.login
        tail_cmd = 'tail -n 100 /var/log/sssd/ldap_child.log'
        cmd = multihost.client[0].run_command(tail_cmd, raiseonerr=False)
        if check.search(cmd.stdout_text):
            getent = 'getent passwd %s' % user
            cmd = multihost.client[0].run_command(getent, raiseonerr=False)
            assert cmd.returncode == 2
        else:
            print("'%s' message not seen on the logs" % kdc_str)
