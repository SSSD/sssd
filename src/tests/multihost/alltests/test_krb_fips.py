""" Basic fips sanity test cases for sssd """

import time
import re
import pytest
import ldap
from constants import ds_instance_name, ds_suffix, krb_realm
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import sssdTools, LdapOperations
from sssd.testlib.common.exceptions import SSHLoginException
from sssd.testlib.common.exceptions import SSSDException
from sssd.testlib.common.libkrb5 import krb5srv
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd_gssapi', 'create_posix_usersgroups')
@pytest.mark.fips
class Testkrbfips(object):
    """ Testing fips """

    @pytest.mark.tier1
    def test_krb_ptr_hash_crash_1792331(self, multihost):
        """
        @Title: sssd_be crashes when krb5_realm and krb5_server
        is omitted and auth_provider is krb5
        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1792331
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

    def test_fips_login(self, multihost):
        """
        @Title: Verify kerberos user can login successfully in fips mode.
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

    def test_child_logs_after_receiving_hup(self, multihost):
        """
        :Title: sssd fails to release file descriptor on child
        logs after receiving hup
        @bugzilla:
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

    @pytest.mark.tier1
    def test_sssd_not_check_gss_spengo(self, multihost, backupsssdconf):
        """
        :Title: krb5/fips: sssd does not properly check GSS-SPNEGO
        @bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1868054
        """
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        del_params = {'ldap_sasl_mech': 'GSSAPI'}
        client.sssd_conf('domain/%s' % domain_name, del_params, action='delete')
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
        if err_msg in cmd.stdout_text:
            status = "FAIL"
        else:
            status = "PASS"
        assert status == "PASS"

    def test_fips_as_req(self, multihost):
        """
        @Title: krb5/fips: verify sssd accepts only elisted fips approved types
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo2@%s' % domain_name
        ldap_host = multihost.master[0].sys_hostname
        pcapfile = '/tmp/krb1.pcap'
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        sudo_pcapfile = '/tmp/pcap1.pcap'
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

    def test_fips_as_rep(self, multihost):
        """
        @Title: krb5/fips: verify sssd accepts only elisted fips approved types
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo3@%s' % domain_name
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
            print("SSH Login failed")
            tshark_cmd = "tshark -r %s -V -2 -R"\
                         " 'kerberos.msg_type == 11'" % pcapfile
            cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
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
            invalid_etypes = ['DES3-CBC-SHA1', 'ARCFOUR-HMAC-MD5',
                              'CAMELLIA128-CTS-CMAC', 'CAMELLIA256-CTS-CMAC']
            count = 0
            for etype in valid_etypes:
                check_str = 'eTYPE-%s' % etype
                check = re.compile(r'%s' % etype)
                if check.search(cmd.stdout_text):
                    count += 1
        assert count == 1
        rm_pcap_file = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    def test_login_fips_weak_crypto(self, multihost):
        """
        @Title: krb5/fips: verify login fails when weak crypto is presented.
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

    def test_ldap_gssapi(self, multihost):
        """
        @Title: krb5/fips: verify sssd is able to create gssapi connection
        with fips approved etype.
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
            (_, ret) = client.command(ldapsearch)
            client.logout()
            multihost.client[0].run_command(pkill)
            tshark_cmd = "tshark -r %s -V -2 -R"\
                         " 'kerberos.msg_type == 13'" % pcapfile
            cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
        rm_pcap_file = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    def test_tgs_nonfips(self, multihost):
        """
        @Title: krb5/fips: Verify sssd fails to create gssapi connection
        with weak etypes
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

