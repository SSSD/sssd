""" Keytab Rotation Test cases

:requirement: IDM-SSSD-REQ: Active Directory host keytab renewal
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import subprocess
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.samba import sambaTools


@pytest.mark.keytabrotation
class TestHostKeytabRotation(object):
    """ Keytab Rotation Test cases

    :setup:
      1. Configure RHEL client to join to Windows AD using
        realm
      2. set machine password age to 1 day in sssd.conf
    """

    @pytest.mark.tier2
    def test_001_rotation(self, multihost, keytab_sssd_conf):
        """
        :title: IDM-SSSD-TC: AD-Provider Keytab Rotation: Verify New entries in
         keytab should have new KVNO after keytab rotation
        :id: 26551713-7a82-489f-adc5-8543caa97dd2
        :steps:
          1. Set pwdLastSet attribute of computer account to 0
          2. Restart sssd
          3. sssd calls adcli and new host entries are added /etc/krb5.keytab
        :expectedresults:
          1. pwdLastSet Attribute should be 0
          2. Verify sssd restart successfully
          3. Verify /etc/krb5.keytab has new kvno apart from older entries
        """
        # Get current keytab entries
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.reset_machine_password()
        client_hostname = multihost.client[0].sys_hostname.split('.')[0]
        if len(client_hostname) > 15:
            client_hostname = client_hostname[:15]
        realm = multihost.ad[0].realm
        host_princ = 'HOST/%s@%s' % (client_hostname, realm)
        kvno_cmd = 'kvno %s' % (host_princ)
        cmd = multihost.client[0].run_command(kvno_cmd, raiseonerr=False)
        kvno = cmd.stdout_text.split('=')[1].strip()
        restart_sssd = 'systemctl restart sssd'
        try:
            multihost.client[0].run_command(restart_sssd)
        except subprocess.CalledProcessError:
            multihost.client[0].multihost.client[0].run_command(
                'journalctl -x -n 50 --no-pager -u sssd', raiseonerr=False)
            pytest.fail("Cannot restart sssd service")
        time.sleep(30)
        ls = 'ls -l /etc/krb5.keytab'
        cmd = multihost.client[0].run_command(ls, raiseonerr=False)
        klist_cmd = "klist -k /etc/krb5.keytab"
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        spn_list = [val.strip() for val in cmd.stdout_text.splitlines()]
        client_domain = multihost.client[0].sys_hostname.split('.')[0].upper()
        if len(client_domain) > 15:
            client_domain = client_domain[:15]
        old_kvno = int(kvno)
        new_kvno = int(kvno) + 1
        # older entry
        client_host_entry_1 = '{} {}/{}@{}'.format(old_kvno, 'host',
                                                   client_domain,
                                                   multihost.ad[0].realm)
        # new entry
        client_host_entry_2 = '{} {}/{}@{}'.format(new_kvno, 'host',
                                                   client_domain,
                                                   multihost.ad[0].realm)
        if client_host_entry_1 and client_host_entry_2 not in spn_list[3:]:
            pytest.fail("keytab rotation failed, host entries not rotated")

    @pytest.mark.tier2
    def test_002_updatedkeytab(self, multihost, keytab_sssd_conf):
        """
        :title: IDM-SSSD-TC: AD-Provider Keytab Rotation:
         Verify with updated Keytab Authentication using
         host credentials is successful
        :id: 21176af3-614e-417f-87b6-13d8dfe7f33a
        :steps:
          1. kinit using new HOST principal
          2. Do ldapsearch using GSSAPI bind
        :expectedresults:
          1. kinit should be successful
          2. ldapsearch should be successful
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.reset_machine_password()
        restart_sssd = 'systemctl restart sssd'
        try:
            multihost.client[0].run_command(restart_sssd)
        except subprocess.CalledProcessError:
            multihost.client[0].multihost.client[0].run_command(
                'journalctl -x -n 50 --no-pager -u sssd', raiseonerr=False)
            pytest.fail("Cannot restart sssd service")
        time.sleep(30)
        domain_basedn_entry = multihost.ad[0].domain_basedn_entry
        client_name = multihost.client[0].sys_hostname.strip().split('.')[0]
        if len(client_name) > 15:
            client_name = client_name[:15]
        client_host_keytab_entry = '{}$@{}'.format(client_name.upper(),
                                                   multihost.ad[0].realm)
        users_dn_entry = '{},{}'.format('CN=users', domain_basedn_entry)
        ad_hostname = multihost.ad[0].sys_hostname
        kinit_cmd = "kinit -k '%s'" % (client_host_keytab_entry)
        try:
            multihost.client[0].run_command(kinit_cmd)
        except subprocess.CalledProcessError:
            pytest.fail("kinit failed after keytab rotation")

        try:
            multihost.client[0].run_command(['klist'])
        except subprocess.CalledProcessError:
            pytest.fail("klist failed")

        ldap_cmd = "ldapsearch -H ldap://%s -Y GSSAPI -N -b %s "\
                   "'(&(objectclass=User) (sAMAccountName=Administrator))'" % (
                       ad_hostname, users_dn_entry)
        try:
            multihost.client[0].run_command(ldap_cmd)
        except subprocess.CalledProcessError:
            pytest.fail("ldapsearch using GSSAPI bind failed")

    @pytest.mark.tier2
    def test_003_delentry(self, multihost, keytab_sssd_conf):
        """
        :title: IDM-SSSD-TC: AD-Provider Keytab Rotation:
         Verify the oldest host principal entries are deleted
         after succesful machine password
        :id: 0812dcbf-5d58-4ff8-9891-789f1a5ce8d4
        :steps:
          1. Reset Machine password again by setting pwdlastSet attribute to 0
          2. Restart sssd service
          3. klist -k /etc/krb5.keytab
        :expectedresults:
          1. pwdLastSet attribute should be 0
          2. sssd service should be successfully restarted
          3. Verify adcli rotates keytab entries and the oldest keytab
             entry with KVNO 2 is deleted
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.reset_machine_password()
        domain_name = client.get_domain_section_name()
        klist_cmd = "klist -k /etc/krb5.keytab"
        client_hostname = multihost.client[0].sys_hostname.split('.')[0]
        if len(client_hostname) > 15:
            client_hostname = client_hostname[:15]
        realm = multihost.ad[0].realm
        host_princ = 'HOST/%s@%s' % (client_hostname, realm)
        kvno_cmd = 'kvno %s' % (host_princ)
        cmd = multihost.client[0].run_command(kvno_cmd, raiseonerr=False)
        kvno = cmd.stdout_text.split('=')[1].strip()
        remove_logs = "rm -f /var/log/sssd/sssd_%s.log" % (domain_name)
        multihost.client[0].run_command(remove_logs)
        restart_sssd = 'systemctl restart sssd'
        old_kvno = int(kvno)
        new_kvno1 = int(kvno) + 1
        new_kvno2 = new_kvno1 + 1
        try:
            multihost.client[0].run_command(restart_sssd)
        except subprocess.CalledProcessError:
            pytest.fail("Cannot restart sssd service")
        multihost.client[0].log.info("Sleep for 60 seconds")
        time.sleep(60)
        multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        client.reset_machine_password()
        try:
            multihost.client[0].run_command(restart_sssd)
        except subprocess.CalledProcessError:
            multihost.client[0].multihost.client[0].run_command(
                'journalctl -x -n 50 --no-pager -u sssd', raiseonerr=False)
            pytest.fail("Cannot restart sssd service")
        time.sleep(60)
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        spn_list = [val.strip() for val in cmd.stdout_text.splitlines()]
        client_domain = multihost.client[0].sys_hostname.split('.')[0].upper()
        if len(client_domain) > 15:
            client_domain = client_domain[:15]
        client_host_entry_old = '{} {}/{}@{}'.format(old_kvno, 'host',
                                                     client_domain,
                                                     multihost.ad[0].realm)
        client_host_entry1 = '{} {}/{}@{}'.format(new_kvno1, 'host',
                                                  client_domain,
                                                  multihost.ad[0].realm)
        client_host_entry2 = '{} {}/{}@{}'.format(new_kvno2, 'host',
                                                  client_domain,
                                                  multihost.ad[0].realm)
        if client_host_entry_old not in spn_list[3:]:
            assert client_host_entry1 and client_host_entry2 in spn_list[3:]
        else:
            pytest.fail("Client old host entry is not deleted from keytab")

    @pytest.mark.tier3
    def test_004_multiplespn(self, multihost, keytab_sssd_conf):
        """
        :title: IDM-SSSD-TC: AD-Provider Keytab Rotation:
         Add Multiple SPN(http,nfs) to the client host and
         verify all the SPN entries are rotated
        :id: a66c325f-09e2-4a81-8b76-b863dead7e92
        :steps:
          1. ADD HTTP SPN for client using net ads keytab cli
          2. ADD NFS SPN for client using net ads keytab cli
          3. Reset Machine password by setting pwdLastSet to 0
          4. Restart sssd
          5. klist -k /etc/krb5.keytab
        :expectedresults:
          1. klist -k /etc/krb5.keytab should HTTP entries
          2. klist -k /etc/krb5.keytab should NFS entries
          3. pwdLastSet attribute should be 0
          4. sssd service should be restarted successfully
          5. New HTTP and NFS entries with new kvno should be added to
             /etc/krb5.keytab
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.reset_machine_password()
        sambaclient = sambaTools(multihost.client[0], multihost.ad[0])
        sambaclient.smbadsconf()
        domain_name = client.get_domain_section_name()
        services_list = ['HTTP', 'NFS']
        client.add_service_principals(services_list)
        klist_cmd = "klist -k /etc/krb5.keytab"
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        realm = multihost.ad[0].realm
        hostname = multihost.client[0].sys_hostname
        remove_logs = "rm -f /var/log/sssd/sssd_%s.log" % (domain_name)
        multihost.client[0].run_command(remove_logs)
        restart_sssd = 'systemctl restart sssd'
        https_princ = 'HTTP/%s@%s' % (hostname, realm)
        kvno_cmd = 'kvno %s' % (https_princ)
        cmd = multihost.client[0].run_command(kvno_cmd, raiseonerr=False)
        kvno = cmd.stdout_text.split('=')[1].strip()
        try:
            multihost.client[0].run_command(restart_sssd)
        except subprocess.CalledProcessError:
            multihost.client[0].multihost.client[0].run_command(
                'journalctl -x -n 50 --no-pager -u sssd', raiseonerr=False)
            pytest.fail("Cannot restart sssd service")
        time.sleep(45)
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        spn_list = [val.strip() for val in cmd.stdout_text.splitlines()]
        new_kvno = int(kvno) + 1
        nfs_entry = '{} {}/{}@{}'.format(new_kvno, 'NFS', hostname, realm)
        http_entry = '{} {}/{}@{}'.format(new_kvno, 'HTTP', hostname, realm)
        assert nfs_entry and http_entry in spn_list[3:]
        client.remove_service_principals(services_list)
        remove_smb_conf = 'rm -f /etc/samba/smb.conf'
        multihost.client[0].run_command(remove_smb_conf, raiseonerr=False)

    @pytest.mark.tier3
    def test_005_deletespn(self, multihost, keytab_sssd_conf):
        """
        :title: IDM-SSSD-TC: AD-Provider Keytab Rotation:
         Removing SPN from AD and verify removed SPN entries
         are not renewed upon renewal
        :id: 6430387a-a715-44b4-81e3-7c012d887e00
        :steps:
          1. Delete HTTP SPN using setspn.exe  cli from AD
          2. Reset Machine password by setting pwdLastSet attribute to 0
          3. Restart sssd
          4. klist -k /etc/krb5.keytab
        :expectedresults:
          1. HTTP SPN should be deleted
          2. pwdLastSet attribute should be 0
          3. sssd service should be restarted successfuly
          4. Verify no new HTTP Entries with new KVNO are added in
             /etc/krb5.keytab
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        sambaclient = sambaTools(multihost.client[0], multihost.ad[0])
        sambaclient.smbadsconf()
        services_list = ['HTTP']
        client.add_service_principals(services_list)
        client.reset_machine_password()
        domain_name = client.get_domain_section_name()
        klist_cmd = "klist -k /etc/krb5.keytab"
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        realm = multihost.ad[0].realm
        hostname = multihost.client[0].sys_hostname
        remove_logs = "rm -f /var/log/sssd/sssd_%s.log" % (domain_name)
        multihost.client[0].run_command(remove_logs)
        restart_sssd = 'systemctl restart sssd'
        https_princ = 'HTTP/%s@%s' % (hostname, realm)
        kvno_cmd = 'kvno %s' % (https_princ)
        cmd = multihost.client[0].run_command(kvno_cmd, raiseonerr=False)
        kvno = cmd.stdout_text.split('=')[1].strip()
        client.remove_service_principals(services_list)
        try:
            multihost.client[0].run_command(restart_sssd)
        except subprocess.CalledProcessError:
            multihost.client[0].multihost.client[0].run_command(
                'journalctl -x -n 50 --no-pager -u sssd', raiseonerr=False)
            pytest.fail("Cannot restart sssd service")
        time.sleep(45)
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        spn_list = [val.strip() for val in cmd.stdout_text.splitlines()]
        new_kvno = int(kvno) + 1
        http_entry = '{} {}/{}@{}'.format(new_kvno, 'HTTP', hostname, realm)
        assert http_entry in spn_list[3:]
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        remove_smb_conf = 'rm -f /etc/samba/smb.conf'
        multihost.client[0].run_command(remove_smb_conf, raiseonerr=False)
