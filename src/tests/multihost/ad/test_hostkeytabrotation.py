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
    def test_001_rotation(self, multihost, keytab_sssd_conf, smbconfig):
        """
        :title: IDM-SSSD-TC: AD-Provider Keytab Rotation: Verify New entries in
         keytab should have new KVNO after keytab rotation
        :id: 26551713-7a82-489f-adc5-8543caa97dd2
        :setup:
          1. Get hash of /etc/krb5.keytab
          2. Expire machine account password by setting pwdLastSet to 0
          3. Restart sssd
        :steps:
          1. Check hash of /etc/krb5.keytab
        :expectedresults:
          1. Hash should be different as secrets are updated
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        multihost.client[0].run_command('cat /etc/samba/smb.conf', raiseonerr=False)
        hash_cmd = 'sha1hmac /etc/krb5.keytab'
        cmd = multihost.client[0].run_command(hash_cmd, raiseonerr=False)
        before_hash = cmd.stdout_text.strip()
        client.reset_machine_password()
        client.service_ctrl('restart', 'sssd')
        time.sleep(30)
        cmd = multihost.client[0].run_command(hash_cmd, raiseonerr=False)
        after_hash = cmd.stdout_text.strip()
        if before_hash == after_hash:
            pytest.fail("keytab rotation failed, host entries not rotated")

    @pytest.mark.tier2
    def test_002_updatedkeytab(self, multihost, keytab_sssd_conf, smbconfig):
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
        client.service_ctrl('restart', 'sssd')
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

    @pytest.mark.tier3
    def test_004_multiplespn(self, multihost, keytab_sssd_conf, smbconfig):
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
        client.update_remote_conf('/etc/samba/smb.conf', 'global', {'sync machine password to keytab': '"/etc/krb5.keytab:account_name:spn_prefixes=HOST,host,HTTP,NFS:sync_spns:sync_kvno:machine_password"'})
        client.service_ctrl('restart', 'winbind')
        services_list = ['HTTP', 'NFS']
        client.add_service_principals(services_list)
        klist_cmd = "klist -k /etc/krb5.keytab"
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        realm = multihost.ad[0].realm
        hostname = multihost.client[0].sys_hostname
        remove_logs = "rm -f /var/log/sssd/sssd_%s.log" % (domain_name)
        multihost.client[0].run_command(remove_logs)
        https_princ = 'HTTP/%s@%s' % (hostname, realm)
        kvno_cmd = 'kvno %s' % (https_princ)
        cmd = multihost.client[0].run_command(kvno_cmd, raiseonerr=False)
        kvno = cmd.stdout_text.split('=')[1].strip()
        client.service_ctrl('restart', 'sssd')
        time.sleep(45)
        cmd = multihost.client[0].run_command(klist_cmd, raiseonerr=False)
        spn_list = [val.strip() for val in cmd.stdout_text.splitlines()]
        new_kvno = int(kvno) - 1
        nfs_entry = '{} {}/{}@{}'.format(new_kvno, 'NFS', hostname, realm)
        http_entry = '{} {}/{}@{}'.format(new_kvno, 'HTTP', hostname, realm)
        client.remove_service_principals(services_list)
        assert nfs_entry in spn_list[3:] and http_entry in spn_list[3:]
