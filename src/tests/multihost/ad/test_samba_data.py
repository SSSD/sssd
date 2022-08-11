""" Automation for RFE related to --add-samba-data to adcli

:casecomponent: sssd
:requirement: Add support for passing --add-samba-data to adcli
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import subprocess
import time
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('winbind_server', 'configure_samba')
@pytest.mark.smbsecretrotation
class Testsmbsecretrotation(object):

    @pytest.mark.tier2
    def test_0001_rotation(self, multihost):
        """
        :title: Verify machine passwd updates local smb secrets
        :id: 3d08ea1c-6724-4bc9-ac62-b8be66486ee4
        """
        # Get current hash of /var/lib/samba/private/secrets.tdb
        hash_cmd = 'sha1hmac /var/lib/samba/private/secrets.tdb'
        cmd = multihost.client[0].run_command(hash_cmd, raiseonerr=False)
        before_hash = cmd.stdout_text.strip()
        print("hash before reseting machine passwd", before_hash)
        stat = 'stat /var/lib/samba/private/secrets.tdb'
        cmd = multihost.client[0].run_command(stat, raiseonerr=False)
        # Get tdb-dump
        tdbdump = 'tdbdump /var/lib/samba/private/secrets.tdb'
        multihost.client[0].run_command(tdbdump, raiseonerr=False)
        client = sssdTools(multihost.client[0], multihost.ad[0])
        sssd_params = {'ad_maximum_machine_account_password_age': '1',
                       'ad_machine_account_password_renewal_opts': '300:15',
                       'ad_update_samba_machine_account_password': 'True',
                       'debug_level': '9'}
        domain_name = client.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain_name)
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
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
        ls = 'cat /etc/sssd/sssd.conf'
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
        entry_1 = '{} {}/{}@{}'.format(old_kvno, 'host', client_domain,
                                       multihost.ad[0].realm)
        # new entry
        entry_2 = '{} {}/{}@{}'.format(new_kvno, 'host', client_domain,
                                       multihost.ad[0].realm)
        if entry_1 and entry_2 not in spn_list[3:]:
            pytest.fail("keytab rotation failed, host entries not rotated")
        cmd = multihost.client[0].run_command(hash_cmd, raiseonerr=False)
        after_hash = cmd.stdout_text.strip()
        print("hash after reseting machine passwd", after_hash)
        cmd = multihost.client[0].run_command(stat, raiseonerr=False)
        logs = "tail -n 500 /var/log/sssd/sssd_%s.log" % domain_name
        multihost.client[0].run_command(logs, raiseonerr=False)
        multihost.client[0].run_command(tdbdump, raiseonerr=False)
