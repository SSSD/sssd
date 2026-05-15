""" Automation of Netgroup suite

:requirement: netgroup
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import time
import ldap
import pytest
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_instance_name, ds_suffix


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups', 'netgroups')
@pytest.mark.netgroup
class TestNetgroup(object):

    @pytest.mark.tier1
    def test_0001_bz1502686(self, multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: netgroup: SSSD crashes in nss
         responder after netgroup timeout when backend is offline
        :id: 2e5823a2-835b-45fd-a2be-36b20856e726
        :customerscenario: True
        """
        hostname = multihost.master[0].sys_hostname
        bad_ldap_uri = "ldaps://typo.%s" % hostname
        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        bkupconf = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.bkup'
        restoreconf = 'cp -f /etc/sssd/sssd.conf.bkup /etc/sssd/sssd.conf'
        remove_bkup = 'rm -f /etc/sssd/sssd.conf.bkup'
        multihost.client[0].run_command(bkupconf)
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        domain_params = {'ldap_uri': bad_ldap_uri}
        tools.sssd_conf('domain/%s' % ds_instance_name, domain_params)
        start = multihost.client[0].service_sssd('start')
        # Check backend status
        domain_status = "sssctl domain-status %s -o" % ds_instance_name
        chk_status = multihost.client[0].run_command(domain_status,
                                                     raiseonerr=False)
        if 'Offline' in chk_status.stdout_text.strip():
            status = 'PASS'
        pid_nss = "pidof sssd_nss"
        chk_pid1 = multihost.client[0].run_command(pid_nss, raiseonerr=False)
        pid_nss1 = chk_pid1.stdout_text.strip()
        if start == 0:
            # request for netgroup
            getent = 'getent netgroup -s sss netgroup_1'
            chk_req = multihost.client[0].run_command(getent, raiseonerr=False)
            if chk_req.returncode != 2:
                status = 'FAIL'
            time.sleep(16)
            sssd_proc = ['sssd', 'sssd_be', 'sssd_nss', 'sssd_pam']
            for proc in sssd_proc:
                pgrep = 'pgrep %s' % proc
                cmd = multihost.client[0].run_command(pgrep, raiseonerr=False)
                if cmd.returncode != 0:
                    status = 'FAIL'
                    print("%s process failed to start" % proc)
                else:
                    pid2 = multihost.client[0].run_command(pid_nss)
                    # automation of bz1576852
                    pid_nss2 = pid2.stdout_text.strip()
                    if pid_nss1 != pid_nss2:
                        status = 'FAIL'
                        print("nss process crashed and restarted")
                    else:
                        status = 'PASS'
            multihost.client[0].run_command(restoreconf)
            multihost.client[0].run_command(remove_bkup)
            assert status != 'FAIL'

    @pytest.mark.tier1
    def test_0002_bz1406437(self, multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: netgroup: sssctl netgroup-show
         Cannot allocate memory
        :id: bdcf03d6-fe5d-44fd-9517-f812dacaf6af
        """
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        tools.remove_sss_cache('/var/lib/sss/db')
        multihost.client[0].service_sssd('start')
        time.sleep(10)
        getent = 'getent netgroup netgroup_1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(getent, raiseonerr=False)
        assert cmd.returncode == 0
        sssctl = 'sssctl netgroup-show netgroup_1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(sssctl, raiseonerr=False)
        if cmd.returncode == 0:
            search = 'Cannot allocate memory'
            out = cmd.stdout_text
            assert out.find(search) == -1
        else:
            pytest.fail("%s failed" % sssctl)

    @pytest.mark.tier1
    def test_0003_background_refresh(self, multihost):
        """
        :title: netgroup: background refresh task does not refresh
         updated netgroup entries
        :id: b17d904d-0d64-4f4a-bbad-4c7f63e1faf2
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1779486 (RHEL8.2)
         https://bugzilla.redhat.com/show_bug.cgi?id=1822461 (RHEL7.8)
        """
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        tools.remove_sss_cache('/var/lib/sss/db')
        domain_params = {'entry_cache_timeout': '30',
                         'refresh_expired_interval': '22'}
        tools.sssd_conf('domain/%s' % ds_instance_name, domain_params)
        multihost.client[0].service_sssd('restart')
        # getent netgroup_1
        getent_cmd = "getent netgroup netgroup_1"
        multihost.client[0].run_command(getent_cmd)
        shortname = multihost.client[0].sys_hostname.strip().split('.')[0]
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        netgroup_dn = 'cn=netgroup_1,ou=Netgroups,%s' % (ds_suffix)
        nisNetgroupTriple = "(%s,foo1,%s)" % (shortname, ds_suffix)
        modify_netgroup = [(ldap.MOD_REPLACE, 'nisNetgroupTriple',
                            nisNetgroupTriple.encode('utf-8'))]
        (_, _) = ldap_inst.modify_ldap(netgroup_dn, modify_netgroup)
        time.sleep(40)
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb'\
                  ' -b cn=Netgroups,cn=%s,cn=sysdb' % (ds_instance_name,
                                                       ds_instance_name)
        cmd = multihost.client[0].run_command(ldb_cmd)
        new_entry = "netgroupTriple: (%s,foo1,%s)" % (shortname, ds_suffix)
        tools.sssd_conf('domain/%s' % ds_instance_name,
                        domain_params, action='delete')
        assert new_entry in cmd.stdout_text.strip().split('\n')
