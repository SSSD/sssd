""" Tests for Memcache for SIDs

:requirement: Memory cache for SID
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('joinad')
@pytest.mark.tier1_3
@pytest.mark.memcachesid
class Testmemcachesid(object):
    def test_0001_memcache_sid(self, multihost):
        """
        :title: Verify memcache for SID
        :id: f7fce9c5-5ba6-428b-8e9b-5e07a88b5050
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1245367
        :customerscenario: true
        :steps:
          1. get uid of user
          2. get gid of group
          3. Clear sssd cache
          4. Lookup sid-by-uid with pysss_nss_idmap
          5. Lookup sid-by-uid with pysss_nss_idmap again
          6. Lookup sid-by-gid with pysss_nss_idmap
          7. Lookup sid-by-gid with pysss_nss_idmap again
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Lookup should run through nss responder
          5. Lookup should read from memory cache of SID
          6. Lookup should run through nss responder
          7. Lookup should read from memory cache of SID
        """
        req_pkg = 'yum install -y strace python3-libsss_nss_idmap'
        multihost.client[0].run_command(req_pkg)
        ad_domain = multihost.ad[0].domainname
        ad_user = f'user2@{ad_domain}'
        ad_group = f'group2@{ad_domain}'
        lookup_cmd_user = f'id -u {ad_user}'
        cmd = multihost.client[0].run_command(lookup_cmd_user)
        ad_uid = cmd.stdout_text.rstrip()
        lookup_cmd_group = f'getent group {ad_group} | cut -f3 -d:'
        cmd = multihost.client[0].run_command(lookup_cmd_group)
        ad_gid = cmd.stdout_text.rstrip()
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.clear_sssd_cache()
        file_dict = {'getsidbyuid': ad_uid, 'getsidbygid': ad_gid}
        for k, v in file_dict.items():
            run_args = f'python3 -c "import pysss_nss_idmap;pysss_nss_idmap.{k}({v})"'

            for i in 'before', 'after':
                strace_file = f'/opt/{k}_{i}.trace'
                cmd = f'strace -fxvto {strace_file} {run_args}'
                multihost.client[0].run_command(cmd)
                cmd = f'grep /var/lib/sss/pipes/nss {strace_file}'
                chk_log = multihost.client[0].run_command(cmd, raiseonerr=False)
                rm_cmd = f'rm -f {strace_file}'
                multihost.client[0].run_command(rm_cmd)
                if i == 'before':
                    assert chk_log.returncode == 0
                if i == 'after':
                    assert chk_log.returncode == 1
