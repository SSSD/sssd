""" Automation of sssd nss suite

:requirement: IDM-SSSD-REQ : Configuration and Service Management
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import time
import os
import re
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.usefixtures('setup_sssd')
@pytest.mark.tier1_3
class TestSssdNss(object):
    """
    This is test case class for sssd nss suite
    """
    def test_avoid_interlocking_among_threads(self, multihost,
                                              backupsssdconf):
        """
        :title: avoid interlocking among threads that use
          `libsss_nss_idmap` API (or other sss_client libs)
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1978119
        :id: 836759ee-fc19-11ec-b57d-845cf3eff344
        :customerscenario: true
        :steps:
            1. Configure sssd with nss
            2. Create multiple tread from single process
            3. Check that requests are not being handled serially
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        version_fedora = 0
        version_rel_cent = 0
        if "Fedora" in multihost.client[0].distro:
            version_fedora = int(re.search(r'\d+', multihost.client[0].distro).group())
        else:
            version_rel_cent = float(re.findall(r"\d+\.\d+", multihost.client[0].distro)[0])
        if version_rel_cent < 9 and version_fedora < 35:
            pytest.skip("unsupported configuration")
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        services = {'debug_level': '9'}
        tools.sssd_conf('nss', services)
        tools.clear_sssd_cache()
        client = multihost.client[0]
        client.run_command("yum install -y gcc")
        file_location = '/script/thread.c'
        client.transport.put_file(os.path.dirname(os.path.abspath(__file__))
                                  + file_location,
                                  '/tmp/thread.c')
        execute_cmd(multihost, "gcc -lpthread /tmp/thread.c -o /tmp/thread")
        execute_cmd(multihost, ">/var/log/sssd/sssd_nss.log")
        execute_cmd(multihost, "chmod 755 /tmp/thread")
        execute_cmd(multihost, "cd /tmp/; ./thread")
        time.sleep(2)
        cmd = execute_cmd(multihost, "grep 'Looking up' "
                                     "/var/log/sssd/sssd_nss.log").stdout_text
        crs = [int(i.split('#')[1]) for i in re.findall('CR #[0-9]+', cmd)]
        assert sorted(crs) != crs
