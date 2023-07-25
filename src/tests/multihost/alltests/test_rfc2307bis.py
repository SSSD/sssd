""" Automation of rfc2307bis

:requirement: rfc2307bis
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import os
import re
import posixpath
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name

@pytest.mark.usefixtures('setup_sssd')
@pytest.mark.rfc2307bis
class Testrfc2307bis(object):
    """
    This is test case class for ldap rfc2307bis
        :setup:
          1. Configure SSSD to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
    """
    @staticmethod
    @pytest.mark.tier1_4
    def test_0001_tevent_loop_never_finished(multihost, backupsssdconf):
        """
        :title: rfc2307bis: tevent_loop_wait() never finishes
        :id: 253ecc50-5fd6-4326-9cb4-9ae68bd07067
        :description: If a signal handler is registered and unregistered
         later, tevent_loop_wait() never finishes.
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=978962
          https://bugzilla.redhat.com/show_bug.cgi?id=994015
        :setup:
          tevent_loop.c is available in /tmp/ directory on client system
        :steps:
          1. Compile tevent_loop.c with gcc
          2. Run the binary file a.out, created from compiling tevent_loop.c, and
             capture the output of a.out in tevent_loop_output
          3. Assert 'We got through the loop' string in tevent_loop_output
        :expectedresults:
          1. Compilation should succeed
          2. The binary a.out should run successfully and output of it
             shouls be captured in tevent_loop_output
          3. The tevent_loop_output should contain 'We got through the loop'
          """
        tools = sssdTools(multihost.client[0])
        section = f'domain/{ds_instance_name}'
        params = {'ldap_schema': 'rfc2307bis'}
        tools.sssd_conf(section, params, action='update')
        tools.clear_sssd_cache()
        multihost.client[0].run_command('dnf --enablerepo=*-CRB install -y libtevent-devel', raiseonerr=False)
        cwd = os.path.dirname(os.path.abspath(__file__))
        source = posixpath.join(cwd, 'script/tevent_loop.c')
        multihost.client[0].transport.put_file(source, '/tmp/tevent_loop.c')
        multihost.client[0].run_command('gcc -ltalloc -ltevent /tmp/tevent_loop.c -o /tmp/a.out', raiseonerr=False)
        multihost.client[0].run_command('/tmp/a.out > /tmp/tevent_loop_output', raiseonerr=False)
        output = multihost.client[0].get_file_contents('/tmp/tevent_loop_output').decode('utf-8')
        log = re.compile(r'We got through the loop')
        assert log.search(output)
