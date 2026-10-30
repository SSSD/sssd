""" Automation of configuration validation

:requirement: IDM-SSSD-REQ: Configuration validation
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import pytest
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.configvalidation
class TestConfigValidation(object):
    """ SSSD Config Validation """
    @pytest.mark.tier1
    def test_0020_fatalerror(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: No sssctl commands can
         be run if the configuration has fatal errors
        :id: b483e14b-b263-4e4b-a6f7-539badc76aa4
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b' ', sssdcfg)
        sssdcfg1 = re.sub(b'id_provider',
                          b'sd_provider', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg1)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'ldap_search_base.\sis\snot allowed\sin\ssection\s'
                         r'.sssd.*')
        assert log.search(cmd.stdout_text)
