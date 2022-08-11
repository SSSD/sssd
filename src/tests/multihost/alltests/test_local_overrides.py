""" Automation of localoverrides suite

:requirement: local_overrides
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.localoverrides
class TestLocalOverrides(object):
    """
    This is test case class for local overrides suite
    """
    @pytest.mark.tier1_2
    def test_0001_bz1919942(self, multihost,
                            backupsssdconf):
        """
        :title: ifp: sss_override does not take
         precedence over override_homedir directive
        :id: d2e98c70-26a0-11ec-bcf5-845cf3eff344
        :customerscenario: true
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1919942
        :steps:
          1. Edit sssd.conf and set homedir, i.e.
             `override_homedir = /home/%u1`
          2. Restart sssd and check homedir
          3. Use `sss_override` to set a
             different home directory
          4. Restart sssd and use getent command
             to check home directory, which is still set to same.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        client = sssdTools(multihost.client[0])
        domain_params = {'override_homedir': '/home/%u1'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        multihost.client[0].service_sssd('restart')
        before = multihost.client[0].run_command("getent passwd "
                                                 "foo5@example1")
        assert before.returncode == 0
        multihost.client[0].run_command("sss_override "
                                        "user-add foo5@example1 -h "
                                        "/home/foo56")
        multihost.client[0].service_sssd('restart')
        after = multihost.client[0].run_command("getent passwd "
                                                "foo5@example1")
        assert "User:/home/foo56" in after.stdout_text
