""" Test cases for autofs responder

:requirement: AD Provider - automount
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


@pytest.mark.usefixtures("enable_autofs_schema", "enable_autofs_service")
@pytest.mark.automount
class Testautofsresponder(object):
    """ Autofs responder test cases

    :setup:
      1. Configure nfs server exporting /export
      2. Load autofs maps to Active Directory under
         ou=automout,dc=<ad-domain>,dc=test
      3. Add an nisMapEntry in automount specifying nfs server,
         directory and file system(nfs)
      4. Join RHEL7 client to Windows AD using realm
    """
    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier1
    def test_001_searchbasedn(self, multihost, add_nisobject):
        """
        :title: IDM-SSSD-TC: AD-Provider Automount: Verify automount rules
         are searched from basedn
        :id: 48baf5ef-3757-45fd-954d-93c94264f880
        :steps:
          1. Edit sssd.conf and specify autofs_provider = ad and restart autofs
          2. Access /export share
        :expectedresults:
          1. Should succeed
          2. /export share should be mounted successfully
        """
        # pylint: disable=unused-argument
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            srv = 'systemctl restart %s' % service
            try:
                multihost.client[0].run_command(srv)
            except subprocess.CalledProcessError:
                pytest.fail("Unable to start %s service" % service)
            time.sleep(5)
        try:
            multihost.client[0].run_command(['automount', '-m'])
        except subprocess.CalledProcessError:
            pytest.fail("automount -m command failed")
        nfs_test = 'ls -l /export/nfs-test'
        cmd = multihost.client[0].run_command(nfs_test, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier1
    def test_002_offline(self, multihost, add_nisobject):
        """
        :title: IDM-SSSD-TC: AD-Provider Automount: Verify automount
         maps are retrieved from cache when sssd is offline
        :id: 84f3c1ba-0321-4c3b-89c7-de90b4f32639
        :steps:
          1. Edit sssd.conf and specify autofs_provider = ad
          2. Restart Autofs
          3. pkill -USR1 sssd
          4. access /export/nfs-test
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. sssd should be offline
          4. /export/nfs-test share should be accessible from client
        """
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            srv = 'systemctl restart %s' % service
            try:
                multihost.client[0].run_command(srv)
            except subprocess.CalledProcessError:
                pytest.fail("Unable to start %s service" % service)
        time.sleep(30)
        automount = 'automount -m'
        try:
            multihost.client[0].run_command(automount)
        except subprocess.CalledProcessError:
            pytest.xfail("automount -m command failed")
        pkill_cmd = 'pkill -USR1 sssd'
        cmd = multihost.client[0].run_command(pkill_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        try:
            multihost.client[0].run_command(automount)
        except subprocess.CalledProcessError:
            pytest.fail("automount -m command failed")
        nfstest = 'ls -l /export/nfs-test'
        cmd = multihost.client[0].run_command(nfstest, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier1
    def test_003_setbasedn(self, multihost, set_autofs_search_base,
                           add_nisobject):
        """
        :title: IDM-SSSD-TC: AD-Provider Automount: Verify automount
         rules are searched when ldap_autofs_search_base is set
        :id: e8dbd94d-c557-4533-8ab7-bc891e1609a3
        :steps:
          1. Edit sssd.conf and specify below parameters: autofs_provider = ad
             ldap_autofs_search_base = ou=automount,dc=<ad-domain>
          2. Restart sssd
          3. Execute automount -m
          4. Access /export shared
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. automount -m should succeed and show maps from AD
          4. client is able mount nfs share /export
        """
        # pylint: disable=unused-argument
        journalctl_cmd = "journalctl -x -n 50 --no-pager"
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            srv = 'systemctl restart %s' % service
            try:
                multihost.client[0].run_command(srv)
            except subprocess.CalledProcessError:
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("Unable to start %s service" % service)
        time.sleep(30)
        try:
            multihost.client[0].run_command(['automount', '-m'])
        except subprocess.CalledProcessError:
            pytest.fail("automount -m command failed")
        nfs_test = 'ls -l /export/nfs-test'
        cmd = multihost.client[0].run_command(nfs_test, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier1
    def test_004_autofsnone(self, multihost, set_autofs_search_base,
                            add_nisobject):
        """
        :title: IDM-SSSD-TC: AD-Provider Automount: Verify maps are
         loaded from cache and maps are accessible when autofs_provider is None
        :id: 82e5a42d-a097-4604-bcd2-9e8af71bd511
        :steps:
          1. Set autofs_provider = None
          2. Restart sssd service
          3. Execute automount -m
          4. Run ls -l /export/nfs-share
        :expectedresults:
          1. Should succeed
          2. sssd service should be started successfully
          3. automount -m should execute successfully
          4. /export/nfs-share should be accessible
        """
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            srv = 'systemctl restart %s' % service
            try:
                multihost.client[0].run_command(srv)
            except subprocess.CalledProcessError:
                pytest.fail("Unable to start %s service" % service)
        time.sleep(30)
        try:
            multihost.client[0].run_command(['automount', '-m'])
        except subprocess.CalledProcessError:
            pytest.fail("automount -m command failed")
        nfs_test = 'ls -l /export/nfs-test'
        cmd = multihost.client[0].run_command(nfs_test, raiseonerr=False)
        assert cmd.returncode == 0
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        section = 'domain/{}'.format(domain_name)
        sssd_params = {'autofs_provider': 'none'}
        client.sssd_conf(section, sssd_params)
        srv = 'systemctl restart sssd'
        try:
            multihost.client[0].run_command(srv)
        except subprocess.CalledProcessError:
            pytest.fail("Unable to start sssd")
        time.sleep(10)
        try:
            multihost.client[0].run_command(['automount', '-m'])
        except subprocess.CalledProcessError:
            pytest.fail("automount -m command failed")
        cmd = multihost.client[0].run_command(nfs_test, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier2
    def test_005_autofsnotset(self, multihost, set_autofs_search_base,
                              add_nisobject):
        """
        :title: IDM-SSSD-TC: AD-Provider Automount: Verify automount maps are
         loaded from Active Directory when autofs provider is not set
         in sssd.conf
        :id: a05ac41a-6668-4cde-8109-498baa5300b6
        :steps:
          1. Make sure autofs_provider is not set in sssd.conf,
          2. Access nfs share /export/nfs-test
        :expectedresults:
          1. autofs_provider is not set
          2. Verify automount maps are loaded from AD and client is able to
             mount nfs share
        """
        # pylint: disable=unused-argument
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        section = 'domain/{}'.format(domain_name)
        sssd_params = {'autofs_provider': 'none'}
        client.sssd_conf(section, sssd_params, action='delete')
        journalctl_cmd = "journalctl -x -n 50 --no-pager"
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("Failed to restart %s" % service)
        automount = 'automount -m'
        cmd = multihost.client[0].run_command(automount, raiseonerr=False)
        assert cmd.returncode == 0
        nfstest = 'ls -l /export/nfs-test'
        cmd = multihost.client[0].run_command(nfstest, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.parametrize('add_nisobject', ['/project1'], indirect=True)
    @pytest.mark.tier2
    def test_006_updatedmaps(self, multihost, set_autofs_search_base,
                             add_nisobject):
        """
        :title: IDM-SSSD-TC: AD-Provider Automount: Verify sssd properly
         updates cache when automount maps are updated with more entries
         in Active Directory
        :id: b0e28b05-468a-438c-bf8f-044f1ec73b05
        :steps:
          1. Add /project1 entry to auto.direct map
          2. Restart autofs
          3. Access /project1 nfs share
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Verify /project1 can be mounted on nfs client
        """
        # pylint: disable=unused-argument
        nfstest = '/project1/project1-test'
        create_nfsfile = 'touch %s' % nfstest
        multihost.master[0].run_command(create_nfsfile)
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                journalctl_cmd = "journalctl -x -n 50 --no-pager"
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("Failed to restart %s" % service)
        automount = 'automount -m'
        cmd = multihost.client[0].run_command(automount, raiseonerr=False)
        assert cmd.returncode == 0
        nfstest = 'ls -l %s' % nfstest
        cmd = multihost.client[0].run_command(nfstest, raiseonerr=False)
        assert cmd.returncode == 0
