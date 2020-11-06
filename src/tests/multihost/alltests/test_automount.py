""" Test cases for autofs responder """

from __future__ import print_function
import re
import subprocess
import time
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures("setup_sssd", "create_posix_usersgroups",
                         "enable_autofs_schema", "enable_autofs_service")
@pytest.mark.automount
class Testautofsresponder(object):
    """ Autofs responder test cases
        @setup
        1. Configure nfs server exporting /export
        2. Load autofs maps to Directory Server under
           ou=automout,dc=example,dc=test
        3. Add an nisMapEntry in automount specifying nfs server,
           directory and file system(nfs)
        4. Join RHEL7 client to Windows AD using realm
    """
    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier1
    def test_001_searchbasedn(self, multihost, add_nisobject):
        """
        @Title: IDM-SSSD-TC: LDAP-Provider Automount: Verify automount rules
        are searched from basedn

        1. Edit sssd.conf and specify autofs_provider = ldap and restart autofs

        @Steps:
        1. Access /export share

        @expectedResults:
        1. /export share should be mounted successfully
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
        @Title: IDM-SSSD-TC: ldap-Provider Automount: Verify automount
        maps are retrieved from cache when sssd is offline

        @Setup:
        1. Edit sssd.conf and specify autofs_provider = ldap
        2. Restart Autofs

        @Steps:
        1. pkill -USR1 sssd
        2. access /export/nfs-test

        @expectedResults:
        1. sssd should be offline
        2. /export/nfs-test share should be accessible from client
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
        @Title: IDM-SSSD-TC: ldap-Provider Automount: Verify automount
        rules are searched when ldap_autofs_search_base is set

        @Setup
        1. Edit sssd.conf and specify below parameters: autofs_provider = ldap
           ldap_autofs_search_base = ou=automount,dc=example,dc=test
        2. Restart sssd

        @Steps:
        1. Execute automount -m
        2. Access /export shared

        @expectedResults:
        1. automount -m should succeed and show maps from AD
        2. client is able mount nfs share /export
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
        @Title: IDM-SSSD-TC: ldap-Provider Automount: Verify maps are
        loaded from cache and maps are accessible when autofs_provider is None

        1. Set autofs_provider = None

        @Steps:
        1. Restart sssd service
        2. Execute automount -m
        3. Run ls -l /export/nfs-share

        @expectedResults:
        1. sssd service should be started successfully
        2. automount -m should execute successfully
        3. /export/nfs-share should be accessible
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
        @Title: IDM-SSSD-TC: ldap-Provider Automount: Verify automount maps are
        loaded from Directory Server when autofs provider is not set
        in sssd.conf

        1. Make sure autofs_provider is not set in sssd.conf,

        @Steps:
        1. Access nfs share /export/nfs-test

        @expectedResults:
        1. Verify automount maps are loaded from AD and client is able to
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
        @Title: IDM-SSSD-TC: ldap-Provider Automount: Verify sssd properly
        updates cache when automount maps are updated with more entries
        in Directory server

        1. Add /project1 entry to auto.direct map
        2. Restart autofs

        @Steps:
        1. Access /project1 nfs share

        @expectedResults:
        1. Verify /project1 can be mounted on nfs client

        """
        # pylint: disable=unused-argument
        nfstest = '/project1/project1-test'
        create_nfsfile = 'touch %s' % nfstest
        multihost.master[0].run_command(create_nfsfile)
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("Failed to restart %s" % service)
        automount = 'automount -m'
        cmd = multihost.client[0].run_command(automount, raiseonerr=False)
        assert cmd.returncode == 0
        nfstest = 'ls -l %s' % nfstest
        cmd = multihost.client[0].run_command(nfstest, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_007_1206221(self, multihost, set_dslimits, indirect_nismaps):
        """
        @Title: automount: sssd should not always read
        entire autofs map from ldap
        setup:
        1. Add Indirect map auto.idmtest which has mount point keys
           from foo1 to foo20 pointing to /projects/foo1 to /projects/foo20
        2. Set sizelimit to 10 on Directory server.

        Verify all the map keys are accessible
        """
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("Failed to restart %s" % service)
        count = 0
        for i in range(1, 20):
            path = '/idmtest/foo%d' % (i)
            list_dir = 'ls -l %s' % (path)
            cmd = multihost.client[0].run_command(list_dir, raiseonerr=False)
            if cmd.returncode != 0:
                count += 1
        assert count == 0

    @pytest.mark.tier2
    def test_008_wildcardsearch(self, multihost, indirect_nismaps,
                                set_ldap_uri):
        """
        @Title: automount: sssd should not use wildcard
        search to fetch map keys
        setup:
        1. Add Indirect map auto.idmtest which has mount point keys
           from foo1 to foo20 pointing to /projects/foo1 to /projects/foo20
        Verify sssd doesn't use (cn=*)(objectclass=nisObject)
        """
        auto_pcapfile = '/tmp/automount.pcap'
        ldap_host = multihost.master[0].sys_hostname
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, auto_pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        # pid_cmd = 'pidof tcpdump'
        # pid = multihost.client[0].run_command(pid_cmd, raiseonerr=False)
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                multihost.client[0].run_command(journalctl_cmd)
                pytest.fail("Failed to restart %s" % service)
        count = 0
        for i in range(1, 20):
            path = '/idmtest/foo%d' % (i)
            list_dir = 'ls -l %s' % (path)
            cmd = multihost.client[0].run_command(list_dir, raiseonerr=False)
            if cmd.returncode != 0:
                count += 1
        assert count == 0
        kill_cmd = 'pkill tcpdump'
        multihost.client[0].run_command(kill_cmd)
        # get the pcap file in text format
        conv_text = 'tshark -r %s -R ldap.filter'\
                    ' -V -2 > /tmp/automount.txt' % (auto_pcapfile)
        multihost.client[0].run_command(conv_text, raiseonerr=False)
        # get the file
        multihost.client[0].transport.get_file('/tmp/automount.txt',
                                               '/tmp/automount.txt')
        with open('/tmp/automount.txt', 'r') as outfile:
            tcpdump_ascii = outfile.read()
        for i in range(1, 10):
            key = 'foo%d' % i
            ldap_filter = '\(\&\(cn=%s\)\(objectclass=nisObject\)\)' % key
            log_1 = re.compile(r'%s' % (ldap_filter))
            assert log_1.search(tcpdump_ascii)

        # delete the pcap file
        del_pcap = 'rm -f %s' % auto_pcapfile
        multihost.client[0].run_command(del_pcap)
