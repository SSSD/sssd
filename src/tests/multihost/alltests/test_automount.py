""" Test cases for autofs responder

:requirement: Ldap Provider - automount
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

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

        :setup:
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
        :title: IDM-SSSD-TC: LDAP-Provider: Automount: Verify automount rules
         are searched from basedn
        :id: f0b8962d-446b-412e-959a-41182d906dbf
        :steps:
          1. Edit sssd.conf and specify autofs_provider = ldap and restart
             autofs
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
        :title: IDM-SSSD-TC: LDAP-Provider Automount: Verify automount
         maps are retrieved from cache when sssd is offline
        :id: 5e85710a-bd86-416b-82aa-10f254421381
        :steps:
          1. Edit sssd.conf and specify autofs_provider = ldap
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
        :title: IDM-SSSD-TC: LDAP-Provider Automount: Verify automount
         rules are searched when ldap_autofs_search_base is set
        :id: 76e7449e-226a-47c5-bc7f-0bb6b9e749e7
        :steps:
          1. Edit sssd.conf and specify below parameters:
             autofs_provider = ldap
             ldap_autofs_search_base = ou=automount,dc=example,dc=test
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
        :title: IDM-SSSD-TC: LDAP-Provider Automount: Verify maps are
         loaded from cache and maps are accessible when autofs_provider is None
        :id: 67daac8b-c7c2-4dca-8331-5e95fd21b483
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
        :title: IDM-SSSD-TC: LDAP-Provider: Automount: Verify automount maps
         are loaded from Directory Server when autofs provider is not set
         in sssd.conf
        :id: 3d93a51c-332c-4a88-af68-71a92e8a1b8e
        :steps:
          1. Access nfs share /export/nfs-test with autofs provider not set
        :expectedresults:
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
        :title: IDM-SSSD-TC: LDAP-Provider Automount: Verify sssd properly
         updates cache when automount maps are updated with more entries
         in Directory server
        :id: 0509a594-bd7a-45d6-b40b-4efcdc6b27f0
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
        :title: automount: sssd should not always read
         entire autofs map from ldap
        :id: e79723ce-ad26-44ae-82ff-1afaae22f188
        :customerscenario: True
        :steps:
          1. Add Indirect map auto.idmtest which has mount point keys
             from foo1 to foo20 pointing to /projects/foo1 to /projects/foo20
          2. Set sizelimit to 10 on Directory server.
        :expectedresults:
          1. Should succeed
          2. Verify all the map keys are accessible
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
        :title: automount: sssd should not use wildcard
         search to fetch map keys
        :id: 92640015-52b9-4e76-9e63-ea7357eec9cd
        :steps:
          1. Add Indirect map auto.idmtest which has mount point keys
           from foo1 to foo20 pointing to /projects/foo1 to /projects/foo20
        :expectedresults:
          1. Verify sssd doesn't use (cn=*)(objectclass=nisObject)
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

    @pytest.mark.tier2
    def test_009_maps_after_coming_online(self, multihost, add_nisobject):
        """
        :title: IDM-SSSD-TC: ldap-Provider Automount: Without eisting cache
          when sssd comes to online state from offline, autofs maps are fetched
          without a restart
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1113639

        :setup:
          1. edit sssd.conf and specify autofs_provider = ad
          2. restart autofs

        :steps:
          1. firewalld block 389 and 636
          2. stop sssd, autofs.
          3. remove sssd cache
          4. Start sssd
          5. remove firewall rule
          6. start autofs

        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
        """
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        for service in ['sssd', 'autofs']:
            client.service_ctrl("stop", service)
        client.service_ctrl("start", "firewalld")
        client.firewall_port(636, 'BLOCK')
        client.firewall_port(389, 'BLOCK')
        client.firewall_port('ALL', 'allowall')
        client.clear_sssd_cache()
        time.sleep(5)
        cmdy = 'id foo1@%s' % domain_name
        multihost.client[0].run_command(cmdy, raiseonerr=False)
        cmd = 'sssctl domain-status %s' % domain_name
        cmd1 = multihost.client[0].run_command(cmd, raiseonerr=False)
        find = re.compile(r'Online status: Offline')
        result = find.search(cmd1.stdout_text)
        assert result is not None
        cmdz = cmd1.stdout_text
        client.firewall_port(636, 'OPEN')
        client.firewall_port(389, 'OPEN')
        client.firewall_port('ALL', 'delall')
        client.service_ctrl("stop", "firewalld")
        time.sleep(60)
        cmd2 = client.service_ctrl("start", "autofs")
        cmd = 'dnf remove -y firewalld'
        multihost.client[0].run_command(cmd, raiseonerr=True)
        assert cmd2 == 0
