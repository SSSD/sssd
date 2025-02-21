""" Test cases for autofs responder

:requirement: Ldap Provider - automount
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import subprocess
import time
import pytest
from constants import ds_instance_name
from sssd.testlib.common.utils import sssdTools, LdapOperations

JOURNALCTL_CMD = "journalctl -x -n 50 --no-pager"


def restart_autofs(multihost):
    for _ in range(1, 20):
        cmd = multihost.client[0].run_command("systemctl restart autofs", raiseonerr=False).returncode
        if cmd == 0:
            break
        time.sleep(10)
    else:
        raise Exception("autofs restart failed too many times")


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
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            srv = 'systemctl restart %s' % service
            try:
                multihost.client[0].run_command(srv)
            except subprocess.CalledProcessError:
                multihost.client[0].run_command(JOURNALCTL_CMD)
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

    @pytest.mark.tier1_2
    def test_two_automount_maps(self, multihost,
                                backupsssdconf):
        """
        :title: Automount sssd issue when 2 maps have same key in
         different case
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1873715
        :id: d28e6eec-ac9f-11eb-b0f5-002b677efe14
        :customerscenario: true
        :steps:
            1. Configure SSSD with autofs, automountMap,
               automount, automountInformation
            2. Add 2 automount entries in LDAP with
               same key ( cn: MIT and cn: mit)
            3. We should have the 2 automounts working
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        client = sssdTools(multihost.client[0])
        domain_params = {'services': 'nss, pam, autofs'}
        client.sssd_conf('sssd', domain_params)
        domain_params = {
            'ldap_autofs_map_object_class': 'automountMap',
            'ldap_autofs_map_name': 'ou',
            'ldap_autofs_entry_object_class': 'automount',
            'ldap_autofs_entry_key': 'cn',
            'ldap_autofs_entry_value': 'automountInformation'}
        client.sssd_conf(f'domain/{domain_name}', domain_params)
        multihost.client[0].service_sssd('restart')
        share_list = ['/export', '/export1', '/export2']
        nfs_server_ip = multihost.master[0].ip
        client_ip = multihost.client[0].ip
        server = sssdTools(multihost.master[0])
        bkup = 'cp -af /etc/exports /etc/exports.backup'
        multihost.master[0].run_command(bkup)
        server.export_nfs_fs(share_list, client_ip)
        search = multihost.master[0].run_command("grep 'fsid=0' "
                                                 "/etc/exports")
        if search.returncode == 0:
            multihost.master[0].run_command("sed -i 's/,fsid=0//g' "
                                            "/etc/exports")
        start_nfs = 'systemctl start nfs-server'
        multihost.master[0].run_command(start_nfs)
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        for ou_ou in ['auto.master', 'auto.direct', 'auto.home']:
            user_info = {'ou': f'{ou_ou}'.encode('utf-8'),
                         'objectClass': [b'top', b'automountMap']}
            user_dn = f'ou={ou_ou},dc=example,dc=test'
            (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {'cn': '/-'.encode('utf-8'),
                     'objectClass': [b'top', b'automount'],
                     'automountInformation': 'auto.direct'.encode('utf-8')}
        user_dn = 'cn=/-,ou=auto.master,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {'cn': '/home'.encode('utf-8'),
                     'objectClass': [b'top', b'automount'],
                     'automountInformation': 'auto.home'.encode('utf-8')}
        user_dn = 'cn=/home,ou=auto.master,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {'cn': 'MIT'.encode('utf-8'),
                     'objectClass': [b'top', b'automount']}
        user_dn = f'automountinformation={nfs_server_ip}:/export1,' \
                  f'ou=auto.home,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        user_info = {'cn': 'mit'.encode('utf-8'),
                     'objectClass': [b'top', b'automount']}
        user_dn = f'automountinformation={nfs_server_ip}:/export2,' \
                  f'ou=auto.home,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        multihost.client[0].run_command("systemctl stop sssd ; "
                                        "rm -rf /var/log/sssd/* ; "
                                        "rm -rf /var/lib/sss/db/* ; "
                                        "systemctl start sssd")
        time.sleep(10)
        restart_autofs(multihost)
        multihost.client[0].run_command("automount -m")
        multihost.master[0].run_command("touch /export1/export1")
        multihost.master[0].run_command("touch /export2/export2")
        time.sleep(2)
        MIT_export = multihost.client[0].run_command("ls /home/MIT")
        mit_export = multihost.client[0].run_command("ls /home/mit")
        restore = 'cp -af /etc/exports.backup /etc/exports'
        multihost.master[0].run_command(restore)
        multihost.client[0].run_command("systemctl stop autofs", raiseonerr=False)
        stop_nfs = 'systemctl stop nfs-server'
        multihost.master[0].run_command(stop_nfs)
        for dn_dn in [f'automountinformation={nfs_server_ip}:/export1,'
                      f'ou=auto.home,dc=example,dc=test',
                      f'automountinformation={nfs_server_ip}:/export2,'
                      f'ou=auto.home,dc=example,dc=test',
                      'cn=/-,ou=auto.master,dc=example,dc=test',
                      'cn=/home,ou=auto.master,dc=example,dc=test',
                      'ou=auto.master,dc=example,dc=test',
                      'ou=auto.direct,dc=example,dc=test',
                      'ou=auto.home,dc=example,dc=test']:
            multihost.master[0].run_command(f'ldapdelete -x -D '
                                            f'"cn=Directory Manager" '
                                            f'-w Secret123 -H ldap:// {dn_dn}')
        assert 'export1' in MIT_export.stdout_text
        assert 'export2' in mit_export.stdout_text

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
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                multihost.client[0].run_command(JOURNALCTL_CMD)
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
                multihost.client[0].run_command(JOURNALCTL_CMD)
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
                multihost.client[0].run_command(JOURNALCTL_CMD)
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
        tools = sssdTools(multihost.client[0])
        # 'sssd_be' talks to LDAP server via network, to make it human read able
        # SSSD needs to set ldap_id_use_start_tls
        ldap_params = {'ldap_id_use_start_tls': False}
        tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
        for service in ['sssd', 'autofs']:
            restart = 'systemctl restart %s' % service
            cmd = multihost.client[0].run_command(restart, raiseonerr=False)
            if cmd.returncode != 0:
                multihost.client[0].run_command(JOURNALCTL_CMD)
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
        multihost.client[0].run_command(kill_cmd, raiseonerr=False)
        # get the pcap file in text format
        conv_text = 'tshark -r %s -R ldap.filter -V -2 > /tmp/automount.txt' % (auto_pcapfile)
        multihost.client[0].run_command(conv_text, raiseonerr=False)
        # get the file
        tcpdump_ascii = multihost.client[0].get_file_contents(f'/tmp/automount.txt').decode('utf-8')
        for i in range(1, 10):
            key = 'foo%d' % i
            ldap_filter = r'\(\&\(cn=%s\)\(objectclass=nisObject\)\)' % key
            log_1 = re.compile(r'%s' % (ldap_filter))
            assert log_1.search(tcpdump_ascii)

        # delete the pcap file
        del_pcap = 'rm -f %s' % auto_pcapfile
        multihost.client[0].run_command(del_pcap)

    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier2
    def test_009_maps_after_coming_online(self, multihost, add_nisobject):
        """
        :title: fetch autofs map after coming online from offline
        :id: b9da6e0e-3d8b-4465-b435-338708d0d51e
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1113639
        :customerscenario: True
        :steps:
          1. edit sssd.conf and specify autofs_provider = ad
          2. restart autofs
          3. firewalld block 389 and 636
          4. stop sssd, autofs.
          5. remove sssd cache
          6. Start sssd
          7. remove firewall rule
          8. start autofs
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
          8. Should succeed
        """
        multihost.master[0].run_command(['touch', '/export/nfs-test'])
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        for service in ['sssd', 'autofs']:
            client.service_ctrl("stop", service)
        client.service_ctrl("start", "firewalld")
        multihost.client[0].run_command("iptables -A "
                                        "OUTPUT -p tcp "
                                        "--dport 636 -j DROP")
        multihost.client[0].run_command("iptables -A "
                                        "OUTPUT -p tcp "
                                        "--dport 389 -j DROP")
        client.clear_sssd_cache()
        time.sleep(5)
        cmdy = 'id foo1@%s' % domain_name
        multihost.client[0].run_command(cmdy, raiseonerr=False)
        cmd = 'sssctl domain-status %s' % domain_name
        cmd1 = multihost.client[0].run_command(cmd, raiseonerr=False)
        find = re.compile(r'Online status: Offline')
        result = find.search(cmd1.stdout_text)
        assert result is not None
        client.firewall_port(636, 'OPEN')
        client.firewall_port(389, 'OPEN')
        client.firewall_port('ALL', 'delall')
        client.service_ctrl("stop", "firewalld")
        multihost.client[0].run_command("iptables -F")
        time.sleep(60)
        cmd2 = client.service_ctrl("start", "autofs")
        assert cmd2 == 0

    @pytest.mark.parametrize('add_nisobject', ['/export'], indirect=True)
    @pytest.mark.tier1
    def test_010_delay_in_unknown_mnt_pt_lookup_error(self, multihost,
                                                      add_nisobject):
        """
        :title: IDM-SSSD-TC: LDAP-Provider: Automount: autofs lookups for
         unknown mounts are delayed for 50s
        :id: 74cf1842-a8a0-4b6c-9670-82d73eb8ec6d
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2013218
        :customerscenario: true
        :steps:
          1. Edit sssd.conf and specify autofs_provider = ldap and restart
             autofs
          2. Access /export share
          3. Access Non-existen mount point
        :expectedresults:
          1. Should succeed
          2. /export share should be mounted successfully
          3. Error for Non-existent share should appear immediately
        """
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
        nfs_test = 'stat /export/nfs-test'
        cmd = multihost.client[0].run_command(nfs_test, raiseonerr=False)
        assert cmd.returncode == 0
        nfs_test = 'time stat /export/non_existing_nfs'
        tm1 = time.time()
        cmd = multihost.client[0].run_command(nfs_test, raiseonerr=False)
        tm2 = time.time()
        assert cmd.returncode != 0 and tm2 - tm1 <= 4
