""" CIFS Test cases

:requirement: cifs
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import pytest


@pytest.fixture(scope="class", autouse=True)
def add_etc_host_records(session_multihost, request):
    """ Add master and AD to /etc/hosts so they can be resolved
    :param obj session_multihost: multihost object
    :param obj request: pytest request object
    """
    session_multihost.client[0].run_command(
        'cp /etc/hosts /etc/hosts.orig', raiseonerr=False)
    records = f"{session_multihost.master[0].ip} " \
        f"{session_multihost.master[0].sys_hostname.strip().split('.')[0]} " \
        f"{session_multihost.master[0].sys_hostname.strip()}\\n" \
        f"{session_multihost.ad[0].ip} " \
        f"{session_multihost.ad[0].sys_hostname.strip().split('.')[0]} " \
        f"{session_multihost.ad[0].sys_hostname.strip()}\\n"
    session_multihost.client[0].run_command(
        f'echo -e "\\n{records}" >> /etc/hosts', raiseonerr=False)
    session_multihost.client[0].run_command('cat /etc/hosts', raiseonerr=False)

    def restore_etc_hosts():
        """ Restore backed up hosts"""
        session_multihost.client[0].run_command(
            'cp -f /etc/hosts.orig /etc/hosts', raiseonerr=False)
    request.addfinalizer(restore_etc_hosts)


@pytest.mark.usefixtures('winbind_server',
                         'configure_samba',
                         'samba_share_permissions')
@pytest.mark.tier2
@pytest.mark.cifs
class Testcifs(object):
    """ Samba IDMAP and CIFS Automations

    :setup:
      1. Join RHEL system to windows AD domain using below command
         $ realm join -v TESTRELM.TEST --membership-software=samba
      2. configure smb.conf to use sss as idmap backend
         idmap config * : backend = sss
         idmap config * : range   = 200000-2147483647
      3. Restart winbind
    """

    @pytest.mark.tier1
    def test_0001_wbinfo(self, multihost):
        """
        :title: IDM-SSSD-TC: samba_idmap: Samba can not
         register sss idmap module due to SMB_IDMAP_INTERFACE_VERSION
        :id: bad2770e-75de-4b41-af47-e9a38b8c0e73
        :requirement: IDM-SSSD-REQ: Samba with sssd as idmap backend
        :steps: Run wbinfo -i <DOMAIN>\\administrator
        :expectedresults: wbinfo command should be successfull
        """
        realm = multihost.ad[0].realm
        wb_cmd = 'wbinfo -i {}{}{}'.format(realm, '\\\\', "administrator")
        cmd = multihost.client[0].run_command(wb_cmd, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_0002_smb1mount(self, multihost):
        """
        :title: cifs: mount samba share using smb1 protocol
        :id: b82b6c93-1857-449c-bfbb-2a184e12cce6
        """
        ad_user = 'idmfoouser1'
        kinit = 'kinit %s' % ad_user
        server = multihost.master[0].sys_hostname.strip().split('.')[0]
        multihost.client[0].run_command(kinit, stdin_text='Secret123')
        mountcifs = "mount -t cifs -o cifsacl "\
                    "-o sec=krb5 -o username=%s //%s/share1"\
                    " /mnt/samba/share1" % (ad_user, server)
        cmd = multihost.client[0].run_command(mountcifs, raiseonerr=False)
        if cmd.returncode != 0:
            journalctl = 'journalctl -x -n 50 --no-pager'
            multihost.client[0].run_command(journalctl)
        else:
            assert cmd.returncode == 0
        umount = "umount /mnt/samba/share1"
        multihost.client[0].run_command(umount, raiseonerr=False)
        kdestroy = 'kdestroy -A'
        multihost.client[0].run_command(kdestroy, raiseonerr=False)

    def test_0003_smb3mount(self, multihost):
        """
        :title: cifs: mount samba share using encrypted smb3 protocol
        :id: 1b10f6f2-d91e-4ea4-a56a-985cd9f9d884
        """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        kinit = 'kinit %s' % ad_user
        server = multihost.master[0].sys_hostname.strip().split('.')[0]
        share_path = '/mnt/samba/share1'
        multihost.client[0].run_command(kinit, stdin_text='Secret123')
        mountcifs = "mount -t cifs -o username=%s,seal,sec=krb5,vers=3.0"\
                    " //%s/share1 /mnt/samba/share1" % (ad_user, server)
        cmd = multihost.client[0].run_command(mountcifs, raiseonerr=False)
        if cmd.returncode != 0:
            journalctl = 'journalctl -x -n 50 --no-pager'
            multihost.client[0].run_command(journalctl)
            pytest.fail("mounting using smb3 protocol failed")
        perms = '660'
        echo1 = "echo 'testwrite1' > "\
                "%s/allgroup/foobar.%s.%s.txt" % (share_path,
                                                  perms, ad_user)
        echo2 = "echo 'testwrite1' > "\
                "%s/%s/foobar.%s.%s.txt" % (share_path,
                                            ad_group, perms, ad_user)
        cmd = multihost.client[0].run_command(echo1, raiseonerr=False)
        assert cmd.returncode == 0
        multihost.client[0].run_command(echo2, raiseonerr=False)
        assert cmd.returncode == 0
        remove_file = "rm -f %s/allgroup/foobar.%s.%s.txt" % (share_path,
                                                              perms, ad_user)
        multihost.client[0].run_command(remove_file)
        remove_file = "rm -f %s/%s/foobar.%s.%s.txt" % (share_path,
                                                        ad_group,
                                                        perms, ad_user)
        multihost.client[0].run_command(remove_file)
        umount = "umount /mnt/samba/share1"
        multihost.client[0].run_command(umount, raiseonerr=False)
        kdestroy = 'kdestroy -A'
        multihost.client[0].run_command(kdestroy, raiseonerr=False)

    def test_0004_writeable(self, multihost):
        """
        :title: cifs: verify samba share is writeable
        :id: abd21985-ebd3-4c9d-987c-6e6da32bb922
        """
        realm = multihost.ad[0].realm
        for idx in range(1, 3):
            ad_user = 'idmfoouser%d' % idx
            ad_group = 'idmfoogroup%d' % idx
            kinit = 'kinit %s' % ad_user
            server = multihost.master[0].sys_hostname.strip().split('.')[0]
            share_path = '/mnt/samba/share1'
            multihost.client[0].run_command(kinit, stdin_text='Secret123')
            mountcifs = "mount -t cifs -o cifsacl "\
                        "-o sec=krb5 -o username=%s //%s/share1"\
                        " /mnt/samba/share1" % (ad_user, server)
            cmd = multihost.client[0].run_command(mountcifs, raiseonerr=False)
            assert cmd.returncode == 0
            time.sleep(5)
            journalctl = 'journalctl -x -n 50 --no-pager'
            multihost.client[0].run_command(journalctl)
            getent = 'getent passwd %s@%s' % (ad_user, realm)
            file_perms = ['660', '640', '600', '660']
            multihost.client[0].run_command(getent)
            for perms in file_perms:
                all_file = "%s/allgroup/testfile.%s.%s.txt" % (share_path,
                                                               perms, ad_user)
                group_file = "%s/%s/testfile.%s.%s.txt" % (share_path,
                                                           ad_group,
                                                           perms, ad_user)
                echo1 = "echo 'testwrite1' > %s" % (all_file)
                echo2 = "echo 'testwrite1' > %s" % (group_file)
                cmd = multihost.client[0].run_command(echo1, raiseonerr=False)
                assert cmd.returncode == 0
                cmd = multihost.client[0].run_command(echo2, raiseonerr=False)
                assert cmd.returncode == 0
                remove_file = "rm -f %s " % (all_file)
                multihost.client[0].run_command(remove_file)
                remove_file = "rm -f %s" % (group_file)
                multihost.client[0].run_command(remove_file)
            umount = "umount /mnt/samba/share1"
            multihost.client[0].run_command(umount, raiseonerr=False)
            kdestroy = 'kdestroy -A'
            multihost.client[0].run_command(kdestroy, raiseonerr=False)

    def test_0005_aclcheck(self, multihost, cifsmount):
        """
        :title: cifs: verify cifs acls on samba share with smb1 mount
        :id: b6f86e6b-03f7-4d76-8450-9b2d3d1ed71e
        """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        netbiosname = multihost.ad[0].netbiosname.strip()
        share_path = '/mnt/samba/share1'
        wb_cmd = 'wbinfo -n {}{}{}'.format(netbiosname, '\\\\', ad_user)
        cmd = multihost.client[0].run_command(wb_cmd, raiseonerr=False)
        smbuser_sid = cmd.stdout_text.split(' ')[0]
        wb_cmd = 'wbinfo -n {}{}{}'.format(netbiosname, '\\\\', ad_group)
        cmd = multihost.client[0].run_command(wb_cmd, raiseonerr=False)
        smbpgroup_sid = cmd.stdout_text.split(' ')[0]
        wb_cmd = 'wbinfo -n {}{}{}'.format(netbiosname, '\\\\',
                                           "idmfooallgroup")
        cmd = multihost.client[0].run_command(wb_cmd, raiseonerr=False)
        smballgroup_sid = cmd.stdout_text.split(' ')[0]
        file_perms = ['660', '640', '600', '660']
        for perms in file_perms:
            allgroup_file = "%s/allgroup/testfoo.%s.%s.txt" % (share_path,
                                                               perms, ad_user)
            acl1 = "getcifsacl -r %s" % allgroup_file
            adgroup_file = "%s/%s/testfoo.%s.%s.txt" % (share_path, ad_group,
                                                        perms, ad_user)
            acl2 = "getcifsacl -r %s" % adgroup_file
            echo1 = "echo 'testwrite1' > %s" % (allgroup_file)

            echo2 = "echo 'testwrite1' > %s" % (adgroup_file)
            cmd = multihost.client[0].run_command(echo1, raiseonerr=False)
            assert cmd.returncode == 0
            getcifsacl = multihost.client[0].run_command(acl1,
                                                         raiseonerr=False)
            usersid = "ACL:%s:0x0/0x0/0x1e01ff" % smbuser_sid
            allgroupsid = "ACL:%s:0x0/0x0/0x120089" % smballgroup_sid
            usergroupsid = "ACL:%s:0x0/0x0/0x120089" % smbpgroup_sid
            acl_list = getcifsacl.stdout_text.split('\n')
            assert usersid in acl_list
            assert allgroupsid in acl_list
            cmd = multihost.client[0].run_command(echo2, raiseonerr=False)
            assert cmd.returncode == 0
            getcifsacl = multihost.client[0].run_command(acl2,
                                                         raiseonerr=False)
            acl_list = getcifsacl.stdout_text.split('\n')
            assert usergroupsid in acl_list
            assert usersid in acl_list

    def test_0006_readfromclient(self, multihost, cifsmount):
        """
        :title: verify files modified on server
         are reflected properly on client
        :id: d8861167-2815-4aaa-abeb-1ac9183e3627
        """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        share_path = '/mnt/samba/share1'
        file_perms = ['660', '640', '600', '660']
        for perms in file_perms:
            allgroup_file = "%s/allgroup/testfoo1.%s.%s.txt" % (share_path,
                                                                perms, ad_user)
            adgroup_file = "%s/%s/testfoo1.%s.%s.txt" % (share_path, ad_group,
                                                         perms, ad_user)
            echo1 = "echo 'testwrite1' > %s" % (allgroup_file)
            echo2 = "echo 'testwrite1' > %s" % (adgroup_file)
            cmd = multihost.master[0].run_command(echo1, raiseonerr=False)
            assert cmd.returncode == 0
            cmd = multihost.master[0].run_command(echo2, raiseonerr=False)
            assert cmd.returncode == 0
            readfile1 = "cat %s" % (allgroup_file)
            cmd = multihost.client[0].run_command(readfile1, raiseonerr=False)
            assert 'testwrite1' in cmd.stdout_text
            readfile2 = "cat %s" % (adgroup_file)
            cmd = multihost.client[0].run_command(readfile2, raiseonerr=False)
            assert 'testwrite1' in cmd.stdout_text

    def test_0007_readfromserver(self, multihost, cifsmount):
        """
        :title: verify files modified on client
         are reflected properly on server
        :id: 0b8e677b-159b-49c0-9b85-3effdd22642d
        """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        share_path = '/mnt/samba/share1'
        file_perms = ['660', '640', '600', '660']
        for perms in file_perms:
            allgroup_file = "%s/allgroup/testfoo2.%s.%s.txt" % (share_path,
                                                                perms, ad_user)
            adgroup_file = "%s/%s/testfoo2.%s.%s.txt" % (share_path, ad_group,
                                                         perms, ad_user)
            echo1 = "echo 'testwrite1' > %s" % (allgroup_file)
            echo2 = "echo 'testwrite1' > %s" % (adgroup_file)
            cmd = multihost.client[0].run_command(echo1, raiseonerr=False)
            assert cmd.returncode == 0
            cmd = multihost.client[0].run_command(echo2, raiseonerr=False)
            assert cmd.returncode == 0
            readfile1 = "cat %s" % (allgroup_file)
            cmd = multihost.master[0].run_command(readfile1, raiseonerr=False)
            assert 'testwrite1' in cmd.stdout_text
            readfile2 = "cat %s" % (adgroup_file)
            cmd = multihost.master[0].run_command(readfile2, raiseonerr=False)
            assert 'testwrite1' in cmd.stdout_text
