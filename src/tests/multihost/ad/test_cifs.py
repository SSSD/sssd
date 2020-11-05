""" CIFS Test cases """
import time
import pytest


@pytest.mark.usefixtures('winbind_server',
                         'configure_samba',
                         'samba_share_permissions')
@pytest.mark.tier2
@pytest.mark.cifs
class Testcifs(object):
    """ Samba IDMAP and CIFS Automations """

    @pytest.mark.tier1
    def test_0001_wbinfo(self, multihost):
        """
        @Title: IDM-SSSD-TC: samba_idmap: Samba can not
        register sss idmap module due to SMB_IDMAP_INTERFACE_VERSION

        @Setup:
        1. Join RHEL system to windows AD domain using below command
           $ realm join -v TESTRELM.TEST --membership-software=samba
        2. configure smb.conf to use sss as idmap backend
           idmap config * : backend = sss
           idmap config * : range   = 200000-2147483647
        3. Restart winbind

        @Steps:
        1. Run wbinfo -i <DOMAIN>\administrator
        """
        realm = multihost.ad[0].realm
        wb_cmd = 'wbinfo -i {}{}{}'.format(realm, '\\\\', "administrator")
        cmd = multihost.client[0].run_command(wb_cmd, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_0002_smb1mount(self, multihost):
        """ @Title: cifs: mount samba share using smb1 protocol """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        realm = multihost.ad[0].realm
        kinit = 'kinit %s' % ad_user
        server = multihost.master[0].sys_hostname.strip().split('.')[0]
        share_path = '/mnt/samba/share1'
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
        """ @Title: cifs: mount samba share using encrypted smb3 protocol """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        realm = multihost.ad[0].realm
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
        """ @Title: cifs: verify samba share is writeable """
        realm = multihost.ad[0].realm
        netbiosname = multihost.ad[0].netbiosname
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
        """ @Title: cifs: verify cifs acls on samba share with smb1 mount"""
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        realm = multihost.ad[0].realm
        netbiosname = multihost.ad[0].netbiosname.strip()
        share_path = '/mnt/samba/share1'
        wb_cmd = 'wbinfo -n {}{}{}'.format(netbiosname, '\\\\',
                                           "'Domain Users'")
        cmd = multihost.client[0].run_command(wb_cmd, raiseonerr=False)
        smbdomuser_sid = cmd.stdout_text.split(' ')[0]
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
        """@Title: verify files modified on server
        are reflected properly on client
        """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        realm = multihost.ad[0].realm
        netbiosname = multihost.ad[0].netbiosname.strip()
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
            assert 'testwrite1'in cmd.stdout_text
            readfile2 = "cat %s" % (adgroup_file)
            cmd = multihost.client[0].run_command(readfile2, raiseonerr=False)
            assert 'testwrite1'in cmd.stdout_text

    def test_0007_readfromserver(self, multihost, cifsmount):
        """@Title: verify files modified on client
        are reflected properly on server
        """
        ad_user = 'idmfoouser1'
        ad_group = 'idmfoogroup1'
        realm = multihost.ad[0].realm
        netbiosname = multihost.ad[0].netbiosname.strip()
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
            assert 'testwrite1'in cmd.stdout_text
            readfile2 = "cat %s" % (adgroup_file)
            cmd = multihost.master[0].run_command(readfile2, raiseonerr=False)
            assert 'testwrite1'in cmd.stdout_text
