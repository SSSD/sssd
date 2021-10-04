from __future__ import print_function
import pdb
import re
import subprocess
import time
from sssd.testlib.common.utils import sssdTools


def getent_sss(multihost, obj, db):
    gtnt = f'getent {db} -s sss {obj}'
    cmd = multihost.client[0].run_command(gtnt, raiseonerr=False)
    return cmd.returncode, cmd.stdout_text


def run_cmd(multihost, arg):
    cmd = multihost.client[0].run_command(arg, raiseonerr=False)
    return cmd.returncode, cmd.stdout_text


@pytest.mark.usefixtures("setup_sssd")
@pytest.mark.filesprovider
@pytest.mark.tier1
class TestFilesProvider(object):
    " This is a test case class for files-provider"
    def test_001_local_usr_caching(self, multihost, useradd):
        """
        :Title: local user caching with files-provider
        :id: fa12373b-8285-4fca-afe1-5e544fd58674
        :customerscenario: false
        :steps:
            1. Create an unprivileged user
            2. User details are returned from sss_cache
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, ot = getent_sss(multihost, 'test1', "passwd")
        assert exit_status == 0

    def test_002_root_usr_caching(self, multihost, backupsssdconf):
        """
        :Title: root user caching with files-provider
        :id: 0fea4269-de00-4e34-95c5-ab106957769d
        :customerscenario: false
        :steps:
            1. SSSD should not cache root user
        :expectedresults:
            1. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, _ = getent_sss(multihost, 'root', "passwd")
        assert exit_status != 0

    def test_003_group_caching(self, multihost, backupsssdconf, useradd):
        """
        :Title: local group caching with files-provider
        :id: ce9bb642-0f73-406d-b5b8-cf66f3b32dfb
        :customerscenario: false
        :steps:
            1. Create local group and add a user as it's member
            2. Confirm local group is showing user as it's member
            3. Confirm the user's group list is showing that local group
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, _ = getent_sss(multihost, "localgrp", "group")
        cmd = 'usermod -aG localgrp user1'
        ex, _ = run_cmd(multihost, cmd)
        assert ex == 0
        exit_status, stdout = getent_sss(multihost, "localgrp", "group")
        assert 'user1' in stdout
        cmd = 'groups user1'
        ex, stdout = run_cmd(multihost, 'groups user1')
        assert 'localgrp' in stdout

    def test_004_uid_change(self, multihost, backupsssdconf, useradd):
        """
        :Title: changes in uid change of user
        :id: bcd0ebfc-0478-4493-a3f8-123e6206e792
        :customerscenario: false
        :steps:
            1. Create a local user
            2. Modify user's uid to a different value
            3. Confirm changes in uid of user are reflected by sssd
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, stdout = getent_sss(multihost, 'user1', 'passwd')
        assert '7777' not in stdout
        multihost.client[0].run_command('usermod -u 7777 user1')
        exit_status, _ = run_cmd(multihost, 'usermod -u 7777 user1')
        assert exit_status == 0
        time.sleep(1)
        exit_status, stdout = getent_sss(multihost, 'user1', 'passwd')
        assert '7777' in stdout

    @pytest.mark.tier2
    def test_005_gid_change(self, multihost, backupsssdconf, useradd):
        """
        :Title: changes in gid of group
        :id: 44c074d7-eb68-415d-a2f0-6a601c503ea2
        :customerscenario: false
        :steps:
            1. Create a local group and add a local user to it's membership
            2. Modify group's gid to a different value
            3. Confirm changes in gid of group are reflected by sssd
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, stdout = getent_sss(multihost, "user1", "passwd")
        exit_status, stdout = run_cmd(multihost, 'usermod -aG l_grp1 user1')
        assert exit_status == 0
        exit_status, stdout = run_cmd(multihost, 'groupmod -g 3333 l_grp1')
        assert exit_status == 0
        time.sleep(1)
        exit_status, stdout = getent_sss(multihost, "l_grp1", "group")
        assert '3333' in stdout

    def test_006_grp_removal(self, multihost, backupsssdconf, useradd):
        """
        :Title: removal of a user from a group
        :id: bbf70304-aeba-4fe9-93d7-9b04677d37c0
        :customerscenario: false
        :steps:
            1. Create a local group and a local user.
            2. Add local user as a member of local-group
            3. Confirm chanages in user's and group's membership returned
               correctly by SSSD
            4. Remove user from group's membership
            5. Confirm chanages in user's and group's membership returned
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
        """
        multihost.client[0].service_sssd('start')
        cmd = 'getent passwd -s sss user1'
        cmd1 = multihost.client[0].run_command(cmd, raiseonerr=False)
        exit_status, _ = getent_sss(multihost, 'user1', 'passwd')
        exit_status, _ = run_cmd(multihost, 'usermod -aG l_grp1 user1')
        time.sleep(1)
        cmd = 'groups user1'
        cmd1 = multihost.client[0].run_command(cmd, raiseonerr=False)
        exit_status, stdout_text = run_cmd(multihost, 'groups user1')
        assert 'l_grp1' in stdout_text
        exit_status, _ = run_cmd(multihost, 'gpasswd -d user1 l_grp1')
        cmd = 'groups user1'
        cmd1 = multihost.client[0].run_command(cmd, raiseonerr=False)
        exit_status, stdout_text = run_cmd(multihost, 'groups user1')
        assert 'l_grp1' not in stdout_text

    def test_007_zero_gid_user(self, multihost, backupsssdconf, useradd):
        """
        :Title: caching of user with gid value set to zero
        :id: f21526e8-1092-493d-a885-3bb732e14741
        :customerscenario: false
        :steps:
            1. Create a local user with gid set to a zero
            2. Confirm SSSD does not cache this user information
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, _ = run_cmd(multihost, 'useradd -g 0 u_zero_uid')
        assert exit_status == 0
        time.sleep(1)
        exit_status, _ = getent_sss(multihost, 'u_zero_uid', 'passwd')
        assert exit_status != 0
        exit_status, _ = run_cmd(multihost, 'userdel -rf u_zero_uid')
        assert exit_status == 0

    def test_008_system_users(self, multihost, backupsssdconf):
        """
        :Title: caching of system users
        :id: 56be0457-989c-433f-87d8-51bb77f07631
        :customerscenario: false
        :steps:
            1. All system-users with non-zero gid are returned by SSSD
        :expectedresults:
            1. Should succeed
        """
        multihost.client[0].service_sssd('start')
        multihost.client[0].transport.get_file('/etc/passwd', '/tmp/passwd')
        with open('/tmp/passwd', 'r') as file:
            u_list = []
            f_read = file.readlines()
            u_name = [usr.split(':')[0] for usr in f_read
                      if usr.split(':')[3] != '0']
            for user in u_name:
                exit_status, _ = getent_sss(multihost, user, 'passwd')
                assert exit_status == 0
        multihost.client[0].run_command('rm -f /tmp/passwd', raiseonerr=False)

    def test_009_system_users_zero_gid(self, multihost, backupsssdconf):
        """
        :Title: caching of system users with zero gid
        :id: 4149b84b-bbfc-4aaa-aaae-462444c9050c
        :customerscenario: false
        :steps:
            1. All system-users with zero gid are not returned by SSSD
        :expectedresults:
            1. Should succeed
        """
        multihost.client[0].service_sssd('start')
        multihost.client[0].transport.get_file('/etc/passwd', '/tmp/passwd')
        with open('/tmp/passwd', 'r') as file:
            u_list = []
            f_read = file.readlines()
            u_name = [usr.split(':')[0] for usr in f_read
                      if usr.split(':')[3] == '0']
            for user in u_name:
                exit_status, _ = getent_sss(multihost, user, 'passwd')
                assert exit_status != 0
        multihost.client[0].run_command('rm -f /tmp/passwd', raiseonerr=False)

    def test_010_dup_uid(self, multihost, backupsssdconf):
        """
        :Title: caching of users with same uid
        :id: f21c2bfe-baf6-4c8d-8195-e834729da0ba
        :customerscenario: false
        :steps:
            1. Create two local user with same uid
            2. Modify user's uid to a different value
            3. Confirm changes in uid of user are reflected by sssd
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        multihost.client[0].service_sssd('start')
        localuser = 'local_user1'
        dup_user = 'local_user2'
        cmd = f'useradd -u 2222 {localuser}'
        exit_status, _ = run_cmd(multihost, cmd)
        cmd = f'useradd -u 2222 -o {dup_user}'
        exit_status, _ = run_cmd(multihost, cmd)
        time.sleep(1)
        exit_status, _ = getent_sss(multihost, f'{dup_user}', 'passwd')
        assert exit_status == 0
        exit_status, _ = getent_sss(multihost, f'{localuser}', 'passwd')
        assert exit_status != 0
        cmd = f'userdel -rf {dup_user}'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        cmd = f'userdel -rf {localuser}'
        multihost.client[0].run_command(cmd, raiseonerr=False)

    def test_011_gecos_usr(self, multihost, backupsssdconf):
        """
        :Title: caching of gecos data of user
        :id: 0e16d3bf-9ded-4b45-bf12-81f90349b007
        :customerscenario: false
        :steps:
            1. Create a local user with some gecos data
            2. Confirm gecos data of user is reflected by sssd
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        multihost.client[0].service_sssd('start')
        localuser = 'localuser1'
        gecos = 'This gecos info added'
        cmd = f'useradd -c "{gecos}" {localuser}'
        exit_status, _ = run_cmd(multihost, cmd)
        assert exit_status == 0
        time.sleep(1)
        exit_status, stdout = getent_sss(multihost, localuser, "passwd")
        assert f'{gecos}' in stdout
        exit_status, _ = run_cmd(multihost, f'userdel -rf {localuser}')

    def test_012_expired_user(self, multihost, backupsssdconf):
        """
        :Title: caching of gecos data of user
        :id: bcd0ebfc-0478-4493-a3f8-123e6206e792
        :customerscenario: false
        :steps:
            1. Create a local user with some gecos data
            2. Confirm gecos data of user is reflected by sssd
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        multihost.client[0].service_sssd('start')
        lusr = 'usr'
        cmd = f'useradd -e 2018-08-09 {lusr}'
        exit_status, _ = run_cmd(multihost, cmd)
        assert exit_status == 0
        time.sleep(1)
        exit_status, stdout = getent_sss(multihost, lusr, "passwd")
        exit_status, _ = run_cmd(multihost, f'userdel -rf {lusr}')

    def test_013_expired_user(self, multihost, backupsssdconf):
        """
        :Title: caching of gecos data of user
        :id: bcd0ebfc-0478-4493-a3f8-123e6206e792
        :customerscenario: false
        :steps:
            1. Create a local user with some gecos data
            2. Confirm gecos data of user is reflected by sssd
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        multihost.client[0].service_sssd('start')
        lusr = 'usr'
        cmd = f'useradd -e 2018-08-09 {lusr}'
        exit_status, _ = run_cmd(multihost, cmd)
        assert exit_status == 0
        time.sleep(1)
        exit_status, stdout = getent_sss(multihost, lusr, "passwd")
        exit_status, _ = run_cmd(multihost, f'userdel -rf {lusr}')

    @pytest.mark.tier2
    def test_014_grp_membr_modification(self, multihost,
                                        backupsssdconf, useradd):
        """
        :Title: modification of user group membership
        :id: ec84bdec-50d9-4eb8-a612-b4c14787639b
        :customerscenario: false
        :steps:
            1. Create a local user and a local group
            2. Add user as member to local group
            3. Confirm modification is reflected in
               user and group information
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, stdout = getent_sss(multihost, 'user1', 'passwd')
        assert 'l_grp1' not in stdout
        exit_status, stdout = getent_sss(multihost, 'l_grp1', 'group')
        assert 'user1' not in stdout
        lusr = 'usr'
        cmd = f'usermod -aG l_grp1 user1'
        exit_status, _ = run_cmd(multihost, cmd)
        time.sleep(1)
        exit_status, stdout = run_cmd(multihost, 'groups user1')
        assert 'l_grp1' in stdout
        exit_status, stdout = getent_sss(multihost, 'l_grp1', 'group')
        assert 'user1' in stdout

    @pytest.mark.tier2
    def test_015_homedir_modification(self, multihost,
                                      backupsssdconf, useradd):
        """
        :Title: modification of user home directory
        :id: 538b74d4-32e2-466d-94b0-faa010a9b16e
        :customerscenario: false
        :steps:
            1. Create a local user
            2. Modify users home directory to other value
            3. Confirm modification is reflected in
               user information
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        multihost.client[0].service_sssd('start')
        exit_status, stdout = getent_sss(multihost, 'user1', 'passwd')
        assert '/home/user1' in stdout
        time.sleep(1)
        new_home = '/home/new_user1'
        cmd = f'usermod -d {new_home} user1'
        exit_status, stdout = run_cmd(multihost, cmd)
        time.sleep(1)
        exit_status, stdout = getent_sss(multihost, 'user1', 'passwd')
        assert new_home in stdout
