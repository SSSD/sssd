""" Automation of IPA subid feature bugs

:requirement: IDM-IPA-REQ: ipa subid range
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import re
import tempfile
import pytest
from pexpect import pxssh


TEST_PASSWORD = "Secret123"
USER = 'admin'


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


def ipa_subid_find(multihost):
    """Grab and store information about admin subid ranges"""
    cmd = multihost.client[0].run_command(
        f'su - {USER} -c "ipa subid-find --owner {USER}"', raiseonerr=False)
    user_details = cmd.stdout_text.splitlines()

    global uid_start, uid_range, gid_start, gid_range
    uid_start = int(user_details[5].split(': ')[1].split('\n')[0])
    uid_range = int(user_details[6].split(': ')[1].split('\n')[0])
    gid_start = int(user_details[7].split(': ')[1].split('\n')[0])
    gid_range = int(user_details[8].split(': ')[1].split('\n')[0])


@pytest.mark.usefixtures('environment_setup',
                         'subid_generate',
                         'bkp_cnfig_for_subid_files')
@pytest.mark.tier1
class TestSubid(object):
    """
    This is for ipa bugs automation
    """

    @staticmethod
    def test_podmanmap_feature(multihost):
        """
        :Title: Podman supports subid ranges managed by FreeIPA
        :id: 0e86df9c-50f1-11ec-82f3-845cf3eff344
        :customerscenario: true
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1803943
        :steps:
            1. Test podman finds proper uid_map
            2. Test podman finds proper gid_map
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        ipa_subid_find(multihost)
        map1 = "/proc/self/uid_map"
        cmd = multihost.client[0].run_command(
            f'su - {USER} -c "podman unshare cat {map1}"', raiseonerr=False)
        actual_result = cmd.stdout_text.splitlines()

        assert str(uid_start) == actual_result[1].split()[1]
        assert str(uid_range) == actual_result[1].split()[2]
        map2 = "/proc/self/gid_map"
        cmd = multihost.client[0].run_command(
            f'su - {USER} -c "podman unshare cat {map2}"', raiseonerr=False)
        actual_result = cmd.stdout_text.splitlines()
        assert str(gid_start) == actual_result[1].split()[1]
        assert str(gid_range) == actual_result[1].split()[2]

    @staticmethod
    def test_subid_feature(multihost):
        """
        :Title: support subid ranges managed by FreeIPA
        :id: 50bcdc28-00c8-11ec-bef4-845cf3eff344
        :customerscenario: true
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1803943
        :steps:
            1. Test newuidmap command
            2. Test newgidmap command
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        ipa_subid_find(multihost)
        with tempfile.NamedTemporaryFile(mode='w') as tfile:
            tfile.write('#!/usr/bin/bash\n')
            tfile.write('whoami\n')
            tfile.write('unshare -U bash -c \'echo $$ >/tmp/unshare.pid;'
                        ' sleep 240; \' &\n')
            tfile.write('ps -ef | grep sleep | grep -v grep\n')
            tfile.write('MYPID="$(cat /tmp/unshare.pid)"\n')
            tfile.write(f'newuidmap $MYPID 0 {uid_start} 1\n')
            tfile.write('echo "uidmap_ $(cat /proc/$MYPID/uid_map) _uidmap"\n')
            tfile.write(f'newgidmap $MYPID 1000 {gid_start} 1\n')
            tfile.write('echo "gidmap_ $(cat /proc/$MYPID/gid_map) _gidmap"\n')
            tfile.flush()
            multihost.client[0].transport.put_file(tfile.name, '/tmp/maps.sh')
        multihost.client[0].run_command(
            'chmod ugo+x /tmp/maps.sh', raiseonerr=False)

        ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                          "UserKnownHostsFile": "/dev/null"}, timeout=600)
        ssh.force_password = True
        try:
            ssh.login(multihost.client[0].ip, USER, TEST_PASSWORD)
            ssh.sendline('/tmp/maps.sh')
            ssh.prompt(timeout=600)
            ssh_output = str(ssh.before)
            ssh.logout()
        except pxssh.ExceptionPxssh as ex:
            pytest.fail(str(ex))
        multihost.client[0].run_command(
            f'echo "{ssh_output}"', raiseonerr=False)
        umap = re.search(f'uidmap_.*0.*{uid_start}.*1.*_uidmap', ssh_output)
        gmap = re.search(f'gidmap_.*1000.*{gid_start}.*1.*_gidmap', ssh_output)
        for file in ['maps.sh', 'unshare.pid']:
            multihost.client[0].run_command(f'rm -vf {file}')
        assert umap, "Expected uid map not found!"
        assert gmap, "Expected gid map not found!"
        assert "write to uid_map failed" not in ssh_output
        assert "write to gid_map failed" not in ssh_output

    @staticmethod
    def test_list_subid_ranges(multihost):
        """
        :Title: support subid ranges managed by FreeIPA
        :id: 4ab33f84-00c8-11ec-ad91-845cf3eff344
        :customerscenario: true
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1803943
        :steps:
            1. Test list_subid_ranges command
            2. Test list_subid_ranges -g command
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        ipa_subid_find(multihost)
        multihost.client[0].run_command(
            f'su -l {USER} -c "whoami"', raiseonerr=False)
        cmd = multihost.client[0].run_command(f"cd /tmp/; "
                                              f"./list_subid_ranges "
                                              f"{USER}")
        assert str(USER) == cmd.stdout_text.split()[1]
        assert str(uid_start) == cmd.stdout_text.split()[2]
        assert str(uid_range) == cmd.stdout_text.split()[3]
        cmd = multihost.client[0].run_command(f"cd /tmp/;"
                                              f" ./list_subid_ranges"
                                              f" -g {USER}")
        assert str(USER) == cmd.stdout_text.split()[1]
        assert str(gid_start) == cmd.stdout_text.split()[2]
        assert str(gid_range) == cmd.stdout_text.split()[3]
