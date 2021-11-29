""" Automation of IPA subid feature bugs

:requirement: IDM-IPA-REQ: ipa subid range
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

import pytest
import subprocess
import time
import os
from sssd.testlib.common.utils import SSHClient


test_password = "Secret123"
user = 'admin'


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


def ipa_subid_find(multihost):
    ssh1 = SSHClient(multihost.client[0].ip,
                     username=user, password=test_password)
    (result, result1, exit_status) = ssh1.exec_command(f"ipa  "
                                                       f"subid-find"
                                                       f"  --owner  "
                                                       f"{user}")
    user_details = result1.readlines()
    global uid_start, uid_range, gid_start, gid_range
    uid_start = int(user_details[5].split(': ')[1].split('\n')[0])
    uid_range = int(user_details[6].split(': ')[1].split('\n')[0])
    gid_start = int(user_details[7].split(': ')[1].split('\n')[0])
    gid_range = int(user_details[8].split(': ')[1].split('\n')[0])
    ssh1.close()


@pytest.mark.usefixtures('environment_setup',
                         'subid_generate',
                         'bkp_cnfig_for_subid_files')
@pytest.mark.tier1
class TestSubid(object):
    """
    This is for ipa bugs automation
    """
    def test_podmanmap_feature(self, multihost):
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
        ssh1 = SSHClient(multihost.client[0].ip,
                         username=user,
                         password=test_password)
        map1 = "/proc/self/uid_map"
        (results1, results2, results3) = ssh1.exec_command(f"podman "
                                                           f"unshare "
                                                           f"cat "
                                                           f"{map1}")
        actual_result = results2.readlines()
        assert str(uid_start) == actual_result[1].split()[1]
        assert str(uid_range) == actual_result[1].split()[2]
        map2 = "/proc/self/gid_map"
        (results1, results2, results3) = ssh1.exec_command(f"podman "
                                                           f"unshare "
                                                           f"cat "
                                                           f"{map2}")
        actual_result = results2.readlines()
        assert str(gid_start) == actual_result[1].split()[1]
        assert str(gid_range) == actual_result[1].split()[2]
        ssh1.close()

    def test_subid_feature(self, multihost):
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
        ssh1 = SSHClient(multihost.client[0].ip,
                         username=user, password=test_password)
        (results1, results2, results3) = ssh1.exec_command("unshare"
                                                           " -U bash"
                                                           " -c 'echo $$"
                                                           ">/tmp/unshare.pid;"
                                                           "sleep 1000'")
        time.sleep(2)
        proces_id = int(execute_cmd(multihost,
                                    "cat "
                                    "/tmp/unshare.pid").stdout_text.strip())
        uid = 0
        gid = 1000
        count = 1
        (std_out, std_err, exit_status) = ssh1.exec_command(f"newuidmap "
                                                            f"{proces_id}"
                                                            f" {uid}"
                                                            f" {uid_start}"
                                                            f" {count}")
        for i in exit_status.readlines():
            assert "write to uid_map failed" not in i
        (result, result1, exit_status) = ssh1.exec_command(f"newgidmap "
                                                           f"{proces_id} "
                                                           f"{gid} "
                                                           f"{gid_start} "
                                                           f"{count}")
        for i in exit_status.readlines():
            assert "write to gid_map failed" not in i
        result = execute_cmd(multihost, f"cat /proc/{proces_id}/uid_map")
        assert str(uid) == result.stdout_text.split()[0]
        assert str(uid_start) == result.stdout_text.split()[1]
        assert str(count) == result.stdout_text.split()[2]
        result = execute_cmd(multihost, f"cat /proc/{proces_id}/gid_map")
        assert str(gid) == result.stdout_text.split()[0]
        assert str(gid_start) == result.stdout_text.split()[1]
        assert str(count) == result.stdout_text.split()[2]
        multihost.client[0].run_command(f'kill -9 {proces_id}')
        multihost.client[0].run_command("rm -vf "
                                        "/tmp/unshare.pid")
        ssh1.close()

    def test_list_subid_ranges(self, multihost):
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
        ssh1 = SSHClient(multihost.client[0].ip,
                         username=user, password=test_password)
        cmd = multihost.client[0].run_command(f"cd /tmp/; "
                                              f"./list_subid_ranges "
                                              f"{user}")
        assert str(user) == cmd.stdout_text.split()[1]
        assert str(uid_start) == cmd.stdout_text.split()[2]
        assert str(uid_range) == cmd.stdout_text.split()[3]
        cmd = multihost.client[0].run_command(f"cd /tmp/;"
                                              f" ./list_subid_ranges"
                                              f" -g {user}")
        assert str(user) == cmd.stdout_text.split()[1]
        assert str(gid_start) == cmd.stdout_text.split()[2]
        assert str(gid_range) == cmd.stdout_text.split()[3]
        ssh1.close()
