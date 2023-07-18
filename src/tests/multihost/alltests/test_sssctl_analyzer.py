"""Automation tests for sssctl analyze

:requirement: sssctl analyze
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
import re
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client
from constants import ds_instance_name


def analyze(multihost, req_arg, op_arg=None):
    """
    Execute sssctl analyze command with given action and options
    and return the exit status as well as command output
        :param str req_arg: command action to perform, values could be
        'list' or 'show' or 'show <num>'
        : param str arg: optional argument string. values could be
        '--source <log_source>' or '--logdir <dir_path>' or '--help'
    """
    if op_arg is None:
        op_arg = ''
    str_cmd = f'sssctl analyze {op_arg} request {req_arg}'
    ss_cmd = multihost.client[0].run_command(str_cmd, raiseonerr=False)
    return ss_cmd.returncode, ss_cmd.stdout_text


@pytest.mark.usefixtures('setup_sssd_krb', 'create_posix_usersgroups')
@pytest.mark.analyze
@pytest.mark.tier1_4
class TestSssctlAnalyze(object):
    """ sssctl analyze test suite """
    def test_analyze_list(self, multihost, backupsssdconf):
        """
        :title: sssctl analyze list to show captured nss related
         requests from sssd log
        :id: 95e18ae1-6c4a-4baa-8202-fe33fe82bdec
        :description: sssctl analyze request list is able to capture the user
         and group related requests raised when commands like id and getent
         are executed
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1294670
        :steps:
          1. Configure sssd to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
          3. Restart SSSD with cleared cache
          4. Fetch user and group information using 'id' and 'getent' tools
          5. Run 'sssctl analyze request list'
          6. Check with sssctl analyze is listing id and getent instances
          7. sssctl analyze with subcmd 'show' and request number is listing
             logs related to that number only
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        dm_sec = ['nss', 'pam']
        sssd_params = {'debug_level': '9'}
        for sec_op in dm_sec:
            tools.sssd_conf(sec_op, sssd_params, action='update')
        multihost.client[0].service_sssd('start')
        tools.clear_sssd_cache()
        g_cmd = f'getent group ldapusers@{ds_instance_name}'
        multihost.client[0].run_command(g_cmd, raiseonerr=False)
        i_cmd = f'id foo1@{ds_instance_name}'
        multihost.client[0].run_command(i_cmd, raiseonerr=False)
        for act_op in ['list', 'list -v']:
            _, stdout = analyze(multihost, act_op)
            assert all(ptn in stdout for ptn in ['id', 'getent'])
        tools.clear_sssd_cache()
        g_cmd = f'getent passwd foo1@{ds_instance_name}'
        multihost.client[0].run_command(g_cmd, raiseonerr=False)
        for act_op in ['list', 'list -v']:
            _, stdout = analyze(multihost, act_op)
            assert all(ptn in stdout for ptn in ['CID #1', 'getent'])

    def test_analyze_diff_log_location(self, multihost, backupsssdconf):
        """
        :title: sssctl analyze able to parse sssd logs from non-default
         location
        :description: sssctl analyze should be able to parse the sssd logs
         from different location or logs from other host
        :id: d297b394-3502-4ade-a5a5-5fb4c4333645
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1294670
                   https://github.com/SSSD/sssd/issues/6298
        :steps:
          1. Configure sssd to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
          3. Restart SSSD with cleared cache
          4. Fetch user as well as  information using 'id' and 'groups' tools
          5. Log in as user via ssh
          6. Copy sssd logs to a different location
          7. Stop sssd and remove conf, logs and cache
          8. Confirm --logdir allows analyze to parse logs from that location
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. No sssd running or configured
          8. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        dm_sec = ['nss', 'pam']
        sssd_params = {'debug_level': '9'}
        for sec_op in dm_sec:
            tools.sssd_conf(sec_op, sssd_params, action='update')
        tools.clear_sssd_cache()
        user = f'foo1@{ds_instance_name}'
        i_cmd = f'id {user}'
        multihost.client[0].run_command(i_cmd, raiseonerr=False)
        check_login_client(multihost, user, 'Secret123')
        cp_cmd = 'cp -r /var/log/sssd /tmp/'
        multihost.client[0].run_command(cp_cmd, raiseonerr=False)
        multihost.client[0].service_sssd('stop')
        cp_cmd = 'rm -f /etc/sssd/sssd.conf'
        multihost.client[0].run_command(cp_cmd, raiseonerr=False)
        tools.remove_sss_cache('/var/log/sssd/')
        tools.remove_sss_cache('/var/lib/sss/db/')
        ss_op = 'show 1 --pam'
        log_dir = '--logdir /tmp/sssd/'
        _, stdout = analyze(multihost, ss_op, log_dir)
        pam_cmds = ['SSS_PAM_AUTHENTICATE', 'SSS_PAM_ACCT_MGMT',
                    'SSS_PAM_SETCRED']
        for pam_auth in pam_cmds:
            assert pam_auth in stdout
        for act_op in ['list', 'list -v']:
            _, stdout = analyze(multihost, act_op, log_dir)
            assert 'id' in stdout
            assert 'sshd' or 'auditd' in stdout

    def test_analyze_pam_logs(self, multihost, backupsssdconf):
        """
        :title: sssctl analyze to parse pam requests from logs
        :id: 7fcd03b6-7f6f-4f39-96f8-45e0cb2d8c20
        :description: sssctl analyze request should able to parse and return
         authentication logs
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1294670
        :steps:
          1. Configure sssd to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
          3. Restart SSSD with cleared cache
          4. Log in as a user using ssh
          5. Confirm --pam option is showing login related logs
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db/')
        tools.remove_sss_cache('/var/log/sssd/')
        dm_sec = ['nss', 'pam']
        sssd_params = {'debug_level': '9'}
        for sec_op in dm_sec:
            tools.sssd_conf(sec_op, sssd_params, action='update')
        multihost.client[0].service_sssd('start')
        user = f'foo1@{ds_instance_name}'
        check_login_client(multihost, user, 'Secret123')
        _, stdout = analyze(multihost, 'show 1 --pam')
        assert 'CID #1' in stdout
        pam_cmds = ['SSS_PAM_AUTHENTICATE', 'SSS_PAM_ACCT_MGMT',
                    'SSS_PAM_SETCRED']
        for pam_auth in pam_cmds:
            assert pam_auth in stdout

    def test_analyze_tevent_id(self, multihost, backupsssdconf):
        """
        :title: sssctl analyze to parse tevent chain IDs from logs
        :id: f748766c-0177-4306-9e7f-816586734e14
        :description: sssctl analyze should able to parse tevent chain
         IDs from responder logs
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2013259
        :steps:
          1. Configure sssd to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
          3. Restart SSSD with cleared cache
          4. Log in as a user using ssh
          5. Confirm tevent chain IDs(RID) is showing in logs
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        dm_sec = ['nss', 'pam']
        sssd_params = {'debug_level': '9'}
        for sec_op in dm_sec:
            tools.sssd_conf(sec_op, sssd_params, action='update')
        tools.clear_sssd_cache()
        i_cmd = f'id foo1@{ds_instance_name}'
        multihost.client[0].run_command(i_cmd, raiseonerr=False)
        user = f'foo1@{ds_instance_name}'
        check_login_client(multihost, user, 'Secret123')
        _, stdout = analyze(multihost, 'show 1 --pam')
        assert all(ptn in stdout for ptn in ['RID#', user])

    def test_analyze_parse_child_logs(self, multihost, backupsssdconf):
        """
        :title: sssctl analyze to parse child logs from logs
        :id: 0f009b2e-420f-40f4-ab37-e224a6607812
        :description: sssctl analyze should able to parse child logs
         from  logs
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2013260
        :steps:
          1. Configure sssd to authenticate against directory server
          2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
          3. Restart SSSD with cleared cache
          4. Log in as a user using ssh
          5. Confirm child krb logs  parsed
          6. Fail log in with wrong credentials
          7. Confirm parsed child logs show error message
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        dm_sec = ['nss', 'pam']
        sssd_params = {'debug_level': '9'}
        for sec_op in dm_sec:
            tools.sssd_conf(sec_op, sssd_params, action='update')
        tools.clear_sssd_cache()
        user = f'foo1@{ds_instance_name}'
        try:
            check_login_client(multihost, user, 'Secret123')
        except Exception:
            _, stdout = analyze(multihost, 'show --pam --child 1')
            assert 'Preauthentication failed' in stdout
            pytest.fail(f"{user} failed to login")
        _, stdout = analyze(multihost, 'show --pam --child 1')
        err = 'sss_child_krb5_trace_cb'
        assert all(ptn in stdout for ptn in [err, user])
        tools.clear_sssd_cache()
        try:
            check_login_client(multihost, user, 'Secret123')
        except Exception:
            _, stdout = analyze(multihost, 'show --pam --child 1')
            assert re.findall(r"RID#[0-9]*] Received error code", stdout)

    @staticmethod
    def test_non_root_privileged(multihost, localusers):
        """
        :title: SSSD: `sssctl analyze` command shouldn't require 'root' privileged
        :id: 51a69d4e-7ae4-11ed-95a5-845cf3eff344
        :description: `sssctl analyze` command shouldn't require
            'root' privileged when run with `--logdir`
            pointing to otherwise accessible files.
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2142960
                   https://bugzilla.redhat.com/show_bug.cgi?id=2142794
                   https://bugzilla.redhat.com/show_bug.cgi?id=2142961
        :steps:
          1. Create directory
          2. Copy logs to above directory
          3. Change ownership to a local user
          4. Try sssctl analyze command pointing to above
            directory with root and loacluser
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. sssctl analyze outputs provided for user root
            and user5000 are the same
        """
        # Create directory
        # Copy logs to above directory
        # Change ownership to a local user
        multihost.client[0].run_command("rm -vfr /tmp/sssd", raiseonerr=False)
        for command in ["mkdir /tmp/sssd",
                        "cp -vf /var/log/sssd/* /tmp/sssd",
                        "chown user5000 /tmp/sssd/",
                        "chown user5000 /tmp/sssd/*"]:
            multihost.client[0].run_command(command)
        # sssctl analyze command with root
        cmd_root = multihost.client[0].run_command("sssctl analyze --logdir /tmp/sssd")
        # sssctl analyze command with non root user
        cmd_user500 = multihost.client[0].run_command("runuser -l user5000 -c "
                                                      "'sssctl analyze --logdir /tmp/sssd'")
        multihost.client[0].run_command("rm -vfr /tmp/sssd")
        assert cmd_root.returncode == 0
        assert cmd_user500.returncode == 0
        # sssctl analyze command output should same for both
        # root and non root user
        assert cmd_root.stdout_text == cmd_user500.stdout_text
