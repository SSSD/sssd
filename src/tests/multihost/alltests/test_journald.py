""" Automation of sanity/journald suite

:requirement: IDM-SSSD-REQ : Journal based logging
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
import re
import time
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'write_journalsssd')
@pytest.mark.journald
class TestJournald(object):
    """
    This is test case class for sanity/journald suite
    """
    @pytest.mark.tier1
    def test_0001_bz1115508(self, multihost, enable_multiple_responders):
        """
        :title: IDM-SSSD-TC: sanity: journald: Send debug logs to journald by
         default bz1115508
        :id: 649107d8-7457-4da3-91c7-32b5bb493fb7
        """
        date = "date" + " --rfc-3339=ns"
        cmd = multihost.client[0].run_command(date, raiseonerr=False)
        date_org = cmd.stdout_text
        date = '"' + date_org[0:19] + '"'

        up_res = {}
        responder = {'jctl_sssd_be': 'sssd_be',
                     'jctl_sssd_pam': 'sssd_pam',
                     'jctl_sssd_nss': 'sssd_nss',
                     'jctl_sssd_autofs': 'sssd_autofs',
                     'jctl_sssd_ssh': 'sssd_ssh',
                     'jctl_sssd_pac': 'sssd_pac',
                     'jctl_sssd_ifp': 'sssd_ifp',
                     'jctl_sssd_sudo': 'sssd_sudo'}

        cmd_lookup = 'getent passwd foo1@%s' % ds_instance_name
        test = multihost.client[0].run_command(cmd_lookup, raiseonerr=False)
        if test.stdout_text.find("foo1") != -1:
            status = 'PASS'
        else:
            status = 'FAIL'
        time.sleep(10)
        multihost.client[0].service_sssd('restart')
        for x in responder:
            cmd = "journalctl --since %s -u sssd SYSLOG_IDENTIFIER=%s" % (
                date, responder[x])
            up_res[x] = cmd
            if 'nss' in up_res[x]:
                up_res[x] = multihost.client[0].run_command(up_res[x],
                                                            raiseonerr=False)
                log = re.compile(r'foo1.*')
                if log.search(up_res[x].stdout_text):
                    status = 'PASS'
                else:
                    status = "FAIL"
            else:
                up_res[x] = multihost.client[0].run_command(up_res[x],
                                                            raiseonerr=False)
                log1 = re.compile(r'.No\sentries.*')
                if log1.search(up_res[x].stdout_text):
                    status = 'FAIL'
                else:
                    status = 'PASS'
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0002_bz1460724(self, multihost, enable_multiple_responders):
        """
        :title: IDM-SSSD-TC: sanity: journald: SYSLOG_IDENTIFIER is different
        :id: c30e6899-6c6b-42bb-a9a3-4aacd589908e
        """
        pgrep = multihost.client[0].run_command(["pgrep", "-af", "sssd"],
                                                raiseonerr=False)

        if '--logger=journald' in pgrep.stdout_text:
            for resp in ['sssd_be', 'sssd_pam', 'sssd_nss', 'sssd_sudo',
                         'sssd_autofs', 'sssd_ssh', 'sssd_ifp', 'sssd_pac']:
                cmd = "journalctl -r --output=json SYSLOG_IDENTIFIER=%s >" \
                      " /root/op.json" % resp
                cmd = multihost.client[0].run_command(cmd)
                assert cmd.returncode == 0
                file_name = '/root/op.json'
                output = multihost.client[0].get_file_contents(file_name)
                search_str = re.compile(r'.SYSLOG_IDENTIFIER.*.:.*.%s.' % resp)
                assert search_str.search(output.decode())
                rm = 'rm -f /root/op.json'
                multihost.client[0].run_command(rm)
