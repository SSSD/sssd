""" Miscellaneous IPA Bug Automations

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import datetime
import re
import time
import subprocess
import pexpect
import pexpect.pxssh
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.helper_functions import check_login
from sssd.testlib.common.expect import pexpect_ssh


def client_login(multihost, user, password, retry=0):
    """ssh to client machine
    user: User to login with
    password: Password of User
    retry: Retry number module should try to login
    """
    client_hostip = multihost.client[0].ip
    for count in range(retry + 1):
        client = pexpect_ssh(client_hostip, user, password, debug=False)
        print(count)
        try:
            ssh = client.login(login_timeout=30,
                               sync_multiplier=1,
                               auto_prompt_reset=False)
        except Exception:
            time.sleep(3)
            continue
        if ssh:
            client.logout()
            break
    else:
        raise Exception("User failed to login")


@pytest.mark.usefixtures('default_ipa_users', 'reset_password')
@pytest.mark.tier1
class Testipabz(object):
    """ IPA BZ Automations """
    @staticmethod
    def test_pass_krb5cname_to_pam(multihost,
                                   backupsssdconf,
                                   backup_config_pam_gssapi_services):
        """
        :title: pass KRB5CCNAME to pam_authenticate environment
         if available
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1917379
        :id: e3a6accc-781d-11ec-a83c-845cf3eff344
        :steps:
            1. Take backup of files
            2. Configure domain_params
            3. Configure /etc/pam.d/sudo
            4. Configur /etc/pam.d/sudo-i
            5. Create IPA sudo rule of /usr/sbin/sssctl
               for user admin
            6. Check user admin can use sudo command
            7. Restore of files
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
        tools.clear_sssd_cache()
        domain_name = tools.get_domain_section_name()
        user = "admin"
        test_password = "Secret123"
        sys_hostname = multihost.client[0].sys_hostname
        multihost.client[0].run_command(
            f'su -l {user} -c "kinit"', stdin_text=test_password,
            raiseonerr=False)

        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudocmd-add /usr/sbin/sssctl"',
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add idm_user_sssctl"',
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-allow-command idm_user_sssctl'
            f' --sudocmds \'/usr/sbin/sssctl\'"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-host idm_user_sssctl --hosts'
            f' {sys_hostname}"', raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "ipa sudorule-add-user idm_user_sssctl --users'
            f' admin"', raiseonerr=False)
        tools.clear_sssd_cache()
        multihost.client[0].run_command(
            f'su -l {user} -c "kinit"', stdin_text=test_password,
            raiseonerr=False)
        multihost.client[0].run_command(
            f'su -l {user} -c "sudo -S -l"', stdin_text=test_password,
            raiseonerr=False)
        file_name = 'domain_list_' + str(time.time())
        client_login(multihost, user, test_password, 5)
        client_hostname = multihost.client[0].sys_hostname
        ssh = pexpect_ssh(client_hostname, user, test_password, debug=False)
        #check_login(user, client_hostname, test_password)
        ssh.fast_login_and_command(f'echo -e {test_password} | sudo -S /usr/sbin/sssctl domain-list > /tmp/{file_name}')
        ssh1 = ssh.fast_login_and_command(f'echo -e {test_password} | sudo -S /usr/sbin/sssctl domain-list')
        assert domain_name in str(ssh1)
