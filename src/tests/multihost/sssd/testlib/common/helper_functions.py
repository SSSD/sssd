"""
This script contains helper functions that can be used in test.
"""

import time
from sssd.testlib.common.expect import pexpect_ssh


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    assert string_name in log_str, f'failed to find string in {log_str}'


def truncate_logs(multihost, log_name):
    """This function will truncate log file
    log_name: Absolute path of log where the truncate will happen.
    """
    multihost.client[0].run_command(f"> {log_name}")


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
                               sync_multiplier=5,
                               auto_prompt_reset=False)
        except Exception:
            time.sleep(3)
            continue
        if ssh:
            client.logout()
            break
    else:
        raise Exception("User failed to login")
