from .expect import pexpect_ssh


ds_instance_name = 'example1'


def check_login(user, hostname, password):
    """This function will check user login
    user: Name of the user.
    hostname: Name of the machine where user will login.
    password: User password.
    """
    client = pexpect_ssh(hostname, user, password, debug=False).fast_login()
    assert client != b''


def clear_only_domain_log(multihost):
    """
    This function will clear domain logs
    """
    client = multihost.client[0]
    log_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
    client.run_command(f'> {log_ssd}')


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    assert string_name in log_str
