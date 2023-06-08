import re


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    assert string_name in log_str


def count_pattern_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    return len(re.findall(string_name, multihost.client[0].get_file_contents(log_name).decode('utf-8')))


def client_backup_file(multihost, file_path):
    """This function will backup file in client machine
    file_path: String, Absolute path of file.
    """
    client = multihost.client[0]
    file_content = client.get_file_contents(file_path)
    client.put_file_contents(file_path+'_bkp', file_content)


def client_restore_file(multihost, file_path):
    """This function will restore file in client machine
    file_path: String, Absolute path of file.
    """
    client = multihost.client[0]
    file_content = client.get_file_contents(file_path)
    client.put_file_contents(file_path.split("_bkp")[0], file_content)


def client_remove_file(multihost, file_path):
    """This function will remove file in client machine
    file_path: String, Absolute path of file.
    """
    client = multihost.client[0]
    client.run_command(f"rm -vf {file_path}")


def count_lines(multihost, log_name):
    """This function will count no of lines of a file
    file_path: String, Absolute path of file.
    """
    return len(multihost.client[0].get_file_contents(log_name).decode('utf-8').split('\n')) - 1


def search_string_in_file(multihost, start_line, search_string, file_path):
    """This function will find strings in a log file
    file_path: String, Absolute path of file.
    search_string: String, to find in the log.
    start_line: int, number of line from where search will start
    """
    file = multihost.client[0].get_file_contents(file_path).decode('utf-8').split('\n')
    current_line = 1
    finding_list = []
    for line in file:
        if current_line >= start_line and search_string in line:
            finding_list.append(f"Found '{search_string}' in {file_path} at line {current_line}: {line.strip()}")
        current_line += 1
    return finding_list
