import socket
from ssh2.session import Session


class SSHClient:
    """ ssh2 methods """
    def __init__(self, hostname, username, password):
        """Initialize defaults"""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.session = None

    def connect(self):
        """login to host"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.hostname, 22))
        session = Session()
        session.handshake(sock)
        session.userauth_password(self.username, self.password)
        self.session = session

    def execute_command(self, command):
        """Run Non interactive Commands"""
        channel = self.session.open_session()
        channel.execute(command)
        size, data = channel.read()
        output = ""
        while size > 0:
            output += data.decode()
            size, data = channel.read()
        channel.close()
        return output

    def close(self):
        """Logout of ssh session"""
        if self.session:
            self.session.disconnect()


def check_login(hostname, user, password):
    """This function will check user login
    user: Name of the user.
    hostname: Name of the machine where user will login.
    password: User password.
    """
    ssh = SSHClient(hostname, user, password)
    ssh.connect()
    ssh.close()


def check_login_client(multihost, user, password):
    """This function will check user login
    user: Name of the user.
    password: User password.
    """
    hostname = multihost.client[0].ip
    ssh = SSHClient(hostname, user, password)
    ssh.connect()
    ssh.close()


def run_command(hostname, user, password, command):
    """This function will execute command
    user: Name of the user.
    hostname: Name of the machine where user will login.
    password: User password.
    command: User command
    """
    ssh = SSHClient(hostname, user, password)
    ssh.connect()
    result = ssh.execute_command(command)
    ssh.close()
    return result


def run_command_client(multihost, user, password, command):
    """This function will execute command
    user: Name of the user.
    hostname: Name of the machine where user will login.
    password: User password.
    command: User command
    """
    hostname = multihost.client[0].ip
    ssh = SSHClient(hostname, user, password)
    ssh.connect()
    result = ssh.execute_command(command)
    ssh.close()
    return result
