""" pexpect methods """

import sys
import pexpect
from pexpect import pxssh
from .exceptions import SSHLoginException
from .exceptions import OSException


class pexpect_ssh(object):
    """ pexpect methods """
    def __init__(self, hostname, username,
                 password, port=None,
                 encoding='utf-8', debug=False):
        """ Initilized defaults """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.encoding = encoding
        if port is None:
            self.port = 22
        else:
            self.port = port
        self.ssh_options = {'StrictHostKeyChecking': 'no',
                            'UserKnownHostsFile': '/dev/null'}
        self.ssh = pxssh.pxssh(options=self.ssh_options)
        if debug:
            self.ssh.logfile = sys.stdout.buffer

    def login(self, login_timeout=10, auto_prompt_reset=True,
              sync_multiplier=1):
        """ login to host """
        self.PROMPT = r"\[PEXPECT\][\$\#] "
        try:
            self.ssh.login(self.hostname, self.username,
                           self.password, port=self.port,
                           login_timeout=login_timeout,
                           auto_prompt_reset=auto_prompt_reset,
                           sync_multiplier=sync_multiplier)
        except pexpect.pxssh.ExceptionPxssh:
            raise SSHLoginException("%s Failed to login" % self.username)

    def command(self, command, raiseonerr=False):
        """ Run Non interactive Commands """
        self.ssh.sendline(command)
        self.ssh.prompt()
        output_utf8 = self.ssh.before
        self.ssh.sendline("echo $?")
        self.ssh.prompt()
        returncode = self.ssh.before
        ret = returncode.decode('utf-8').split('\r')[1].strip('\n')
        output_str = output_utf8.decode('utf-8')
        if raiseonerr:
            if (int(ret)) != 0:
                raise OSException('Command failed with err: %s' % (output_str))
        return (output_str, ret)

    def expect_command(self, command, password, raiseonerr=False):
        """ Run interactive command prompting for password * """
        self.ssh.sendline(command)
        self.ssh.expect('Password.*.')
        self.ssh.sendline(password)
        cmd = self.ssh.expect(['Password incorrect .*.', r'[#\$] '])
        if cmd == 0:
            print("Password Incorrect")
        elif cmd == 1:
            print("Correct Password")
        output_utf8 = self.ssh.before
        self.ssh.sync_original_prompt()
        self.ssh.set_unique_prompt()
        self.ssh.sendline("echo $?")
        self.ssh.prompt()
        returncode = self.ssh.before.decode('utf-8')
        output_str = output_utf8.decode('utf-8')
        if raiseonerr:
            if (int(returncode)) != 0:
                raise OSException('Command failed with err: %s' % (output_str))
        return(output_str, returncode)

    def logout(self):
        """ Logout of ssh session """
        self.ssh.logout()
