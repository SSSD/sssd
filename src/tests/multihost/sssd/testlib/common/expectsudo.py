import os
import sys
import time

import pexpect
from pexpect import pxssh, ExceptionPexpect, TIMEOUT, EOF, spawn
from pexpect.pxssh import ExceptionPxssh
from sssd.testlib.common.exceptions import OSException


class pexpect_ssh(spawn):
    """
    pexpect methods: login(), logout(), command(), expect_command(),
                     sudo_correct_password(), sudo_permission_denied() and
                     sudo_incorrect_password()
    """

    def __init__(self, hostname, username, password, port=None,
                 encoding="utf-8", options=None,
                 enable_auto_prompt_reset=False,
                 enable_sync_original_prompt=False, debug=False):
        if options is None:
            options = {}
        spawn.__init__(self, command=None, timeout=30, maxread=4096,
                       searchwindowsize=None, logfile=None,
                       cwd=None, env=None, ignore_sighup=True, echo=True,
                       encoding=None, codec_errors="strict")
        """ Initilized defaults """
        self.PROMPT = r"\[PEXPECT\][\$\#] "  # setting prompt
        self.hostname = hostname
        self.username = username
        self.password = password
        self.encoding = encoding
        self.SSH_OPTS = ("-o'RSAAuthentication=no'"
                         + " -o 'PubkeyAuthentication=no'")
        self.options = options
        self.enable_auto_prompt_reset = enable_auto_prompt_reset
        self.enable_sync_original_prompt = enable_sync_original_prompt
        self.force_password = False
        if port is None:
            self.port = 22
        else:
            self.port = port
        self.ssh_options = {"StrictHostKeyChecking": "no",
                            "UserKnownHostsFile": "/dev/null"}
        self.ssh = pxssh.pxssh(options=self.ssh_options, timeout=30,
                               maxread=4096, searchwindowsize=1500)
        if debug:
            self.ssh.logfile = sys.stdout.buffer

    def login(self, terminal_type="ansi",
              original_prompt=r"[#$]", login_timeout=30, port=None,
              ssh_key=None, quiet=True, check_local_ip=True):
        """This logs the user into the given server.

        It uses
        'original_prompt' to try to find the prompt right after login. When it
        finds the prompt it immediately tries to reset the prompt to something
        more easily matched. The default 'original_prompt' is very optimistic
        and is easily fooled. It's more reliable to try to match the original
        prompt as exactly as possible to prevent false matches by server
        strings such as the "Message Of The Day". On many systems you can
        disable the MOTD on the remote server by creating a zero-length file
        called :file:`~/.hushlogin` on the remote server. If a prompt cannot
        be found then this will not necessarily cause the login to fail.
        In the case of a timeout when looking for the prompt we assume that
        the original prompt was so weird that we could not match it, so we
        use a few tricks to guess when we have reached the prompt. Then we
        hope for the best and blindly try to reset the prompt to something
        more unique. If that fails then login() raises an
        :class:`ExceptionPxssh` exception.

        In some situations it is not possible or desirable to reset the
        original prompt. In this case, pass ``auto_prompt_reset=False`` to
        inhibit setting the prompt to the UNIQUE_PROMPT. Remember that pxssh
        uses a unique prompt in the :meth:`prompt` method. If the original
        prompt is not reset then this will disable the :meth:`prompt` method
        unless you manually set the :attr:`PROMPT` attribute.
        """

        ssh_options = ''.join([" -o '%s=%s'" % (o, v) for (o, v) in
                               self.options.items()])
        if quiet:
            ssh_options = ssh_options + " -q"
        if not check_local_ip:
            ssh_options = ssh_options + " -o'NoHostAuthenticationFor" \
                                        "Localhost=yes'"
        if self.force_password:
            ssh_options = ssh_options + " " + self.SSH_OPTS
        if port is not None:
            ssh_options = ssh_options + " -p %s" % (str(port))
        if ssh_key is not None:
            try:
                os.path.isfile(ssh_key)
            except ExceptionPexpect:
                print("private ssh key does not exist")
            ssh_options = ssh_options + " -i %s" % ssh_key
        cmd = "ssh %s -l %s %s" % (ssh_options, self.username, self.hostname)

        # This does not distinguish between a remote server 'password' prompt
        # and a local ssh 'passphrase' prompt (for unlocking a private key).
        self.ssh._spawn(cmd)
        login_list = self.ssh.compile_pattern_list([r"(?i)are you sure you "
                                                    r"want to continue "
                                                    r"connecting",
                                                    original_prompt,
                                                    r"(?i)(?:password:)|"
                                                    r"(?:passphrase for key)",
                                                    r"(?i)permission denied",
                                                    r"(?i)terminal type",
                                                    pexpect.TIMEOUT,
                                                    r"(?i)connection closed"
                                                    r" by remote host",
                                                    pexpect.EOF])
        i = self.ssh.expect_list(login_list, timeout=login_timeout)
        # First phase
        if i == 0:
            # New certificate -- always accept it.
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            self.ssh.sendline("yes")
            i_0 = self.ssh.compile_pattern_list([r"(?i)are you sure you"
                                                 r" want to continue "
                                                 r"connecting",
                                                 original_prompt,
                                                 r"(?i)(?:password:)|"
                                                 r"(?:passphrase for key)",
                                                 r"(?i)permission denied",
                                                 r"(?i)terminal type",
                                                 pexpect.TIMEOUT])
            i = self.ssh.expect_list(i_0)
        if i == 2:  # password or passphrase
            i_2 = self.ssh.compile_pattern_list([r"(?i)are you sure you"
                                                 r" want to continue "
                                                 r"connecting",
                                                 original_prompt,
                                                 r"(?i)(?:password:)|"
                                                 r"(?:passphrase for key)",
                                                 r"(?i)permission denied",
                                                 r"(?i)terminal type",
                                                 pexpect.TIMEOUT])
            self.ssh.sendline(self.password)
            i = self.ssh.expect_list(i_2)
        if i == 4:
            i_4 = self.ssh.compile_pattern_list([r"(?i)are you sure you want"
                                                 r" to continue connecting",
                                                 original_prompt,
                                                 r"(?i)(?:password:)|"
                                                 r"(?:passphrase for key)",
                                                 "(?i)permission denied",
                                                 "(?i)terminal type",
                                                 pexpect.TIMEOUT])
            self.ssh.sendline(terminal_type)
            i = self.ssh.expect_list(i_4)
        if i == 7:
            self.ssh.close()
            raise ExceptionPxssh("Could not establish connection to host")

        # Second phase
        if i == 0:
            # This is weird. This should not happen twice in a row.
            self.ssh.close()
            raise ExceptionPxssh("Weird error. Got 'are you sure' "
                                 "prompt twice.")
        elif i == 1:  # can occur if you have a public key pair set to
            # authenticate.
            pass
        elif i == 2:  # password prompt again
            # For incorrect passwords, some ssh servers will
            # ask for the password again, others return 'denied' right away.
            # If we get the password prompt again then this means
            # we didn't get the password right the first time.
            self.ssh.close()
            raise ExceptionPxssh("password refused")
        elif i == 3:  # permission denied -- password was bad.
            self.ssh.close()
            raise ExceptionPxssh("permission denied")
        elif i == 4:  # terminal type again
            self.ssh.close()
            raise ExceptionPxssh("Weird error. Got 'terminal type' "
                                 "prompt twice.")
        elif i == 5:  # Timeout
            # This is tricky... I presume that we are at the command-line
            # prompt. It may be that the shell prompt was so weird that we
            # couldn't match it. Or it may be that we couldn't log in for
            # some other reason. I can't be sure, but it's safe to guess
            # that we did login because if I presume wrong and we are not
            # logged in then this should be caught later when I try to set
            # the shell prompt.
            pass
        elif i == 6:  # Connection closed by remote host
            self.ssh.close()
            raise ExceptionPxssh("connection closed")
        else:  # Unexpected
            self.ssh.close()
            raise ExceptionPxssh("unexpected login response")
        if self.enable_sync_original_prompt:
            if not self.ssh.sync_original_prompt(1):
                self.ssh.close()
                raise ExceptionPxssh("could not synchronize with "
                                     "original prompt")
        # We appear to be in.
        # set shell prompt to something unique.
        if self.enable_auto_prompt_reset:
            if not self.ssh.set_unique_prompt():
                self.ssh.close()
                raise ExceptionPxssh("could not set shell prompt "
                                     "(received: %r, expected: %r)." % (
                                         self.ssh.before, self.PROMPT,))
        return True

    def logout(self):
        """ Logout of ssh session """
        self.ssh.sendline("exit")
        index = self.ssh.expect(["(?i)there are stopped jobs", pexpect.EOF,
                                 pexpect.TIMEOUT])
        if index == 1:
            self.ssh.sendline("exit")
        self.ssh.close()

    def command(self, command, raiseonerr=False):
        """
        Run Non interactive Commands
        :param command: command to be tested
        :param raiseonerr: raise exception if returncode is non-zero
        :return: stdout, returncode of command tested
        """
        self.ssh.sendline(command)
        self.ssh.prompt()
        output_utf8 = self.ssh.before
        self.ssh.sendline("echo $?")
        self.ssh.prompt()
        returncode = self.ssh.before
        ret = returncode.decode("utf-8").split('\r')[1].strip('\n')
        output_str = output_utf8.decode("utf-8")
        if raiseonerr:
            if (int(ret)) != 0:
                raise OSException("Command failed with err: %s" % output_str)
        return output_str, ret

    def expect_command(self, command, password, password_prompt, regex):
        """
        Run interactive command prompting for password
        :param command: command to be tested
        :param password: password that needs to be input
        :param password_prompt: regex for password prompt
        :param regex: regex for what needs to be checked
        :return: stdout, returncode of command tested
        """
        self.ssh.sendline(command)
        try:
            pw_prompt_list = self.ssh.compile_pattern_list([password_prompt,
                                                           pexpect.EOF,
                                                           pexpect.TIMEOUT])
            index = self.ssh.expect_list(pw_prompt_list)
            if index != 0:
                return "Issues searching with provided password " \
                       "prompt regex", 1
        except ExceptionPexpect as ex:
            print(ex)
        self.ssh.sendline(password)
        self.ssh.prompt()
        output_utf8 = self.ssh.before
        try:
            compiled_list = self.ssh.compile_pattern_list([regex, pexpect.EOF,
                                                           pexpect.TIMEOUT])
            index = self.ssh.expect_list(compiled_list)
            if index == 0:
                return output_utf8.decode("utf-8"), 0
            else:
                return output_utf8.decode("utf-8"), 1
        except ExceptionPexpect as ex:
            print(ex)

    def sudo_permission_granted(self, sudocommand="sudo whoami",
                                password="Secret123",
                                password_prompt_regex="(?i).*password.*:",
                                granted_regex=r"(?i)^(?!.*try again.*)"
                                              r"(?!.*incorrect password.*)"
                                              r"(?!.*not allowed.*)"
                                              r"(?!.*reported.*)"
                                              r"(?!.*have a tty.*)"
                                              r"(?!.*no right to run.*)"
                                              r"(?!.*unknown.*)"
                                              r"(?!.*sorry.*)"
                                              r"(?!.*may not run.*)"
                                              r"(?!.*unable to initialize.*)"
                                              r"(?!.*a terminal is required.*)"
                                              r"(?!.*configure an askpass "
                                              r"helper.*).*$"):
        """
        1) This method checks that password provided to perform sudo is correct
        and user/group is granted permission to perform sudo operation.
        2) If returncode=0 -> correct password,
              returncode=1 -> incorrect password/permission denied
        :param sudocommand: sudo command to be tested
        :param password: password for testing sudo user
        :param password_prompt_regex: regex for password prompt
        :param granted_regex: regex for correct password string
        :return: stdout, returncode
        """
        self.__init__(self.hostname, self.username, self.password)
        self.login()
        (stdout, returncode) = self.expect_command(sudocommand, password,
                                                   password_prompt_regex,
                                                   granted_regex)
        self.logout()
        return stdout, returncode

    def sudo_permission_denied(self, sudocommand="sudo whoami",
                               password="Secret123",
                               password_prompt_regex="(?i).*password.*:",
                               denied_regex=r"(?i).*not allowed.*|"
                                            r".*reported.*|"
                                            r".*have a tty.*|"
                                            r".*no right to run.*|"
                                            r".*unknown.*|"
                                            r".*unable to "
                                            r"initialize.*"):
        """
        1) This method checks whether the user/group is allowed to perform
        sudo operation after entering correct password.
        2) If returncode=0 -> permission denied,
              returncode=1 -> permission allowed/incorrect password
        :param sudocommand: sudo command to be tested
        :param password: user/group password for testing sudo
        :param password_prompt_regex: regex for password prompt
        :param denied_regex: regex for permission denied string
        :return: stdout, returncode
        """
        self.__init__(self.hostname, self.username, self.password)
        self.login()
        (stdout, returncode) = self.expect_command(sudocommand, password,
                                                   password_prompt_regex,
                                                   denied_regex)
        self.logout()
        return stdout, returncode

    def sudo_incorrect_password(self, sudocommand="sudo whoami",
                                password="Secret123",
                                password_prompt_regex="(?i).*password.*:",
                                incorrect_password_regex=r"(?i).*try again.*|"
                                                         r".*incorrect "
                                                         r"password.*"):
        """
        1) This method aims at checking if the password provided to perform
        sudo is incorrect or not
        2) If returncode=0 -> incorrect password,
              returncode=1 -> correct password/permission denied
        :param sudocommand: sudo command to be tested
        :param password: user/group password for testing sudo
        :param password_prompt_regex: regex for password prompt
        :param incorrect_password_regex: regex for incorrect password string
        :return: stdout, returncode
        """
        self.__init__(self.hostname, self.username, self.password)
        self.login()
        (stdout, returncode) = self.expect_command(sudocommand, password,
                                                   password_prompt_regex,
                                                   incorrect_password_regex)
        self.logout()
        return stdout, returncode

    def sudo_requires_auth(self, sudocommand="sudo whoami",
                           password="Secret123",
                           password_prompt_regex="(?i).*password.*:"):
        """
        1)This method aims at checking if sudo user/group requires
        authentication prompt or not.
        2)If returncode=0 -> requires auth,
             returncode=1 -> no auth required/incorrect password/permission
             denied
        :param sudocommand: sudo command to be tested
        :param password: user/group password for testing sudo
        :param password_prompt_regex: regex for password prompt
        :return: stdout, returncode
        """
        self.__init__(self.hostname, self.username, self.password)
        self.login()
        self.ssh.sendline(sudocommand)
        try:
            regex_list = self.ssh.compile_pattern_list([password_prompt_regex,
                                                        r"(?i).*a terminal "
                                                        r"is required.*|"
                                                        r".*use the -S "
                                                        r"option.*|"
                                                        r".*configure an "
                                                        r"askpass helper.*",
                                                        EOF, TIMEOUT])
            index = self.ssh.expect_list(regex_list)
            if index == 0:
                self.ssh.sendline(password)
                self.ssh.prompt()
                output_utf8 = self.ssh.before
                self.logout()
                return output_utf8.decode("utf-8"), 0
            elif index == 1:
                self.ssh.prompt()
                output_utf8 = self.ssh.before
                self.logout()
                return output_utf8.decode("utf-8"), 1
            else:
                return "No password prompt or 'terminal is required' " \
                       "message encountered ", 1
        except ExceptionPexpect as ex:
            print(ex)
