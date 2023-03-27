from __future__ import annotations

import shlex
from typing import Any

from pytest_mh.ssh import SSHClient, SSHLog, SSHProcess

from . import to_list_of_strings


class SSHKillableProcess(object):
    """
    Run an asynchronous process that requires ``SIGTERM`` to be terminated.
    """

    def __init__(
        self,
        client: SSHClient,
        argv: list[Any],
        *,
        cwd: str | None = None,
        env: dict[str, Any] | None = None,
        input: str | None = None,
        read_timeout: float = 2,
        log_level: SSHLog = SSHLog.Full,
    ) -> None:
        """
        :param client: SSH client.
        :type client: SSHClient
        :param argv: Command to run.
        :type argv: list[Any]
        :param cwd: Working directory, defaults to None (= do not change)
        :type cwd: str | None, optional
        :param env: Additional environment variables, defaults to None
        :type env: dict[str, Any] | None, optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param read_timeout: Timeout in seconds, how long should the client wait for output, defaults to 30 seconds
        :type read_timeout: float, optional
        :param log_level: Log level, defaults to SSHLog.Full
        :type log_level: SSHLog, optional
        """
        if env is None:
            env = {}

        argv = to_list_of_strings(argv)
        command = shlex.join(argv)
        pidfile = "/tmp/.mh.sshkillableprocess.pid"

        self.client: SSHClient = client
        self.process: SSHProcess = client.async_run(
            f"""
                set -m
                {command} &
                echo $! &> "{pidfile}"
                fg
            """,
            cwd=cwd,
            env=env,
            input=input,
            read_timeout=read_timeout,
            log_level=log_level,
        )

        # Get pid
        result = self.client.run(
            f"""
            until [ -f "{pidfile}" ]; do sleep 0.005; done
            cat "{pidfile}"
            rm -f "{pidfile}"
        """
        )

        self.pid = result.stdout.strip()
        """Process id."""

        self.kill_delay: int = 0
        """Wait ``kill_delay`` seconds before killing the process."""

        self.__killed: bool = False

    def kill(self) -> None:
        if self.__killed:
            return

        self.client.run(f"sleep {self.kill_delay}; kill {self.pid}")
        self.__killed = True

    def __enter__(self) -> SSHKillableProcess:
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self.kill()
        self.process.wait()
