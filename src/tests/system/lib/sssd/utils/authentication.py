"""Testing authentications and authorization mechanisms."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.ssh import SSHClient, SSHProcessResult

__all__ = [
    "AuthenticationUtils",
    "KerberosAuthenticationUtils",
    "SSHAuthenticationUtils",
    "SUAuthenticationUtils",
    "SudoAuthenticationUtils",
]


class AuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing various authentication and authorization mechanisms.

    It executes commands on remote host in order to test authentication and
    authorization via su, ssh, sudo and kerberos.

    .. note::

        Since the authentication via su and ssh command can be mostly done via
        the same mechanisms (like password or two-factor authentication), it
        implements the same API. Therefore you can test su and ssh in the same
        test case through parametrization.

        .. code-block:: python
            :caption: Example

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            @pytest.mark.parametrize('method', ['su', 'ssh'])
            def test_example(client: Client, provider: GenericProvider, method: str):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.parametrize(method).password('tuser', 'Secret123')
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.su: SUAuthenticationUtils = SUAuthenticationUtils(host)
        """
        Test authentication and authorization via su.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.su.password('tuser', 'Secret123')
        """

        self.sudo: SudoAuthenticationUtils = SudoAuthenticationUtils(host)
        """
        Test authentication and authorization via sudo.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add(password='Secret123')
                ldap.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
                assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')
        """

        self.ssh: SSHAuthenticationUtils = SSHAuthenticationUtils(host)
        """
        Test authentication and authorization via ssh.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.ssh.password('tuser', 'Secret123')
        """

    def parametrize(self, method: str) -> SUAuthenticationUtils | SSHAuthenticationUtils:
        """
        Return authentication tool based on the method. The method can be
        either ``su`` or ``ssh``.

        :param method: ``su`` or ``ssh``
        :type method: str
        :raises ValueError: If invalid method is specified.
        :return: Authentication tool.
        :rtype: HostSU | HostSSH
        """

        allowed = ["su", "ssh"]
        if method not in allowed:
            raise ValueError(f"Unknown method {method}, choose from {allowed}.")

        return getattr(self, method)

    def kerberos(self, ssh: SSHClient) -> KerberosAuthenticationUtils:
        """
        Test authentication and authorization via Kerberos.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP, kdc: KDC):
                ldap.user('tuser').add()
                kdc.principal('tuser').add()

                client.sssd.common.krb5_auth(kdc)
                client.sssd.start()

                with client.ssh('tuser', 'Secret123') as ssh:
                    with client.auth.kerberos(ssh) as krb:
                        assert krb.has_tgt(kdc.realm)

        :param ssh: SSH connection for the target user.
        :type ssh: SSHClient
        :return: Kerberos authentication object.
        :rtype: KerberosAuthenticationUtils
        """
        return KerberosAuthenticationUtils(self.host, ssh)


class SUAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication and authorization via su.
    """

    def password(self, username: str, password: str) -> bool:
        """
        Call ``su - $username`` and authenticate the user with password.

        :param name: User name.
        :type name: str
        :param password: User password.
        :type password: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """

        result = self.host.ssh.expect_nobody(
            rf"""
            # It takes some time to get authentication failure
            set timeout 10
            set prompt "\n.*\[#\$>\] $"

            spawn su - "{username}"

            expect {{
                "Password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                -re $prompt {{puts "expect result: Password authentication successful"; exit 0}}
                "Authentication failure" {{puts "expect result: Authentication failure"; exit 4}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            puts "expect result: Unexpected code path"
            exit 3
        """
        )

        return result.rc == 0

    def password_expired(self, username: str, password: str, new_password: str) -> bool:
        """
        Call ``su - $username`` and authenticate the user with password, expect
        that the password is expired and change it to the new password.

        :param username: User name.
        :type name: str
        :param password: Old, expired user password.
        :type password: str
        :param new_password: New user password.
        :type new_password: str
        :return: True if authentication and password change was successful, False otherwise.
        :rtype: bool
        """
        result = self.host.ssh.expect_nobody(
            rf"""
            # It takes some time to get authentication failure
            set timeout 10
            set prompt "\n.*\[#\$>\] $"

            spawn su - "{username}"

            expect {{
                "Password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "Password expired. Change your password now." {{ }}
                -re $prompt {{puts "expect result: Authentication succeeded without password change"; exit 3}}
                "Authentication failure" {{puts "expect result: Authentication failure"; exit 4}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "Current Password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "New password:" {{send "{new_password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "Retype new password:" {{send "{new_password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                -re $prompt {{puts "expect result: Password change was successful"; exit 0}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            puts "expect result: Unexpected code path"
            exit 3
        """
        )

        return result.rc == 0


class SSHAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication and authorization via ssh.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.opts = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        """SSH CLI options."""

    def password(self, username: str, password: str) -> bool:
        """
        SSH to the remote host and authenticate the user with password.

        :param name: User name.
        :type name: str
        :param password: User password.
        :type password: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """

        result = self.host.ssh.expect_nobody(
            rf"""
            # It takes some time to get authentication failure
            set timeout 10
            set prompt "\n.*\[#\$>\] $"

            spawn ssh {self.opts} \
                -o PreferredAuthentications=password \
                -o NumberOfPasswordPrompts=1 \
                -l "{username}" localhost

            expect {{
                "password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                -re $prompt {{puts "expect result: Password authentication successful"; exit 0}}
                "{username}@localhost: Permission denied" {{puts "expect result: Authentication failure"; exit 4}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            puts "expect result: Unexpected code path"
            exit 3
        """
        )

        return result.rc == 0

    def password_expired(self, username: str, password: str, new_password: str) -> bool:
        """
        SSH to the remote host and authenticate the user with password, expect
        that the password is expired and change it to the new password.

        :param username: User name.
        :type name: str
        :param password: Old, expired user password.
        :type password: str
        :param new_password: New user password.
        :type new_password: str
        :return: True if authentication and password change was successful, False otherwise.
        :rtype: bool
        """
        result = self.host.ssh.expect_nobody(
            rf"""
            # It takes some time to get authentication failure
            set timeout 10
            set prompt "\n.*\[#\$>\] $"

            spawn ssh {self.opts} \
                -o PreferredAuthentications=password \
                -o NumberOfPasswordPrompts=1 \
                -l "{username}" localhost

            expect {{
                "password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "Password expired. Change your password now." {{ }}
                -re $prompt {{puts "expect result: Authentication succeeded without password change"; exit 3}}
                "{username}@localhost: Permission denied" {{puts "expect result: Authentication failure"; exit 4}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "Current Password:" {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "New password:" {{send "{new_password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "Retype new password:" {{send "{new_password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                "passwd: all authentication tokens updated successfully." {{ }}
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Unexpected end of file"; exit 2}}
            }}

            expect {{
                timeout {{puts "expect result: Unexpected output"; exit 1}}
                eof {{puts "expect result: Password change was successful"; exit 0}}
            }}

            puts "expect result: Unexpected code path"
            exit 3
        """
        )

        return result.rc == 0


class SudoAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication and authorization via sudo.
    """

    def run(self, username: str, password: str | None = None, *, command: str) -> bool:
        """
        Execute sudo command.

        :param username: Username that calls sudo.
        :type username: str
        :param password: User password, defaults to None
        :type password: str | None, optional
        :param command: Command to execute (make sure to properly escape any quotes).
        :type command: str
        :return: True if the command was successful, False if the command failed or the user can not run sudo.
        :rtype: bool
        """
        result = self.host.ssh.run(
            f'su - "{username}" -c "sudo --stdin {command}"', input=password, raise_on_error=False
        )

        return result.rc == 0

    def list(self, username: str, password: str | None = None, *, expected: list[str] | None = None) -> bool:
        """
        List commands that the user can run under sudo.

        :param username: Username that runs sudo.
        :type username: str
        :param password: User password, defaults to None
        :type password: str | None, optional
        :param expected: List of expected commands (formatted as sudo output), defaults to None
        :type expected: list[str] | None, optional
        :return: True if the user can run sudo and allowed commands match expected commands (if set), False otherwise.
        :rtype: bool
        """
        result = self.host.ssh.run(f'su - "{username}" -c "sudo --stdin -l"', input=password, raise_on_error=False)
        if result.rc != 0:
            return False

        if expected is None:
            return True

        allowed = []
        for line in reversed(result.stdout_lines):
            if not line.startswith("    "):
                break
            allowed.append(line.strip())

        for line in expected:
            if line not in allowed:
                return False
            allowed.remove(line)

        if len(allowed) > 0:
            return False

        return True


class KerberosAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing Kerberos authentication and KCM.
    """

    def __init__(self, host: MultihostHost, ssh: SSHClient | None = None) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        :param ssh: SSH client for the target user, defaults to None
        :type ssh: SSHClient | None, optional
        """
        super().__init__(host)

        self.ssh: SSHClient = ssh if ssh is not None else host.ssh
        """SSH client for the target user."""

    def kinit(
        self, principal: str, *, password: str, realm: str | None = None, args: list[str] | None = None
    ) -> SSHProcessResult:
        """
        Run ``kinit`` command.

        Principal can be without the realm part. The realm can be given in
        separate parameter ``realm``, in such case the principal name is
        constructed as ``$principal@$realm``. If the principal does not contain
        realm specification and ``realm`` parameter is not set then the default
        realm is used.

        :param principal: Kerberos principal.
        :type principal: str
        :param password: Principal's password.
        :type password: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``), defaults to None
        :type realm: str | None, optional
        :param args: Additional parameters to ``klist``, defaults to None
        :type args: list[str] | None, optional
        :return: Command result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        if realm is not None:
            principal = f"{principal}@{realm}"

        return self.ssh.exec(["kinit", *args, principal], input=password)

    def kvno(self, principal: str, *, realm: str | None = None, args: list[str] | None = None) -> SSHProcessResult:
        """
        Run ``kvno`` command.

        Principal can be without the realm part. The realm can be given in
        separate parameter ``realm``, in such case the principal name is
        constructed as ``$principal@$realm``. If the principal does not contain
        realm specification and ``realm`` parameter is not set then the default
        realm is used.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``), defaults to None
        :type realm: str | None, optional
        :param args: Additional parameters to ``klist``, defaults to None
        :type args: list[str] | None, optional
        :return: Command result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        if realm is not None:
            principal = f"{principal}@{realm}"

        return self.ssh.exec(["kvno", *args, principal])

    def klist(self, *, args: list[str] | None = None) -> SSHProcessResult:
        """
        Run ``klist`` command.

        :param args: Additional parameters to ``klist``, defaults to None
        :type args: list[str] | None, optional
        :return: Command result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        return self.ssh.exec(["klist", *args])

    def kswitch(self, principal: str, realm: str) -> SSHProcessResult:
        """
        Run ``kswitch -p principal@realm`` command.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``)
        :type realm: str
        :return: Command result.
        :rtype: SSHProcessResult
        """
        if "@" not in principal:
            principal = f"{principal}@{realm}"

        return self.ssh.exec(["kswitch", "-p", principal])

    def kdestroy(
        self, *, all: bool = False, ccache: str | None = None, principal: str | None = None, realm: str | None = None
    ) -> SSHProcessResult:
        """
        Run ``kdestroy`` command.

        Principal can be without the realm part. The realm can be given in
        separate parameter ``realm``, in such case the principal name is
        constructed as ``$principal@$realm``. If the principal does not contain
        realm specification and ``realm`` parameter is not set then the default
        realm is used.

        :param all: Destroy all ccaches (``kdestroy -A``), defaults to False
        :type all: bool, optional
        :param ccache: Destroy specific ccache (``kdestroy -c $cache``), defaults to None
        :type ccache: str | None, optional
        :param principal: Destroy ccache for given principal (``kdestroy -p $princ``), defaults to None
        :type principal: str | None, optional
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``), defaults to None
        :type realm: str | None, optional
        :return: Command result.
        :rtype: SSHProcessResult
        """
        args = []

        if all:
            args.append("-A")

        if ccache is not None:
            args.append("-c")
            args.append(ccache)

        if realm is not None and principal is not None:
            principal = f"{principal}@{realm}"

        if principal is not None:
            args.append("-p")
            args.append(principal)

        return self.ssh.exec(["kdestroy", *args])

    def has_tgt(self, principal: str | None, realm: str) -> bool:
        """
        Check that the user has obtained Kerberos Ticket Granting Ticket for
        given principle. If ``principal`` is ``None`` then primary principal is
        checked.

        :param principal: Expected principal for which the TGT was obtained (without the realm part).
        :type principle: str | None
        :param realm: Expected realm for which the TGT was obtained.
        :type realm: str
        :return: True if TGT is available, False otherwise.
        :rtype: bool
        """
        if principal is not None:
            result = self.klist()
            return f"krbtgt/{realm}@{realm}" in result.stdout

        principals = self.list_principals()
        tickets = principals.get(f"{principal}@{realm}", [])

        return "krbtgt/{realm}@{realm}" in tickets

    def has_primary_cache(self, principal: str, realm: str) -> bool:
        """
        Check that the ccache for given principal is the primary one.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``)
        :type realm: str
        :return: True if the ccache for given principal is the primary one.
        :rtype: bool
        """
        result = self.ssh.exec(["klist", "-l"], raise_on_error=False)
        if result.rc != 0:
            return False

        if len(result.stdout_lines) <= 2:
            return False

        primary = result.stdout_lines[2]

        return f"{principal}@{realm}" in primary

    def has_tickets(self, principal: str, realm: str, expected: list[str]) -> bool:
        """
        Check that the ccache contains all tickets from ``expected`` and nothing
        more.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal
            (``$principal@$realm``)
        :type realm: str
        :param expected: List of tickets that must be present in the ccache.
        :type expected: list[str]
        :return: True if the ccache contains exactly ``expected`` tickets.
        :rtype: bool
        """
        ccaches = self.list_principals()
        principal = f"{principal}@{realm}"

        if principal not in ccaches:
            return False

        return ccaches[principal] == expected

    def cache_count(self) -> int:
        """
        Return number of existing credential caches (or number of principals)
        for active user (klist -l).

        :return: Number of existing ccaches.
        :rtype: int
        """
        result = self.ssh.exec(["klist", "-l"], raise_on_error=False)
        if result.rc != 0:
            return 0

        if len(result.stdout_lines) <= 2:
            return 0

        return len(result.stdout_lines) - 2

    def list_principals(self, env: dict[str, Any] | None = None) -> dict[str, list[str]]:
        """
        List all principals that have existing credential cache.

        :param env: Additional environment variables passed to ``klist -A`` command, defaults to None
        :type env: dict[str, Any] | None, optional
        :return: Dictionary with principal as the key and list of available tickets as value.
        :rtype: dict[str, list[str]]
        """

        def __parse_output(result: SSHProcessResult) -> dict[str, list[str]]:
            ccache_principal: str | None = None
            ccache: dict[str, list[str]] = dict()

            for line in result.stdout_lines:
                if line.startswith("Default principal"):
                    ccache_principal = line.split()[-1]
                    ccache.setdefault(ccache_principal, [])
                    continue

                if ccache_principal is not None and "@" in line:
                    ticket = line.split()[-1]
                    ccache[ccache_principal].append(ticket)

            return ccache

        result = self.ssh.exec(["klist", "-A"], env=env, raise_on_error=False)
        if result.rc != 0:
            return dict()

        return __parse_output(result)

    def list_ccaches(self) -> dict[str, str]:
        """
        List all available ccaches.

        :return: Dictionary with principal as the key and ccache name as value.
        :rtype: dict[str, str]
        """

        def __parse_output(result: SSHProcessResult) -> dict[str, str]:
            if len(result.stdout_lines) <= 2:
                return dict()

            ccaches: dict[str, str] = dict()
            for line in result.stdout_lines[2:]:
                (principal, ccache) = line.split(maxsplit=2)
                ccaches[principal] = ccache

            return ccaches

        result = self.ssh.exec(["klist", "-l"], raise_on_error=False)
        if result.rc != 0:
            return dict()

        return __parse_output(result)

    def list_tgt_times(self, realm: str) -> tuple[datetime, datetime]:
        """
        Return start and expiration time of primary ccache TGT.

        :param realm: Expected realm for which the TGT was obtained.
        :type realm: str
        :return: (start time, expiration time) of the TGT
        :rtype: tuple[int, int]
        """
        tgt = f"krbtgt/{realm}@{realm}"
        result = self.klist()
        for line in result.stdout_lines:
            if tgt in line:
                (sdate, stime, edate, etime, principal) = line.split(maxsplit=5)

                start = None
                end = None

                # format may be different on different hosts
                for format in ["%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                    try:
                        start = datetime.strptime(f"{sdate} {stime}", format)
                        end = datetime.strptime(f"{edate} {etime}", format)
                    except ValueError:
                        continue

                if start is None:
                    raise ValueError(f"Unable to parse datetime: {sdate} {stime}")

                if end is None:
                    raise ValueError(f"Unable to parse datetime: {edate} {etime}")

                return (start, end)

        raise Exception("TGT was not found")

    def __enter__(self) -> KerberosAuthenticationUtils:
        """
        Connect to the host over ssh if not already connected.

        :return: Self..
        :rtype: HostKerberos
        """
        self.ssh.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        """
        Disconnect.
        """
        self.kdestroy(all=True)
