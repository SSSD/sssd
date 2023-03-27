"""Run various standard Linux commands on remote host."""

from __future__ import annotations

from typing import Any

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.ssh import SSHProcess, SSHProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

from ..misc.ssh import SSHKillableProcess

__all__ = [
    "GetentUtils",
    "GroupEntry",
    "IdEntry",
    "LinuxToolsUtils",
    "PasswdEntry",
    "UnixGroup",
    "UnixObject",
    "UnixUser",
]


class UnixObject(object):
    """
    Generic Unix object.
    """

    def __init__(self, id: int | None, name: str | None) -> None:
        """
        :param id: Object ID.
        :type id: int | None
        :param name: Object name.
        :type name: str | None
        """
        self.id: int | None = id
        """
        ID.
        """

        self.name: str | None = name
        """
        Name.
        """

    def __str__(self) -> str:
        return f'({self.id},"{self.name}")'

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, str):
            return o == self.name
        elif isinstance(o, int):
            return o == self.id
        elif isinstance(o, tuple):
            if len(o) != 2 or not isinstance(o[0], int) or not isinstance(o[1], str):
                raise NotImplementedError(f"Unable to compare {type(o)} with {self.__class__}")

            (id, name) = o
            return id == self.id and name == self.name
        elif isinstance(o, UnixObject):
            # Fallback to identity comparison
            return NotImplemented

        raise NotImplementedError(f"Unable to compare {type(o)} with {self.__class__}")


class UnixUser(UnixObject):
    """
    Unix user.
    """

    pass


class UnixGroup(UnixObject):
    """
    Unix group.
    """

    pass


class IdEntry(object):
    """
    Result of ``id``
    """

    def __init__(self, user: UnixUser, group: UnixGroup, groups: list[UnixGroup]) -> None:
        self.user: UnixUser = user
        """
        User information.
        """

        self.group: UnixGroup = group
        """
        Primary group.
        """

        self.groups: list[UnixGroup] = groups
        """
        Secondary groups.
        """

    def memberof(self, groups: int | str | tuple[int, str] | list[int | str | tuple[int, str]]) -> bool:
        """
        Check if the user is member of give group(s).

        Group specification can be either a single gid or group name. But it can
        be also a tuple of (gid, name) where both gid and name must match or list
        of groups where the user must be member of all given groups.

        :param groups: _description_
        :type groups: int | str | tuple
        :return: _description_
        :rtype: bool
        """
        if isinstance(groups, (int, str, tuple)):
            return groups in self.groups

        return all(x in self.groups for x in groups)

    def __str__(self) -> str:
        return f"{{user={str(self.user)},group={str(self.group)},groups={str(self.groups)}}}"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> IdEntry:
        user = UnixUser(d["uid"]["id"], d["uid"].get("name", None))
        group = UnixGroup(d["gid"]["id"], d["gid"].get("name", None))
        groups = []

        for secondary_group in d["groups"]:
            groups.append(UnixGroup(secondary_group["id"], secondary_group.get("name", None)))

        return cls(user, group, groups)

    @classmethod
    def FromOutput(cls, stdout: str) -> IdEntry:
        jcresult = jc.parse("id", stdout)

        if not isinstance(jcresult, dict):
            raise TypeError(f"Unexpected type: {type(jcresult)}, expecting dict")

        return cls.FromDict(jcresult)


class PasswdEntry(object):
    """
    Result of ``getent group``
    """

    def __init__(self, name: str, password: str, uid: int, gid: int, gecos: str, home: str, shell: str) -> None:
        self.name: str | None = name
        """
        User name.
        """

        self.password: str | None = password
        """
        User password.
        """

        self.uid: int = uid
        """
        User id.
        """

        self.gid: int = gid
        """
        Group id.
        """

        self.gecos: str | None = gecos
        """
        GECOS.
        """

        self.home: str | None = home
        """
        Home directory.
        """

        self.shell: str | None = shell
        """
        Login shell.
        """

    def __str__(self) -> str:
        return f"({self.name}:{self.password}:{self.uid}:{self.gid}:{self.gecos}:{self.home}:{self.shell})"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> PasswdEntry:
        return cls(
            name=d.get("username", None),
            password=d.get("password", None),
            uid=d.get("uid", None),
            gid=d.get("gid", None),
            gecos=d.get("gecos", None),
            home=d.get("home", None),
            shell=d.get("shell", None),
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> PasswdEntry:
        result = jc.parse("passwd", stdout)

        if not isinstance(result, list):
            raise TypeError(f"Unexpected type: {type(result)}, expecting list")

        if len(result) != 1:
            raise ValueError("More then one entry was returned")

        return cls.FromDict(result[0])


class GroupEntry(object):
    """
    Result of ``getent group``
    """

    def __init__(self, name: str, password: str, gid: int, members: list[str]) -> None:
        self.name: str | None = name
        """
        Group name.
        """

        self.password: str | None = password
        """
        Group password.
        """

        self.gid: int = gid
        """
        Group id.
        """

        self.members: list[str] = members
        """
        Group members.
        """

    def __str__(self) -> str:
        return f'({self.name}:{self.password}:{self.gid}:{",".join(self.members)})'

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> GroupEntry:
        return cls(
            name=d.get("group_name", None),
            password=d.get("password", None),
            gid=d.get("gid", None),
            members=d.get("members", []),
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> GroupEntry:
        result = jc.parse("group", stdout)

        if not isinstance(result, list):
            raise TypeError(f"Unexpected type: {type(result)}, expecting list")

        if len(result) != 1:
            raise ValueError("More then one entry was returned")

        return cls.FromDict(result[0])


class LinuxToolsUtils(MultihostUtility[MultihostHost]):
    """
    Run various standard commands on remote host.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.getent: GetentUtils = GetentUtils(host)
        """
        Run ``getent`` command.
        """

        self.__fs: LinuxFileSystem = fs
        self.__rollback: list[str] = []

    def id(self, name: str) -> IdEntry | None:
        """
        Run ``id`` command.

        :param name: User name or id.
        :type name: str | int
        :return: id data, None if not found
        :rtype: IdEntry | None
        """
        command = self.host.ssh.exec(["id", name], raise_on_error=False)
        if command.rc != 0:
            return None

        return IdEntry.FromOutput(command.stdout)

    def grep(self, pattern: str, paths: str | list[str], args: list[str] | None = None) -> bool:
        """
        Run ``grep`` command.

        :param pattern: Pattern to match.
        :type pattern: str
        :param paths: Paths to search.
        :type paths: str | list[str]
        :param args: Additional arguments to ``grep`` command, defaults to None.
        :type args: list[str] | None, optional
        :return: True if grep returned 0, False otherwise.
        :rtype: bool
        """
        if args is None:
            args = []

        paths = [paths] if isinstance(paths, str) else paths
        command = self.host.ssh.exec(["grep", *args, pattern, *paths])

        return command.rc == 0

    def tcpdump(self, pcap_path: str, args: list[Any] | None = None) -> SSHKillableProcess:
        """
        Run tcpdump. The packets are captured in ``pcap_path``.

        :param pcap_path: Path to the capture file.
        :type pcap_path: str
        :param args: Arguments to ``tcpdump``, defaults to None
        :type args: list[Any] | None, optional
        :return: Killable process.
        :rtype: SSHKillableProcess
        """
        if args is None:
            args = []

        self.__fs.backup(pcap_path)

        command = SSHKillableProcess(self.host.ssh, ["tcpdump", *args, "-w", pcap_path])

        # tcpdump requires some time to process and capture packets
        command.kill_delay = 1

        return command

    def tshark(self, args: list[Any] | None = None) -> SSHProcessResult:
        """
        Execute tshark command with given arguments.

        :param args: Arguments to ``tshark``, defaults to None
        :type args: list[Any] | None, optional
        :return: SSH Process result
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        return self.host.ssh.exec(["tshark", *args])

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.ssh.run(cmd)

        super().teardown()


class KillCommand(object):
    def __init__(self, host: MultihostHost, process: SSHProcess, pid: int) -> None:
        self.host = host
        self.process = process
        self.pid = pid
        self.__killed: bool = False

    def kill(self) -> None:
        if self.__killed:
            return

        self.host.ssh.exec(["kill", self.pid])
        self.__killed = True

    def __enter__(self) -> KillCommand:
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self.kill()
        self.process.wait()


class GetentUtils(MultihostUtility[MultihostHost]):
    """
    Interface to getent command.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

    def passwd(self, name: str | int) -> PasswdEntry | None:
        """
        Call ``getent passwd $name``

        :param name: User name or id.
        :type name: str | int
        :return: passwd data, None if not found
        :rtype: PasswdEntry | None
        """
        return self.__exec(PasswdEntry, "passwd", name)

    def group(self, name: str | int) -> GroupEntry | None:
        """
        Call ``getent group $name``

        :param name: Group name or id.
        :type name: str | int
        :return: group data, None if not found
        :rtype: PasswdEntry | None
        """
        return self.__exec(GroupEntry, "group", name)

    def __exec(self, cls, cmd: str, name: str | int) -> Any:
        command = self.host.ssh.exec(["getent", cmd, name], raise_on_error=False)
        if command.rc != 0:
            return None

        return cls.FromOutput(command.stdout)
