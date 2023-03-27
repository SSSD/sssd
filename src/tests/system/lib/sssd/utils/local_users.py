"Managing local users and groups."

from __future__ import annotations

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.ssh import SSHLog

__all__ = [
    "LocalGroup",
    "LocalUser",
    "LocalUsersUtils",
]


class LocalUsersUtils(MultihostUtility[MultihostHost]):
    """
    Management of local users and groups.

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.cli: CLIBuilder = CLIBuilder(host.ssh)
        self._users: list[str] = []
        self._groups: list[str] = []

    def teardown(self) -> None:
        """
        Delete any added user and group.
        """
        cmd = ""

        if self._users:
            cmd += "\n".join([f"userdel '{x}' --force --remove" for x in self._users])
            cmd += "\n"

        if self._groups:
            cmd += "\n".join([f"groupdel '{x}' --force" for x in self._groups])
            cmd += "\n"

        if cmd:
            self.host.ssh.run("set -e\n\n" + cmd)

        super().teardown()

    def user(self, name: str) -> LocalUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                # Create user
                client.local.user('user-1').add(uid=10001)

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.user.id == 10001
                assert result.group.name == 'user-1'
                assert result.group.id == 10001

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: LocalUser
        """
        return LocalUser(self, name)

    def group(self, name: str) -> LocalGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                # Create user
                user = client.local.user('user-1').add(uid=10001)

                # Create secondary group and add user as a member
                client.local.group('group-1').add().add_member(user)

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.user.id == 10001
                assert result.group.name == 'user-1'
                assert result.group.id == 10001
                assert result.memberof('group-1')

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: LocalGroup
        """
        return LocalGroup(self, name)


class LocalUser(object):
    """
    Management of local users.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: User name.
        :type name: str
        """
        self.util = util
        self.name = name

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> LocalUser:
        """
        Create new local user.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: LocalUser
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
        }

        passwd = f" && passwd --stdin '{self.name}'" if password else ""
        self.util.logger.info(f'Creating local user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command("useradd", args) + passwd, input=password, log_level=SSHLog.Error)

        self.util._users.append(self.name)
        return self

    def modify(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> LocalUser:
        """
        Modify existing local user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: LocalUser
        """

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
        }

        passwd = f" && passwd --stdin '{self.name}'" if password else ""
        self.util.logger.info(f'Modifying local user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command("usermod", args) + passwd, input=password, log_level=SSHLog.Error)

        return self

    def delete(self) -> None:
        """
        Delete the user.
        """
        self.util.logger.info(f'Deleting local user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f"userdel '{self.name}' --force --remove", log_level=SSHLog.Error)
        self.util._users.remove(self.name)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get user attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching local user "{self.name}" on {self.util.host.hostname}')
        result = self.util.host.ssh.exec(["getent", "passwd", self.name], raise_on_error=False, log_level=SSHLog.Error)
        if result.rc != 0:
            return {}

        jcresult = jc.parse("passwd", result.stdout)
        if not jcresult:
            return {}

        if not isinstance(jcresult, list):
            raise TypeError(f"Unexpected type: {type(jcresult)}, expecting list")

        if not isinstance(jcresult[0], dict):
            raise TypeError(f"Unexpected type: {type(jcresult[0])}, expecting dict")

        return {k: [str(v)] for k, v in jcresult[0].items() if not attrs or k in attrs}


class LocalGroup(object):
    """
    Management of local groups.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: Group name.
        :type name: str
        """
        self.util = util
        self.name = name

    def add(
        self,
        *,
        gid: int | None = None,
    ) -> LocalGroup:
        """
        Create new local group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: LocalGroup
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Creating local group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command("groupadd", args), log_level=SSHLog.Silent)
        self.util._groups.append(self.name)

        return self

    def modify(
        self,
        *,
        gid: int | None = None,
    ) -> LocalGroup:
        """
        Modify existing local group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: LocalGroup
        """

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Modifying local group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command("groupmod", args), log_level=SSHLog.Error)

        return self

    def delete(self) -> None:
        """
        Delete the group.
        """
        self.util.logger.info(f'Deleting local group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f"groupdel '{self.name}' --force", log_level=SSHLog.Error)
        self.util._groups.remove(self.name)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get group attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching local group "{self.name}" on {self.util.host.hostname}')
        result = self.util.host.ssh.exec(["getent", "group", self.name], raise_on_error=False, log_level=SSHLog.Silent)
        if result.rc != 0:
            return {}

        jcresult = jc.parse("group", result.stdout)
        if not jcresult:
            return {}

        if not isinstance(jcresult, list):
            raise TypeError(f"Unexpected type: {type(jcresult)}, expecting list")

        if not isinstance(jcresult[0], dict):
            raise TypeError(f"Unexpected type: {type(jcresult[0])}, expecting dict")

        return {k: [str(v)] for k, v in jcresult[0].items() if not attrs or k in attrs}

    def add_member(self, member: LocalUser) -> LocalGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: LocalUser
        :return: Self.
        :rtype: LocalGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[LocalUser]) -> LocalGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[LocalUser]
        :return: Self.
        :rtype: LocalGroup
        """
        self.util.logger.info(f'Adding members to group "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join([f"groupmems --group '{self.name}' --add '{x.name}'" for x in members])
        self.util.host.ssh.run("set -ex\n" + cmd, log_level=SSHLog.Error)

        return self

    def remove_member(self, member: LocalUser) -> LocalGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: LocalUser
        :return: Self.
        :rtype: LocalGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[LocalUser]) -> LocalGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[LocalUser]
        :return: Self.
        :rtype: LocalGroup
        """
        self.util.logger.info(f'Removing members from group "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join([f"groupmems --group '{self.name}' --delete '{x.name}'" for x in members])
        self.util.host.ssh.run("set -ex\n" + cmd, log_level=SSHLog.Error)

        return self
