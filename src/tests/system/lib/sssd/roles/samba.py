"""Samba multihost role."""

from __future__ import annotations

from typing import Any, TypeAlias

import ldap.modlist
from pytest_mh.cli import CLIBuilderArgs
from pytest_mh.ssh import SSHProcessResult

from ..hosts.samba import SambaHost
from ..misc import attrs_parse, to_list_of_strings
from .base import BaseLinuxLDAPRole, BaseObject, DeleteAttribute
from .ldap import LDAPAutomount, LDAPObject, LDAPOrganizationalUnit, LDAPSudoRule

__all__ = [
    "Samba",
    "SambaObject",
    "SambaUser",
    "SambaGroup",
    "SambaOrganizationalUnit",
    "SambaAutomount",
    "SambaSudoRule",
]


class Samba(BaseLinuxLDAPRole[SambaHost]):
    """
    Samba role.

    Provides unified Python API for managing objects in the Samba domain controller.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.Samba)
        def test_example(samba: Samba):
            u = samba.user('tuser').add()
            g = samba.group('tgroup').add()
            g.add_member(u)

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.automount: SambaAutomount = SambaAutomount(self)
        """
        Manage automount maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example_autofs(client: Client, samba: Samba, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automount maps
                auto_master = samba.automount.map('auto.master').add()
                auto_home = samba.automount.map('auto.home').add()
                auto_sub = samba.automount.map('auto.sub').add()

                # Create mount points
                auto_master.key('/ehome').add(info=auto_home)
                auto_master.key('/esub/sub1/sub2').add(info=auto_sub)

                # Create mount keys
                key1 = auto_home.key('export1').add(info=nfs_export1)
                key2 = auto_home.key('export2').add(info=nfs_export2)
                key3 = auto_sub.key('export3').add(info=nfs_export3)

                # Start SSSD
                client.sssd.common.autofs()
                client.sssd.start()

                # Reload automounter in order to fetch updated maps
                client.automount.reload()

                # Check that we can mount all directories on correct locations
                assert client.automount.mount('/ehome/export1', nfs_export1)
                assert client.automount.mount('/ehome/export2', nfs_export2)
                assert client.automount.mount('/esub/sub1/sub2/export3', nfs_export3)

                # Check that the maps are correctly fetched
                assert client.automount.dumpmaps() == {
                    '/ehome': {
                        'map': 'auto.home',
                        'keys': [str(key1), str(key2)]
                    },
                    '/esub/sub1/sub2': {
                        'map': 'auto.sub',
                        'keys': [str(key3)]
                    },
                }
        """

        # Set AD schema for automount
        self.automount.set_schema(self.automount.Schema.AD)

    def user(self, name: str) -> SambaUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create user
                samba.user('user-1').add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'domain users'

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: SambaUser
        """
        return SambaUser(self, name)

    def group(self, name: str) -> SambaGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create user
                user = samba.user('user-1').add()

                # Create secondary group and add user as a member
                samba.group('group-1').add().add_member(user)

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'domain users'
                assert result.memberof('group-1')

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: SambaGroup
        """
        return SambaGroup(self, name)

    def ou(self, name: str, basedn: LDAPObject | str | None = None) -> SambaOrganizationalUnit:
        """
        Get organizational unit object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create organizational unit for sudo rules
                ou = samba.ou('mysudoers').add()

                # Create user
                samba.user('user-1').add()

                # Create sudo rule
                samba.sudorule('testrule', basedn=ou).add(user='ALL', host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :return: New organizational unit object.
        :rtype: SambaOrganizationalUnit
        """
        return SambaOrganizationalUnit(self, name, basedn)

    def sudorule(self, name: str, basedn: LDAPObject | str | None = "ou=sudoers") -> SambaSudoRule:
        """
        Get sudo rule object.

        .. code-blocK:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                user = samba.user('user-1').add(password="Secret123")
                samba.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: LDAPObject | str | None, optional
        :return: New sudo rule object.
        :rtype: SambaSudoRule
        """
        return SambaSudoRule(self, SambaUser, SambaGroup, name, basedn)


class SambaObject(BaseObject):
    """
    Base class for Samba DC object management.

    Provides shortcuts for command execution and implementation of :meth:`get`
    and :meth:`delete` methods.
    """

    def __init__(self, role: Samba, command: str, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param command: Samba command group.
        :type command: str
        :param name: Object name.
        :type name: str
        """
        super().__init__(role)

        self.command: str = command
        """Samba-tool command."""

        self.name: str = name
        """Object name."""

    def _exec(self, op: str, args: list[str] | None = None, **kwargs) -> SSHProcessResult:
        """
        Execute samba-tool command.

        .. code-block:: console

            $ samba-tool $command $ op $name $args
            for example >>> samba-tool user add tuser

        :param op: Command group operation (usually add, delete, show)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        return self.role.host.ssh.exec(["samba-tool", self.command, op, self.name, *args], **kwargs)

    def _add(self, attrs: CLIBuilderArgs) -> None:
        """
        Add Samba object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        """
        self._exec("add", self.cli.args(attrs))

    def _modify(self, attrs: dict[str, Any | list[Any] | DeleteAttribute | None]) -> None:
        """
        Modify Samba object.

        :param attrs: Attributes to modify.
        :type attrs: dict[str, Any  |  list[Any]  |  DeleteAttribute  |  None]
        """
        obj = self.get()

        # Remove dn and distinguishedName attributes
        dn = obj.pop("dn")[0]
        del obj["distinguishedName"]

        # Build old attrs
        old_attrs = {k: [str(i).encode("utf-8") for i in v] for k, v in obj.items()}

        # Update object
        for attr, value in attrs.items():
            if value is None:
                continue

            if isinstance(value, DeleteAttribute):
                del obj[attr]
                continue

            if not isinstance(value, list):
                obj[attr] = [str(value)]
                continue

            obj[attr] = to_list_of_strings(value)

        # Build new attrs
        new_attrs = {k: [str(i).encode("utf-8") for i in v] for k, v in obj.items()}

        # Build diff
        modlist = ldap.modlist.modifyModlist(old_attrs, new_attrs)
        if modlist:
            self.role.host.conn.modify_s(dn, modlist)

    def delete(self) -> None:
        """
        Delete Samba object.
        """
        self._exec("delete")

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get Samba object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        cmd = self._exec("show")
        return attrs_parse(cmd.stdout_lines, attrs)


class SambaUser(SambaObject):
    """
    Samba user management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param name: User name.
        :type name: str
        """
        super().__init__(role, "user", name)

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> SambaUser:
        """
        Create new Samba user.

        Parameters that are not set are ignored.

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
        :rtype: SambaUser
        """
        attrs: CLIBuilderArgs = {
            "password": (self.cli.option.POSITIONAL, password),
            "given-name": (self.cli.option.VALUE, self.name),
            "surname": (self.cli.option.VALUE, self.name),
            "uid-number": (self.cli.option.VALUE, uid),
            "gid-number": (self.cli.option.VALUE, gid),
            "unix-home": (self.cli.option.VALUE, home),
            "gecos": (self.cli.option.VALUE, gecos),
            "login-shell": (self.cli.option.VALUE, shell),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        uid: int | DeleteAttribute | None = None,
        gid: int | DeleteAttribute | None = None,
        home: str | DeleteAttribute | None = None,
        gecos: str | DeleteAttribute | None = None,
        shell: str | DeleteAttribute | None = None,
    ) -> SambaUser:
        """
        Modify existing Samba user.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param uid: User id, defaults to None
        :type uid: int | DeleteAttribute | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param home: Home directory, defaults to None
        :type home: str | DeleteAttribute | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | DeleteAttribute | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: SambaUser
        """
        attrs: dict[str, Any] = {
            "uidNumber": uid,
            "gidNumber": gid,
            "unixHomeDirectory": home,
            "gecos": gecos,
            "loginShell": shell,
        }

        self._modify(attrs)
        return self


class SambaGroup(SambaObject):
    """
    Samba group management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param name: Group name.
        :type name: str
        """
        super().__init__(role, "group", name)

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        scope: str = "Global",
        category: str = "Security",
    ) -> SambaGroup:
        """
        Create new Samba group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param scope: Scope ('Global', 'Universal', 'DomainLocal'), defaults to 'Global'
        :type scope: str, optional
        :param category: Category ('Distribution', 'Security'), defaults to 'Security'
        :type category: str, optional
        :return: Self.
        :rtype: SambaGroup
        """
        attrs: CLIBuilderArgs = {
            "gid-number": (self.cli.option.VALUE, gid),
            "description": (self.cli.option.VALUE, description),
            "group-scope": (self.cli.option.VALUE, scope),
            "group-type": (self.cli.option.VALUE, category),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | DeleteAttribute | None = None,
        description: str | DeleteAttribute | None = None,
    ) -> SambaGroup:
        """
        Modify existing Samba group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param gid: Group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param description: Description, defaults to None
        :type description: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: SambaUser
        """
        attrs: dict[str, Any] = {
            "gidNumber": gid,
            "description": description,
        }

        self._modify(attrs)
        return self

    def add_member(self, member: SambaUser | SambaGroup) -> SambaGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: SambaUser | SambaGroup
        :return: Self.
        :rtype: SambaGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[SambaUser | SambaGroup]) -> SambaGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[SambaUser | SambaGroup]
        :return: Self.
        :rtype: SambaGroup
        """
        self._exec("addmembers", self.__get_member_args(members))
        return self

    def remove_member(self, member: SambaUser | SambaGroup) -> SambaGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: SambaUser | SambaGroup
        :return: Self.
        :rtype: SambaGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[SambaUser | SambaGroup]) -> SambaGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[SambaUser | SambaGroup]
        :return: Self.
        :rtype: SambaGroup
        """
        self._exec("removemembers", self.__get_member_args(members))
        return self

    def __get_member_args(self, members: list[SambaUser | SambaGroup]) -> list[str]:
        return [",".join([x.name for x in members])]


SambaOrganizationalUnit: TypeAlias = LDAPOrganizationalUnit[SambaHost, Samba]
SambaAutomount: TypeAlias = LDAPAutomount[SambaHost, Samba]
SambaSudoRule: TypeAlias = LDAPSudoRule[SambaHost, Samba, SambaUser, SambaGroup]
