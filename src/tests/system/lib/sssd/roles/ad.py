"""Active Directory multihost role."""

from __future__ import annotations

from typing import Any

from pytest_mh.cli import CLIBuilderArgs
from pytest_mh.ssh import SSHClient, SSHPowerShellProcess, SSHProcessResult

from ..hosts.ad import ADHost
from ..misc import attrs_include_value, attrs_parse
from .base import BaseObject, BaseWindowsRole, DeleteAttribute
from .nfs import NFSExport

__all__ = [
    "AD",
    "ADAutomount",
    "ADAutomountMap",
    "ADGroup",
    "ADObject",
    "ADOrganizationalUnit",
    "ADSudoRule",
    "ADUser",
]


class AD(BaseWindowsRole[ADHost]):
    """
    AD service management.
    """

    """
    Active Directory role.

    Provides unified Python API for managing objects in the Active Directory
    domain controller.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.AD)
        def test_example(ad: AD):
            u = ad.user('tuser').add()
            g = ad.group('tgroup').add()
            g.add_member(u)

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.auto_ou: dict[str, bool] = {}
        """Organizational units that were automatically created."""

        self.automount: ADAutomount = ADAutomount(self)
        """
        Manage automount maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example_autofs(client: Client, ad: AD, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automount maps
                auto_master = ad.automount.map('auto.master').add()
                auto_home = ad.automount.map('auto.home').add()
                auto_sub = ad.automount.map('auto.sub').add()

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

    def ssh(self, user: str, password: str, *, shell=SSHPowerShellProcess) -> SSHClient:
        """
        Open SSH connection to the host as given user.

        :param user: Username.
        :type user: str
        :param password: User password.
        :type password: str
        :param shell: Shell that will run the commands, defaults to SSHPowerShellProcess
        :type shell: str, optional
        :return: SSH client connection.
        :rtype: SSHClient
        """
        return super().ssh(user, password, shell=shell)

    def user(self, name: str, basedn: ADObject | str | None = "cn=users") -> ADUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                # Create user
                ad.user('user-1').add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'domain users'

        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``cn=users``
        :type basedn: ADObject | str | None, optional
        :return: New user object.
        :rtype: ADUser
        """
        return ADUser(self, name, basedn)

    def group(self, name: str, basedn: ADObject | str | None = "cn=users") -> ADGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example_group(client: Client, ad: AD):
                # Create user
                user = ad.user('user-1').add()

                # Create secondary group and add user as a member
                ad.group('group-1').add().add_member(user)

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
        :param basedn: Base dn, defaults to ``cn=users``
        :type basedn: ADObject | str | None, optional
        :return: New group object.
        :rtype: ADGroup
        """
        return ADGroup(self, name, basedn)

    def ou(self, name: str, basedn: ADObject | str | None = None) -> ADOrganizationalUnit:
        """
        Get organizational unit object.

        .. code-blocK:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                # Create organizational unit for sudo rules
                ou = ad.ou('mysudoers').add()

                # Create user
                ad.user('user-1').add()

                # Create sudo rule
                ad.sudorule('testrule', basedn=ou).add(user='ALL', host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: New organizational unit object.
        :rtype: ADOrganizationalUnit
        """
        return ADOrganizationalUnit(self, name, basedn)

    def sudorule(self, name: str, basedn: ADObject | str | None = "ou=sudoers") -> ADSudoRule:
        """
        Get sudo rule object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                user = ad.user('user-1').add(password="Secret123")
                ad.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: ADObject | str | None, optional
        :return: New sudo rule object.
        :rtype: ADSudoRule
        """

        return ADSudoRule(self, name, basedn)


class ADObject(BaseObject[ADHost, AD]):
    """
    Base class for Active Directory object management.

    Provides shortcuts for command execution and implementation of :meth:`get`
    and :meth:`delete` methods.
    """

    def __init__(
        self,
        role: AD,
        command_group: str,
        name: str,
        rdn: str,
        basedn: ADObject | str | None = None,
        default_ou: str | None = None,
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param command_group: AD command group.
        :type command_group: str
        :param name: Object name.
        :type name: str
        :param rdn: Relative distinguished name.
        :type rdn: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        :param default_ou: Name of default organizational unit that is automatically
                           created if basedn is set to ou=$default_ou, defaults to None.
        :type default_ou: str | None, optional
        """
        super().__init__(role)

        self.command_group: str = command_group
        """Active Directory Powershell module command group."""

        self.name: str = name
        """Object name."""

        self.rdn: str = rdn
        """Object relative DN."""

        self.basedn: ADObject | str | None = basedn
        """Object base DN."""

        self.dn: str = self._dn(rdn, basedn)
        """Object DN."""

        self.path: str = self._path(basedn)
        """Object path (DN of the parent container)."""

        self.default_ou: str | None = default_ou
        """Default organizational unit that usually holds this object."""

        self._identity: CLIBuilderArgs = {"Identity": (self.cli.option.VALUE, self.dn)}
        """Identity parameter used in powershell commands."""

        self.__create_default_ou(basedn, self.default_ou)

    def __create_default_ou(self, basedn: ADObject | str | None, default_ou: str | None) -> None:
        """
        If default base dn is used we want to make sure that the container
        (usually an organizational unit) exit. This is to allow nicely working
        topology parametrization when the base dn is not specified and created
        inside the test because not all backends supports base dn (e.g. IPA).

        :param basedn: Selected base DN.
        :type basedn: ADObject | str | None
        :param default_ou: Default name of organizational unit.
        :type default_ou: str | None
        """
        if default_ou is None:
            return

        if basedn is None or not isinstance(basedn, str):
            return

        if basedn.lower() != f"ou={default_ou}" or default_ou in self.role.auto_ou:
            return

        self.role.ou(default_ou).add()
        self.role.auto_ou[default_ou] = True

    def _dn(self, rdn: str, basedn: ADObject | str | None = None) -> str:
        """
        Get distinguished name of an object.

        :param rdn: Relative DN.
        :type rdn: str
        :param basedn: Base DN, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: Distinguished name combined from rdn+dn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, ADObject):
            return f"{rdn},{basedn.dn}"

        if not basedn:
            return f"{rdn},{self.role.host.naming_context}"

        return f"{rdn},{basedn},{self.role.host.naming_context}"

    def _path(self, basedn: ADObject | str | None = None) -> str:
        """
        Get object LDAP path.

        :param basedn: Base DN, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: Distinguished name of the parent container combined from basedn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, ADObject):
            return basedn.dn

        if not basedn:
            return self.role.host.naming_context

        return f"{basedn},{self.role.host.naming_context}"

    def _exec(self, op: str, args: list[str] | str | None = None, **kwargs) -> SSHProcessResult:
        """
        Execute AD command.

        .. code-block:: console

            $ $op-AD$command_group $args
            for example >>> New-ADUser tuser

        :param op: Command group operation (usually New, Set, Remove, Get)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        if isinstance(args, list):
            args = " ".join(args)
        elif args is None:
            args = ""

        return self.role.host.ssh.run(
            f"""
            Import-Module ActiveDirectory
            {op}-AD{self.command_group} {args}
        """,
            **kwargs,
        )

    def _add(self, attrs: CLIBuilderArgs) -> None:
        """
        Add Active Directory object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        """
        self._exec("New", self.cli.args(attrs, quote_value=True))

    def _modify(self, attrs: CLIBuilderArgs) -> None:
        """
        Modifiy Active Directory object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        """
        self._exec("Set", self.cli.args(attrs, quote_value=True))

    def delete(self) -> None:
        """
        Delete Active Directory object.
        """
        args: CLIBuilderArgs = {
            "Confirm": (self.cli.option.SWITCH, False),
            **self._identity,
        }
        self._exec("Remove", self.cli.args(args, quote_value=True))

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get AD object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        cmd = self._exec("Get", self.cli.args(self._identity, quote_value=True))
        return attrs_parse(cmd.stdout_lines, attrs)

    def _attrs_to_hash(self, attrs: dict[str, Any]) -> str | None:
        """
        Convert attributes into an Powershell hash table records.

        :param attrs: Attributes names and values.
        :type attrs: dict[str, Any]
        :return: Attributes in powershell hash record format.
        :rtype: str | None
        """
        out = ""
        for key, value in attrs.items():
            if value is not None:
                if isinstance(value, list):
                    values = [f'"{x}"' for x in value]
                    out += f'"{key}"={",".join(values)};'
                else:
                    out += f'"{key}"="{value}";'

        if not out:
            return None

        return "@{" + out.rstrip(";") + "}"


class ADOrganizationalUnit(ADObject):
    """
    AD organizational unit management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = None) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "OrganizationalUnit", name, f"ou={name}", basedn)

    def add(self) -> ADOrganizationalUnit:
        """
        Create new AD organizational unit.

        :return: Self.
        :rtype: ADOrganizationalUnit
        """
        attrs: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Path": (self.cli.option.VALUE, self.path),
            "ProtectedFromAccidentalDeletion": (self.cli.option.PLAIN, "$False"),
        }

        self._add(attrs)
        return self


class ADUser(ADObject):
    """
    AD user management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = "cn=users") -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=users'
        :type basedn: ADObject | str | None, optional
        """
        # There is no automatically created default ou because cn=users already exists
        super().__init__(role, "User", name, f"cn={name}", basedn, default_ou=None)

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> ADUser:
        """
        Create new AD user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password (cannot be None), defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            "uid": self.name,
            "uidNumber": uid,
            "gidNumber": gid,
            "unixHomeDirectory": home,
            "gecos": gecos,
            "loginShell": shell,
        }

        attrs: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "AccountPassword": (self.cli.option.PLAIN, f'(ConvertTo-SecureString "{password}" -AsPlainText -force)'),
            "OtherAttributes": (self.cli.option.PLAIN, self._attrs_to_hash(unix_attrs)),
            "Enabled": (self.cli.option.PLAIN, "$True"),
            "Path": (self.cli.option.VALUE, self.path),
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
    ) -> ADUser:
        """
        Modify existing AD user.

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
        :rtype: ADUser
        """
        unix_attrs = {
            "uidNumber": uid,
            "gidNumber": gid,
            "unixHomeDirectory": home,
            "gecos": gecos,
            "loginShell": shell,
        }

        clear = [key for key, value in unix_attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value
            for key, value in unix_attrs.items()
            if value is not None and not isinstance(value, DeleteAttribute)
        }

        attrs: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, self._attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(attrs)
        return self


class ADGroup(ADObject):
    """
    AD group management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = "cn=users") -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=users'
        :type basedn: ADObject | str | None, optional
        """
        # There is no automatically created default ou because cn=users already exists
        super().__init__(role, "Group", name, f"cn={name}", basedn, default_ou=None)

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        scope: str = "Global",
        category: str = "Security",
    ) -> ADGroup:
        """
        Create new AD group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param scope: Scope ('Global', 'Universal', 'DomainLocal'), defaults to 'Global'
        :type scope: str, optional
        :param category: Category ('Distribution', 'Security'), defaults to 'Security'
        :type category: str, optional
        :return: Self.
        :rtype: ADGroup
        """
        unix_attrs = {
            "gidNumber": gid,
            "description": description,
        }

        attrs: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "GroupScope": (self.cli.option.VALUE, scope),
            "GroupCategory": (self.cli.option.VALUE, category),
            "OtherAttributes": (self.cli.option.PLAIN, self._attrs_to_hash(unix_attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | DeleteAttribute | None = None,
        description: str | DeleteAttribute | None = None,
    ) -> ADGroup:
        """
        Modify existing AD group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param gid: Group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param description: Description, defaults to None
        :type description: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            "gidNumber": gid,
            "description": description,
        }

        clear = [key for key, value in unix_attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value
            for key, value in unix_attrs.items()
            if value is not None and not isinstance(value, DeleteAttribute)
        }

        attrs: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, self._attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(attrs)
        return self

    def add_member(self, member: ADUser | ADGroup) -> ADGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: ADUser | ADGroup
        :return: Self.
        :rtype: ADGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[ADUser | ADGroup]) -> ADGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[ADUser | ADGroup]
        :return: Self.
        :rtype: ADGroup
        """
        self.role.host.ssh.run(
            f"""
            Import-Module ActiveDirectory
            Add-ADGroupMember -Identity '{self.dn}' -Members {self.__get_members(members)}
        """
        )
        return self

    def remove_member(self, member: ADUser | ADGroup) -> ADGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: ADUser | ADGroup
        :return: Self.
        :rtype: ADGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[ADUser | ADGroup]) -> ADGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[ADUser | ADGroup]
        :return: Self.
        :rtype: ADGroup
        """
        self.role.host.ssh.run(
            f"""
            Import-Module ActiveDirectory
            Remove-ADGroupMember -Confirm:$False -Identity '{self.dn}' -Members {self.__get_members(members)}
        """
        )
        return self

    def __get_members(self, members: list[ADUser | ADGroup]) -> str:
        return ",".join([f'"{x.dn}"' for x in members])


class ADSudoRule(ADObject):
    """
    AD sudo rule management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        basedn: ADObject | str | None = "ou=sudoers",
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Sudo rule name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "Object", name, f"cn={name}", basedn, default_ou="sudoers")

    def add(
        self,
        *,
        user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None = None,
        runasgroup: int | str | ADGroup | list[int | str | ADGroup] | None = None,
        notbefore: str | list[str] | None = None,
        notafter: str | list[str] | None = None,
        order: int | list[int] | None = None,
        nopasswd: bool | None = None,
    ) -> ADSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup], optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str], optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str], optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | ADGroup | list[int | str | ADGroup] | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: ADSudoRule
        """
        attrs = {
            "objectClass": "sudoRole",
            "sudoUser": self.__sudo_user(user),
            "sudoHost": host,
            "sudoCommand": command,
            "sudoOption": option,
            "sudoRunAsUser": self.__sudo_user(runasuser),
            "sudoRunAsGroup": self.__sudo_group(runasgroup),
            "sudoNotBefore": notbefore,
            "sudoNotAfter": notafter,
            "sudoOrder": order,
        }

        if nopasswd is True:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "!authenticate")
        elif nopasswd is False:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "authenticate")

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "sudoRole"),
            "OtherAttributes": (self.cli.option.PLAIN, self._attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        return self

    def modify(
        self,
        *,
        user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | DeleteAttribute | None = None,
        host: str | list[str] | DeleteAttribute | None = None,
        command: str | list[str] | DeleteAttribute | None = None,
        option: str | list[str] | DeleteAttribute | None = None,
        runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | DeleteAttribute | None = None,
        runasgroup: int | str | ADGroup | list[int | str | ADGroup] | DeleteAttribute | None = None,
        notbefore: str | list[str] | DeleteAttribute | None = None,
        notafter: str | list[str] | DeleteAttribute | None = None,
        order: int | list[int] | DeleteAttribute | None = None,
        nopasswd: bool | None = None,
    ) -> ADSudoRule:
        """
        Modify existing sudo rule.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
          | DeleteAttribute | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | DeleteAttribute | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | DeleteAttribute | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | DeleteAttribute | None, optional
        :param runasuser: sudoRunAsUsere attribute, defaults to None
        :type runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
          | DeleteAttribute | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | ADGroup | list[int | str | ADGroup] | DeleteAttribute | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | DeleteAttribute | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | DeleteAttribute | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | DeleteAttribute | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: ADSudoRule
        """
        attrs = {
            "sudoUser": self.__sudo_user(user),
            "sudoHost": host,
            "sudoCommand": command,
            "sudoOption": option,
            "sudoRunAsUser": self.__sudo_user(runasuser),
            "sudoRunAsGroup": self.__sudo_group(runasgroup),
            "sudoNotBefore": notbefore,
            "sudoNotAfter": notafter,
            "sudoOrder": order,
        }

        if nopasswd is True:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "!authenticate")
        elif nopasswd is False:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "authenticate")

        clear = [key for key, value in attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value for key, value in attrs.items() if value is not None and not isinstance(value, DeleteAttribute)
        }

        args: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, self._attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(args)
        return self

    def __sudo_user(
        self, sudo_user: None | DeleteAttribute | int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
    ) -> list[str] | DeleteAttribute | None:
        def _get_value(value: int | str | ADUser | ADGroup) -> str:
            if isinstance(value, ADUser):
                return value.name

            if isinstance(value, ADGroup):
                return "%" + value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return "#" + str(value)

            raise ValueError(f"Unsupported type: {type(value)}")

        if sudo_user is None:
            return None

        if isinstance(sudo_user, DeleteAttribute):
            return sudo_user

        if not isinstance(sudo_user, list):
            return [_get_value(sudo_user)]

        out = []
        for value in sudo_user:
            out.append(_get_value(value))

        return out

    def __sudo_group(
        self, sudo_group: None | DeleteAttribute | int | str | ADGroup | list[int | str | ADGroup]
    ) -> list[str] | DeleteAttribute | None:
        def _get_value(value: int | str | ADGroup):
            if isinstance(value, ADGroup):
                return value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return "#" + str(value)

            raise ValueError(f"Unsupported type: {type(value)}")

        if sudo_group is None:
            return None

        if isinstance(sudo_group, DeleteAttribute):
            return sudo_group

        if not isinstance(sudo_group, list):
            return [_get_value(sudo_group)]

        out = []
        for value in sudo_group:
            out.append(_get_value(value))

        return out


class ADAutomount(object):
    """
    AD automount management.
    """

    def __init__(self, role: AD) -> None:
        """
        :param role: AD role object.
        :type role: AD
        """
        self.__role = role

    def map(self, name: str, basedn: ADObject | str | None = "ou=autofs") -> ADAutomountMap:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: ADObject | str | None, optional
        :return: New automount map object.
        :rtype: ADAutomountMap
        """
        return ADAutomountMap(self.__role, name, basedn)

    def key(self, name: str, map: ADAutomountMap) -> ADAutomountKey:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: ADAutomountMap
        :return: New automount key object.
        :rtype: ADAutomountKey
        """
        return ADAutomountKey(self.__role, name, map)


class ADAutomountMap(ADObject):
    """
    AD automount map management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        basedn: ADObject | str | None = "ou=autofs",
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "Object", name, f"cn={name}", basedn, default_ou="autofs")

    def add(
        self,
    ) -> ADAutomountMap:
        """
        Create new AD automount map.

        :return: Self.
        :rtype: ADAutomountMap
        """
        attrs = {
            "objectClass": "nisMap",
            "cn": self.name,
            "nisMapName": self.name,
        }

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "nisMap"),
            "OtherAttributes": (self.cli.option.PLAIN, self._attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        return self

    def key(self, name: str) -> ADAutomountKey:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: ADAutomountKey
        """
        return ADAutomountKey(self.role, name, self)


class ADAutomountKey(ADObject):
    """
    AD automount key management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        map: ADAutomountMap,
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: ADAutomountMap
        """
        super().__init__(role, "Object", name, f"cn={name}", map)
        self.map: ADAutomountMap = map
        self.info: str | None = None

    def add(self, *, info: str | NFSExport | ADAutomountMap) -> ADAutomountKey:
        """
        Create new AD automount key.

        :param info: Automount information.
        :type info: str | NFSExport | ADAutomountMap
        :return: Self.
        :rtype: ADAutomountKey
        """
        parsed = self.__get_info(info)
        if isinstance(parsed, DeleteAttribute) or parsed is None:
            # This should not happen, it is here just to silence mypy
            raise ValueError("Invalid value of info attribute")

        attrs = {
            "objectClass": "nisObject",
            "cn": self.name,
            "nisMapEntry": parsed,
            "nisMapName": self.map.name,
        }

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "nisObject"),
            "OtherAttributes": (self.cli.option.PLAIN, self._attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        self.info = parsed
        return self

    def modify(
        self,
        *,
        info: str | NFSExport | ADAutomountMap | DeleteAttribute | None = None,
    ) -> ADAutomountKey:
        """
        Modify existing AD automount key.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param info: Automount information, defaults to ``None``
        :type info:  str | NFSExport | ADAutomountMap | DeleteAttribute | None
        :return: Self.
        :rtype: ADAutomountKey
        """
        parsed = self.__get_info(info)
        attrs = {
            "nisMapEntry": parsed,
        }

        clear = [key for key, value in attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value for key, value in attrs.items() if value is not None and not isinstance(value, DeleteAttribute)
        }

        args: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, self._attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(args)
        self.info = parsed if not isinstance(parsed, DeleteAttribute) else ""
        return self

    def dump(self) -> str:
        """
        Dump the key in the ``automount -m`` format.

        .. code-block:: text

            export1 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export1

        You can also call ``str(key)`` instead of ``key.dump()``.

        :return: Key information in ``automount -m`` format.
        :rtype: str
        """
        return f"{self.name} | {self.info}"

    def __str__(self) -> str:
        """
        Alias for :meth:`dump` method.

        :return: Key information in ``automount -m`` format.
        :rtype: str
        """
        return self.dump()

    def __get_info(
        self, info: str | NFSExport | ADAutomountMap | DeleteAttribute | None
    ) -> str | DeleteAttribute | None:
        if isinstance(info, NFSExport):
            return info.get()

        if isinstance(info, ADAutomountMap):
            return info.name

        return info
