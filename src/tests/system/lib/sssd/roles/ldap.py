"""LDAP multihost role."""

from __future__ import annotations

from enum import Enum
from typing import Any, Generic, Protocol, TypeVar

import ldap
import ldap.ldapobject

from ..hosts.ldap import LDAPHost
from ..misc import attrs_include_value, to_list_without_none
from ..utils.ldap import LDAPRecordAttributes, LDAPUtils
from .base import BaseLinuxLDAPRole, BaseObject, DeleteAttribute, HostType
from .nfs import NFSExport

__all__ = [
    "ProtocolName",
    "LDAPRoleType",
    "LDAPUserType",
    "LDAPGroupType",
    "LDAP",
    "LDAPObject",
    "LDAPACI",
    "LDAPOrganizationalUnit",
    "LDAPUser",
    "LDAPGroup",
    "LDAPSudoRule",
    "LDAPAutomount",
    "LDAPAutomountMap",
    "LDAPAutomountKey",
]


class ProtocolName(Protocol):
    """
    Used to hint that the type must contain name attribute.
    """

    name: str


LDAPRoleType = TypeVar("LDAPRoleType", bound=BaseLinuxLDAPRole)
LDAPUserType = TypeVar("LDAPUserType", bound=ProtocolName)
LDAPGroupType = TypeVar("LDAPGroupType", bound=ProtocolName)


class LDAP(BaseLinuxLDAPRole[LDAPHost]):
    """
    LDAP role.

    Provides unified Python API for managing objects in the LDAP server.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_example(ldap: LDAP):
            u = ldap.user('tuser').add()
            g = ldap.group('tgroup').add()
            g.add_member(u)

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.auto_uid: int = 23000
        """The next automatically assigned user id."""

        self.auto_gid: int = 33000
        """The next automatically assigned group id."""

        self.aci: LDAPACI = LDAPACI(self)
        """Manage LDAP ACI records."""

        self.automount: LDAPAutomount[LDAPHost, LDAP] = LDAPAutomount[LDAPHost, LDAP](self)
        """
        Manage automount maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example_autofs(client: Client, ldap: LDAP, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automount maps
                auto_master = ldap.automount.map('auto.master').add()
                auto_home = ldap.automount.map('auto.home').add()
                auto_sub = ldap.automount.map('auto.sub').add()

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

    def _generate_uid(self) -> int:
        """
        Generate next user id value.

        :return: User id.
        :rtype: int
        """
        self.auto_uid += 1
        return self.auto_uid

    def _generate_gid(self) -> int:
        """
        Generate next group id value.

        :return: Group id.
        :rtype: int
        """
        self.auto_gid += 1
        return self.auto_gid

    def ou(self, name: str, basedn: LDAPObject | str | None = None) -> LDAPOrganizationalUnit[LDAPHost, LDAP]:
        """
        Get organizational unit object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                # Create user
                ou = ldap.ou('my-users').add()
                ldap.user('user-1', basedn=ou).add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and test that the user was found
                result = client.tools.id('user-1') is not None

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :return: New organizational unit object.
        :rtype: LDAPOrganizationalUnit[LDAPHost, LDAP]
        """
        return LDAPOrganizationalUnit[LDAPHost, LDAP](self, name, basedn)

    def user(self, name: str, basedn: LDAPObject | str | None = "ou=users") -> LDAPUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                # Create user
                ldap.user('user-1').add(uid=10001, gid=10001)

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.user.id == 10001
                assert result.group.id == 10001  # primary group
                assert result.group.name is None

        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=users``
        :type basedn: LDAPObject | str | None, optional
        :return: New user object.
        :rtype: LDAPUser
        """
        return LDAPUser(self, name, basedn)

    def group(
        self, name: str, basedn: LDAPObject | str | None = "ou=groups", *, rfc2307bis: bool = False
    ) -> LDAPGroup:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                # Create user
                user = ldap.user('user-1').add(uid=10001, gid=10001)

                # Create primary group
                ldap.group('user-1').add(gid=10001)

                # Create secondary group and add user as a member
                ldap.group('group-1').add(gid=20001).add_member(user)

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.user.id == 10001
                assert result.group.id == 10001  # primary group
                assert result.group.name == 'user-1'
                assert result.memberof('group-1')


        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=groups``
        :type basedn: LDAPObject | str | None, optional
        :param rfc2307bis: If True, rfc2307bis schema is used, defaults to False
        :type rfc2307bis: bool, optional
        :return: New group object.
        :rtype: LDAPGroup
        """
        return LDAPGroup(self, name, basedn, rfc2307bis=rfc2307bis)

    def sudorule(
        self, name: str, basedn: LDAPObject | str | None = "ou=sudoers"
    ) -> LDAPSudoRule[LDAPHost, LDAP, LDAPUser, LDAPGroup]:
        """
        Get sudo rule object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                user = ldap.user('user-1').add(password="Secret123")
                ldap.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: LDAPObject | str | None, optional
        :return: New sudo rule object.
        :rtype: LDAPSudoRule[LDAPHost, LDAP, LDAPUser, LDAPGroup]
        """
        return LDAPSudoRule[LDAPHost, LDAP, LDAPUser, LDAPGroup](self, LDAPUser, LDAPGroup, name, basedn)


class LDAPObject(BaseObject[HostType, LDAPRoleType]):
    """
    Base class for LDAP object management.

    Provides shortcuts for command execution and implementation of :meth:`get`
    and :meth:`delete` methods.
    """

    def __init__(
        self,
        role: LDAPRoleType,
        name: str,
        rdn: str,
        basedn: LDAPObject | str | None = None,
        default_ou: str | None = None,
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAPRoleType
        :param name: Object name.
        :type name: str
        :param rdn: Relative distinguished name.
        :type rdn: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :param default_ou: Name of default organizational unit that is automatically
                           created if basedn is set to ou=$default_ou, defaults to None.
        :type default_ou: str | None, optional
        """
        super().__init__(role)

        self.name: str = name
        """Object name."""

        self.rdn: str = rdn
        """Object relative DN."""

        self.basedn: LDAPObject | str | None = basedn
        """Object base DN."""

        self.dn: str = self._dn(rdn, basedn)
        """Object DN."""

        self.default_ou: str | None = default_ou
        """Default organizational unit that usually holds this object."""

        self.__create_default_ou(basedn, self.default_ou)

    def __create_default_ou(self, basedn: LDAPObject | str | None, default_ou: str | None) -> None:
        """
        If default base dn is used we want to make sure that the container
        (usually an organizational unit) exit. This is to allow nicely working
        topology parametrization when the base dn is not specified and created
        inside the test because not all backends supports base dn (e.g. IPA).

        :param basedn: Selected base DN.
        :type basedn: LDAPObject | str | None
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

    def _dn(self, rdn: str, basedn: LDAPObject | str | None = None) -> str:
        """
        Get distinguished name of an object.

        :param rdn: Relative DN.
        :type rdn: str
        :param basedn: Base DN, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :return: Distinguished name combined from rdn+dn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, LDAPObject):
            return f"{rdn},{basedn.dn}"

        return self.role.ldap.dn(rdn, basedn)

    def _default(self, value: Any, default: Any) -> Any:
        """
        :return: Value if not None, default value otherwise.
        :rtype: Any
        """
        if value is None:
            return default

        return value

    def _hash_password(self, password: str | None | DeleteAttribute) -> str | None | DeleteAttribute:
        """
        Compute sha256 hash of a password that can be used as a value.

        Return original value If password is None or DeleteAttribute.

        :param password: Password to hash.
        :type password: str
        :return: Base64 of sha256 hash digest.
        :rtype: str
        """
        if password is None or isinstance(password, DeleteAttribute):
            # Return unchanged value to simplify attribute modification
            return password

        return self.role.ldap.hash_password(password)

    def _add(self, attrs: LDAPRecordAttributes) -> None:
        """
        Add LDAP record.

        :param attrs: LDAP attributes.
        :type attrs: LDAPRecordAttributes
        """
        self.role.ldap.add(self.dn, attrs)

    def _modify(
        self,
        *,
        add: LDAPRecordAttributes | None = None,
        replace: LDAPRecordAttributes | None = None,
        delete: LDAPRecordAttributes | None = None,
    ) -> None:
        """
        Modify LDAP record.

        :param add: Attributes and values to add, defaults to None
        :type add: LDAPRecordAttributes | None, optional
        :param replace: Attributes and values to replace, defaults to None
        :type replace: LDAPRecordAttributes | None, optional
        :param delete: Attributes and values to delete, defaults to None
        :type delete: LDAPRecordAttributes | None, optional
        """
        self.role.ldap.modify(self.dn, add=add, replace=replace, delete=delete)

    def _set(self, attrs: LDAPRecordAttributes) -> None:
        """
        Set LDAP record attributes to specific values.

        This is similar to modify. The attributes are either replaced with their
        given values or the whole attribute is deleted if DeleteAttribute is
        set as the value.

        :param attrs: Dictionary with attribute name as the key.
        :type attrs: LDAPRecordAttributes
        """
        replace: dict[str, Any] = {}
        delete: dict[str, Any] = {}
        for attr, value in attrs.items():
            if value is None:
                continue

            if isinstance(value, DeleteAttribute):
                delete[attr] = None
                continue

            replace[attr] = value

        self.role.ldap.modify(self.dn, replace=replace, delete=delete)

    def delete(self) -> None:
        """
        Delete LDAP record..
        """
        self.role.ldap.delete(self.dn)

    def get(self, attrs: list[str] | None = None, opattrs: bool = False) -> dict[str, list[str]] | None:
        """
        Get LDAP record attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :param opattrs: If True, operational attributes are returned as well, defaults to False
        :type opattrs: bool, optional
        :raises ValueError: If multiple objects with the same dn exists.
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        attrs = ["*"] if attrs is None else attrs
        if opattrs:
            attrs.append("+")

        result = self.role.ldap.conn.search_s(self.dn, ldap.SCOPE_BASE, attrlist=attrs)
        if not result:
            return None

        if len(result) != 1:
            raise ValueError(f"Multiple objects returned on base search for {self.dn}")

        (_, result_attrs) = result[0]

        return {k: [i.decode("utf-8") for i in v] for k, v in result_attrs.items()}


class LDAPACI(object):
    """
    LDAP ACI records management.
    """

    def __init__(self, role: LDAP) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        """
        self.role: LDAP = role
        self.ldap: LDAPUtils = self.role.ldap
        self.dn: str = self.ldap.naming_context

    def add(self, value: str):
        """
        Add new ACI record.

        :param value: ACI value
        :type value: str
        """
        self.ldap.modify(self.dn, add={"aci": value})

    def modify(self, old: str, new: str):
        """
        Modify existing ACI record.

        :param old: Old ACI value
        :type old: str
        :param new: New ACI value
        :type new: str
        """
        self.delete(old)
        self.add(new)

    def delete(self, value: str):
        """
        Delete existing ACI record.

        :param value: ACI value
        :type value: str
        """
        self.ldap.modify(self.dn, delete={"aci": value})


class LDAPOrganizationalUnit(LDAPObject[HostType, LDAPRoleType]):
    """
    LDAP organizational unit management.
    """

    def __init__(self, role: LDAPRoleType, name: str, basedn: LDAPObject | str | None = None) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAPRoleType
        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        """
        super().__init__(role, name, f"ou={name}", basedn)

    def add(self) -> LDAPOrganizationalUnit:
        """
        Create new LDAP organizational unit.

        :return: Self.
        :rtype: LDAPOrganizationalUnit
        """
        attrs: LDAPRecordAttributes = {"objectClass": "organizationalUnit", "ou": self.name}

        self._add(attrs)
        return self


class LDAPUser(LDAPObject[LDAPHost, LDAP]):
    """
    LDAP user management.
    """

    def __init__(self, role: LDAP, name: str, basedn: LDAPObject | str | None = "ou=users") -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=users``
        :type basedn: LDAPObject | str | None, optional
        """
        super().__init__(role, name, f"cn={name}", basedn, default_ou="users")

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        shadowMin: int | None = None,
        shadowMax: int | None = None,
        shadowWarning: int | None = None,
        shadowLastChange: int | None = None,
    ) -> LDAPUser:
        """
        Create new LDAP user.

        User and group id is assigned automatically if they are not set. Other
        parameters that are not set are ignored.

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
        :param shadowMin: shadowmin LDAP attribute, defaults to None
        :type shadowMin: int | None, optional
        :param shadowMax: shadowmax LDAP attribute, defaults to None
        :type shadowMax: int | None, optional
        :param shadowWarning: shadowwarning LDAP attribute, defaults to None
        :type shadowWarning: int | None, optional
        :param shadowLastChange: shadowlastchage LDAP attribute, defaults to None
        :type shadowLastChange: int | None, optional
        :return: Self.
        :rtype: LDAPUser
        """
        # Assign uid and gid automatically if not present to have the same
        # interface as other services.
        if uid is None:
            uid = self.role._generate_uid()

        if gid is None:
            gid = uid

        attrs = {
            "objectClass": ["posixAccount"],
            "cn": self.name,
            "uid": self.name,
            "uidNumber": uid,
            "gidNumber": gid,
            "homeDirectory": self._default(home, f"/home/{self.name}"),
            "userPassword": self._hash_password(password),
            "gecos": gecos,
            "loginShell": shell,
            "shadowMin": shadowMin,
            "shadowMax": shadowMax,
            "shadowWarning": shadowWarning,
            "shadowLastChange": shadowLastChange,
        }

        if to_list_without_none([shadowMin, shadowMax, shadowWarning, shadowLastChange]):
            attrs["objectClass"].append("shadowAccount")

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        uid: int | DeleteAttribute | None = None,
        gid: int | DeleteAttribute | None = None,
        password: str | DeleteAttribute | None = None,
        home: str | DeleteAttribute | None = None,
        gecos: str | DeleteAttribute | None = None,
        shell: str | DeleteAttribute | None = None,
        shadowMin: int | DeleteAttribute | None = None,
        shadowMax: int | DeleteAttribute | None = None,
        shadowWarning: int | DeleteAttribute | None = None,
        shadowLastChange: int | DeleteAttribute | None = None,
    ) -> LDAPUser:
        """
        Modify existing LDAP user.

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
        :param shadowMin: shadowmin LDAP attribute, defaults to None
        :type shadowMin: int | DeleteAttribute | None, optional
        :param shadowMax: shadowmax LDAP attribute, defaults to None
        :type shadowMax: int | DeleteAttribute | None, optional
        :param shadowWarning: shadowwarning LDAP attribute, defaults to None
        :type shadowWarning: int | DeleteAttribute | None, optional
        :param shadowLastChange: shadowlastchage LDAP attribute, defaults to None
        :type shadowLastChange: int | DeleteAttribute | None, optional
        :return: Self.
        :rtype: LDAPUser
        """
        attrs: LDAPRecordAttributes = {
            "uidNumber": uid,
            "gidNumber": gid,
            "homeDirectory": home,
            "userPassword": self._hash_password(password),
            "gecos": gecos,
            "loginShell": shell,
            "shadowMin": shadowMin,
            "shadowMax": shadowMax,
            "shadowWarning": shadowWarning,
            "shadowLastChange": shadowLastChange,
        }

        self._set(attrs)
        return self


class LDAPGroup(LDAPObject[LDAPHost, LDAP]):
    """
    LDAP group management.
    """

    def __init__(
        self, role: LDAP, name: str, basedn: LDAPObject | str | None = "ou=groups", *, rfc2307bis: bool = False
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=groups``
        :type basedn: LDAPObject | str | None, optional
        :param rfc2307bis: If True, rfc2307bis schema is used, defaults to False
        :type rfc2307bis: bool, optional
        """
        super().__init__(role, name, f"cn={name}", basedn, default_ou="groups")

        self.rfc2307bis: bool = rfc2307bis
        """True if rfc2307bis schema should be used."""

        if not self.rfc2307bis:
            self.object_class = ["posixGroup"]
            self.member_attr = "memberUid"
        else:
            self.object_class = ["posixGroup", "groupOfNames"]
            self.member_attr = "member"

    def __members(self, values: list[LDAPUser | LDAPGroup | str] | None) -> list[str] | None:
        if values is None:
            return None

        if self.rfc2307bis:
            return [x.dn if isinstance(x, LDAPObject) else self._dn(x) for x in values]

        return [x.name if isinstance(x, LDAPObject) else x for x in values]

    def add(
        self,
        *,
        gid: int | None = None,
        members: list[LDAPUser | LDAPGroup | str] | None = None,
        password: str | None = None,
        description: str | None = None,
    ) -> LDAPGroup:
        """
        Create new LDAP group.

        Group id is assigned automatically if it is not set. Other parameters
        that are not set are ignored.

        :param gid: _description_, defaults to None
        :type gid: int | None, optional
        :param members: List of group members, defaults to None
        :type members: list[LDAPUser  |  LDAPGroup  |  str] | None, optional
        :param password: Group password, defaults to None
        :type password: str | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: LDAPGroup
        """
        # Assign gid automatically if not present to have the same
        # interface as other services.
        if gid is None:
            gid = self.role._generate_gid()

        attrs = {
            "objectClass": self.object_class,
            "cn": self.name,
            "gidNumber": gid,
            "userPassword": self._hash_password(password),
            "description": description,
            self.member_attr: self.__members(members),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | DeleteAttribute | None = None,
        members: list[LDAPUser | LDAPGroup | str] | DeleteAttribute | None = None,
        password: str | DeleteAttribute | None = None,
        description: str | DeleteAttribute | None = None,
    ) -> LDAPGroup:
        """
        Modify existing LDAP group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param gid: Group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param members: List of group members, defaults to None
        :type members: list[LDAPUser  |  LDAPGroup  |  str] | DeleteAttribute | None, optional
        :param password: Group password, defaults to None
        :type password: str | DeleteAttribute | None, optional
        :param description: Description, defaults to None
        :type description: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: LDAPGroup
        """
        attrs = {
            "gidNumber": gid,
            "userPassword": self._hash_password(password),
            "description": description,
            self.member_attr: self.__members(members) if not isinstance(members, DeleteAttribute) else members,
        }

        self._set(attrs)
        return self

    def add_member(self, member: LDAPUser | LDAPGroup | str) -> LDAPGroup:
        """
        Add group member.

        :param member: User or group (on rfc2307bis schema) to add as a member.
        :type member: LDAPUser | LDAPGroup | str
        :return: Self.
        :rtype: LDAPGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[LDAPUser | LDAPGroup | str]) -> LDAPGroup:
        """
        Add multiple group members.

        :param members: Users or groups (on rfc2307bis schema) to add as members.
        :type members: list[LDAPUser | LDAPGroup | str]
        :return: Self.
        :rtype: LDAPGroup
        """
        self._modify(add={self.member_attr: self.__members(members)})
        return self

    def remove_member(self, member: LDAPUser | LDAPGroup | str) -> LDAPGroup:
        """
        Remove group member.

        :param member: User or group (on rfc2307bis schema) to add as a member.
        :type member: LDAPUser | LDAPGroup | str
        :return: Self.
        :rtype: LDAPGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[LDAPUser | LDAPGroup | str]) -> LDAPGroup:
        """
        Remove multiple group members.

        :param members: Users or groups (on rfc2307bis schema) to add as members.
        :type members: list[LDAPUser | LDAPGroup | str]
        :return: Self.
        :rtype: LDAPGroup
        """
        self._modify(delete={self.member_attr: self.__members(members)})
        return self


class LDAPSudoRule(Generic[HostType, LDAPRoleType, LDAPUserType, LDAPGroupType], LDAPObject[HostType, LDAPRoleType]):
    """
    LDAP sudo rule management.
    """

    def __init__(
        self,
        role: LDAPRoleType,
        user_cls: type[LDAPUserType],
        group_cls: type[LDAPGroupType],
        name: str,
        basedn: LDAPObject | str | None = "ou=sudoers",
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAPRoleType
        :param user_cls: User class.
        :type user_cls: type[LDAPUserType]
        :param group_cls: Group class-
        :type group_cls: type[LDAPGroupType]
        :param name: Sudo rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: LDAPObject | str | None, optional
        """
        super().__init__(role, name, f"cn={name}", basedn, default_ou="sudoers")

        self.user_cls: type[LDAPUserType] = user_cls
        """User class."""

        self.group_cls: type[LDAPGroupType] = group_cls
        """Group class."""

    def add(
        self,
        *,
        user: int | str | LDAPUserType | LDAPGroupType | list[int | str | LDAPUserType | LDAPGroupType] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: int
        | str
        | LDAPUserType
        | LDAPGroupType
        | list[int | str | LDAPUserType | LDAPGroupType]
        | None = None,
        runasgroup: int | str | LDAPGroupType | list[int | str | LDAPGroupType] | None = None,
        notbefore: str | list[str] | None = None,
        notafter: str | list[str] | None = None,
        order: int | list[int] | None = None,
        nopasswd: bool | None = None,
    ) -> LDAPSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | LDAPUserType | LDAPGroupType | list[int | str | LDAPUserType | LDAPGroupType], optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str], optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str], optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: int | str | LDAPUserType | LDAPGroupType
            | list[int | str | LDAPUserType | LDAPGroupType] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | LDAPGroupType | list[int | str | LDAPGroupType] | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: LDAPSudoRule
        """
        attrs = {
            "objectClass": "sudoRole",
            "cn": self.name,
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

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        user: int
        | str
        | LDAPUserType
        | LDAPGroupType
        | list[int | str | LDAPUserType | LDAPGroupType]
        | DeleteAttribute
        | None = None,
        host: str | list[str] | DeleteAttribute | None = None,
        command: str | list[str] | DeleteAttribute | None = None,
        option: str | list[str] | DeleteAttribute | None = None,
        runasuser: int
        | str
        | LDAPUserType
        | LDAPGroupType
        | list[int | str | LDAPUserType | LDAPGroupType]
        | DeleteAttribute
        | None = None,
        runasgroup: int | str | LDAPGroupType | list[int | str | LDAPGroupType] | DeleteAttribute | None = None,
        notbefore: str | list[str] | DeleteAttribute | None = None,
        notafter: str | list[str] | DeleteAttribute | None = None,
        order: int | list[int] | DeleteAttribute | None = None,
        nopasswd: bool | None = None,
    ) -> LDAPSudoRule:
        """
        Modify existing sudo rule.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | LDAPUserType | LDAPGroupType | list[int | str | LDAPUserType | LDAPGroupType]
          | DeleteAttribute | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | DeleteAttribute | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | DeleteAttribute | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | DeleteAttribute | None, optional
        :param runasuser: sudoRunAsUsere attribute, defaults to None
        :type runasuser: int | str | LDAPUserType | LDAPGroupType | list[int | str | LDAPUserType | LDAPGroupType]
          | DeleteAttribute | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | LDAPGroupType | list[int | str | LDAPGroupType] | DeleteAttribute | None,
          optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | DeleteAttribute | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | DeleteAttribute | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | DeleteAttribute | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: LDAPSudoRule
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

        self._set(attrs)
        return self

    def __sudo_user(
        self,
        sudo_user: None
        | DeleteAttribute
        | int
        | str
        | LDAPUserType
        | LDAPGroupType
        | list[int | str | LDAPUserType | LDAPGroupType],
    ) -> list[str] | DeleteAttribute | None:
        def _get_value(value: int | str | LDAPUserType | LDAPGroupType):
            if isinstance(value, self.user_cls):
                return value.name

            if isinstance(value, self.group_cls):
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
        self, sudo_group: None | DeleteAttribute | int | str | LDAPGroupType | list[int | str | LDAPGroupType]
    ) -> list[str] | DeleteAttribute | None:
        def _get_value(value: int | str | LDAPGroupType):
            if isinstance(value, self.group_cls):
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


class LDAPAutomount(Generic[HostType, LDAPRoleType]):
    """
    LDAP automount management.
    """

    class Schema(Enum):
        """
        LDAP automount schema.
        """

        RFC2307 = ("rfc2307",)
        RFC2307bis = ("rfc2307bis",)
        AD = ("ad",)

    def __init__(self, role: LDAPRoleType) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAPRoleType
        """
        self.__role: LDAPRoleType = role
        self.__schema: LDAPAutomount.Schema = self.Schema.RFC2307

    def map(
        self, name: str, basedn: LDAPObject | str | None = "ou=autofs"
    ) -> LDAPAutomountMap[HostType, LDAPRoleType]:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: LDAPObject | str | None, optional
        :return: New automount map object.
        :rtype: LDAPAutomountMap[HostType, LDAPRoleType]:
        """
        return LDAPAutomountMap[HostType, LDAPRoleType](self.__role, name, basedn, schema=self.__schema)

    def key(self, name: str, map: LDAPAutomountMap) -> LDAPAutomountKey[HostType, LDAPRoleType]:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: LDAPAutomountMap
        :return: New automount key object.
        :rtype: LDAPAutomountKey[HostType, LDAPRoleType]
        """
        return LDAPAutomountKey[HostType, LDAPRoleType](self.__role, name, map, schema=self.__schema)

    def set_schema(self, schema: "LDAPAutomount.Schema"):
        """
        Set automount LDAP schema.

        :param schema: LDAP Schema.
        :type schema: LDAPAutomount.Schema
        """
        self.__schema = schema


class LDAPAutomountMap(LDAPObject[HostType, LDAPRoleType]):
    """
    LDAP automount map management.
    """

    def __init__(
        self,
        role: LDAPRoleType,
        name: str,
        basedn: LDAPObject | str | None = "ou=autofs",
        *,
        schema: LDAPAutomount.Schema = LDAPAutomount.Schema.RFC2307,
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAP
        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: LDAPObject | str | None, optional
        :param schema: LDAP Automount schema, defaults to ``LDAPAutomount.Schema.RFC2307``
        :type schema: LDAPAutomount.Schema
        """
        self.__schema: LDAPAutomount.Schema = schema
        self.__attrs: dict[str, str] = self.__get_attrs_map(schema)
        super().__init__(role, name, f'{self.__attrs["rdn"]}={name}', basedn, default_ou="autofs")

    def __get_attrs_map(self, schema: LDAPAutomount.Schema) -> dict[str, str]:
        if schema == LDAPAutomount.Schema.RFC2307:
            return {
                "objectClass": "nisMap",
                "rdn": "nisMapName",
                "automountMapName": "nisMapName",
            }
        elif schema == LDAPAutomount.Schema.RFC2307bis:
            return {
                "objectClass": "automountMap",
                "rdn": "automountMapName",
                "automountMapName": "automountMapName",
            }
        elif schema == LDAPAutomount.Schema.AD:
            return {
                "objectClass": "nisMap",
                "rdn": "cn",
                "automountMapName": "nisMapName",
            }
        else:
            raise ValueError(f"Unknown schema: {schema}")

    def add(
        self,
    ) -> LDAPAutomountMap:
        """
        Create new LDAP automount map.

        :return: Self.
        :rtype: LDAPAutomountMap
        """
        attrs: LDAPRecordAttributes = {
            "objectClass": self.__attrs["objectClass"],
            self.__attrs["automountMapName"]: self.name,
        }

        if self.__schema == LDAPAutomount.Schema.AD:
            attrs["cn"] = self.name

        self._add(attrs)
        return self

    def key(self, name: str) -> LDAPAutomountKey[HostType, LDAPRoleType]:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: LDAPAutomountKey
        """
        return LDAPAutomountKey(self.role, name, self, schema=self.__schema)


class LDAPAutomountKey(LDAPObject[HostType, LDAPRoleType]):
    """
    LDAP automount key management.
    """

    def __init__(
        self,
        role: LDAPRoleType,
        name: str,
        map: LDAPAutomountMap,
        *,
        schema: LDAPAutomount.Schema = LDAPAutomount.Schema.RFC2307,
    ) -> None:
        """
        :param role: LDAP role object.
        :type role: LDAPRoleType
        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: LDAPAutomountMap
        :param schema: LDAP Automount schema, defaults to ``LDAPAutomount.Schema.RFC2307``
        :type schema: LDAPAutomount.Schema
        """
        self.__schema: LDAPAutomount.Schema = schema
        self.__attrs: dict[str, str] = self.__get_attrs_map(schema)

        super().__init__(role, name, f'{self.__attrs["rdn"]}={name}', map)
        self.map: LDAPAutomountMap = map
        self.info: str = ""

    def __get_attrs_map(self, schema: LDAPAutomount.Schema) -> dict[str, str]:
        if schema == LDAPAutomount.Schema.RFC2307:
            return {
                "objectClass": "nisObject",
                "rdn": "cn",
                "automountKey": "cn",
                "automountInformation": "nisMapEntry",
            }
        elif schema == LDAPAutomount.Schema.RFC2307bis:
            return {
                "objectClass": "automount",
                "rdn": "automountKey",
                "automountKey": "automountKey",
                "automountInformation": "automountInformation",
            }
        elif schema == LDAPAutomount.Schema.AD:
            return {
                "objectClass": "nisObject",
                "rdn": "cn",
                "automountKey": "cn",
                "automountInformation": "nisMapEntry",
            }
        else:
            raise ValueError(f"Unknown schema: {schema}")

    def add(self, *, info: str | NFSExport | LDAPAutomountMap) -> LDAPAutomountKey:
        """
        Create new LDAP automount key.

        :param info: Automount information.
        :type info: str | NFSExport | LDAPAutomountMap
        :return: Self.
        :rtype: LDAPAutomountKey
        """
        parsed = self.__get_info(info)
        if isinstance(parsed, DeleteAttribute) or parsed is None:
            # This should not happen, it is here just to silence mypy
            raise ValueError("Invalid value of info attribute")

        attrs = {
            "objectClass": self.__attrs["objectClass"],
            self.__attrs["automountKey"]: self.name,
            self.__attrs["automountInformation"]: parsed,
        }

        if self.__schema in [LDAPAutomount.Schema.RFC2307, LDAPAutomount.Schema.AD]:
            attrs["nisMapName"] = self.map.name

        self._add(attrs)
        self.info = parsed
        return self

    def modify(
        self,
        *,
        info: str | NFSExport | LDAPAutomountMap | DeleteAttribute | None = None,
    ) -> LDAPAutomountKey:
        """
        Modify existing LDAP automount key.

        :param info: Automount information, defaults to ``None``
        :type info: str | NFSExport | LDAPAutomountMap | DeleteAttribute | None
        :return: Self.
        :rtype: LDAPAutomountKey
        """
        parsed = self.__get_info(info)
        attrs = {
            self.__attrs["automountInformation"]: parsed,
        }

        self._set(attrs)
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

    def __get_info(self, info: str | NFSExport | LDAPAutomountMap | DeleteAttribute | None):
        if isinstance(info, NFSExport):
            return info.get()

        if isinstance(info, LDAPAutomountMap):
            return info.name

        return info
