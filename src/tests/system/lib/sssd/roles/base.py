"""Base classes and objects for SSSD specific multihost roles."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Generic, TypeGuard, TypeVar

from pytest_mh import MultihostRole
from pytest_mh.cli import CLIBuilder
from pytest_mh.utils.fs import LinuxFileSystem
from pytest_mh.utils.services import SystemdServices

from ..hosts.base import BaseHost, BaseLDAPDomainHost
from ..utils.authentication import AuthenticationUtils
from ..utils.authselect import AuthselectUtils
from ..utils.ldap import LDAPUtils
from ..utils.tools import LinuxToolsUtils

HostType = TypeVar("HostType", bound=BaseHost)
RoleType = TypeVar("RoleType", bound=MultihostRole)
LDAPHostType = TypeVar("LDAPHostType", bound=BaseLDAPDomainHost)


__all__ = [
    "HostType",
    "RoleType",
    "LDAPHostType",
    "DeleteAttribute",
    "BaseObject",
    "BaseRole",
    "BaseLinuxRole",
    "BaseLinuxLDAPRole",
    "BaseWindowsRole",
]


class DeleteAttribute(object):
    """
    This class is used to distinguish between setting an attribute to an empty
    value and deleting it completely.
    """

    pass


class BaseObject(Generic[HostType, RoleType]):
    """
    Base class for object management classes (like users or groups).

    It provides shortcuts to low level functionality to easily enable execution
    of remote commands. It also defines multiple helper methods that are shared
    across roles.
    """

    def __init__(self, role: RoleType) -> None:
        self.role: RoleType = role
        """Multihost role object."""

        self.host: HostType = role.host
        """Multihost host object."""

        self.cli: CLIBuilder = self.host.cli
        """Command line builder to easy build command line for execution."""


class BaseRole(MultihostRole[HostType]):
    """
    Base role class. Roles are the main interface to the remote hosts that can
    be directly accessed in test cases as fixtures.

    All changes to the remote host that were done through the role object API
    are automatically reverted when a test is finished.
    """

    Delete: DeleteAttribute = DeleteAttribute()
    """
    Use this to indicate that you want to delete an attribute instead of setting
    it to an empty value.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def is_delete_attribute(self, value: Any) -> TypeGuard[DeleteAttribute]:
        """
        Return ``True`` if the value is :attr:`DeleteAttribute`

        :param value: Value to test.
        :type value: Any
        :return: Return ``True`` if the value is :attr:`DeleteAttribute`
        :rtype: TypeGuard[DeleteAttribute]
        """
        return isinstance(value, DeleteAttribute)


class BaseLinuxRole(BaseRole[HostType]):
    """
    Base linux role.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.authselect: AuthselectUtils = AuthselectUtils(self.host)
        """
        Manage nsswitch and PAM configuration.
        """

        self.fs: LinuxFileSystem = LinuxFileSystem(self.host)
        """
        File system manipulation.
        """

        self.svc: SystemdServices = SystemdServices(self.host)
        """
        Systemd service management.
        """

        self.tools: LinuxToolsUtils = LinuxToolsUtils(self.host, self.fs)
        """
        Standard tools interface.
        """

        self.auth: AuthenticationUtils = AuthenticationUtils(self.host)
        """
        Authentication helpers.
        """


class BaseLinuxLDAPRole(BaseLinuxRole[LDAPHostType]):
    """
    Base Linux role for roles that require direct LDAP access.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.ldap: LDAPUtils = LDAPUtils(self.host)
        """Provides methods for direct LDAP access to the LDAP server."""

        self.auto_ou: dict[str, bool] = {}
        """Organizational units that were automatically created."""

    @abstractmethod
    def ou(self, name: str, basedn=None):
        pass


class BaseWindowsRole(BaseRole[HostType]):
    """
    Base Windows role.
    """

    pass
