"""Base classes and objects for SSSD specific multihost hosts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import ldap
import ldap.ldapobject
from pytest_mh import MultihostHost
from pytest_mh.ssh import SSHPowerShellProcess

from ..config import SSSDMultihostDomain

__all__ = [
    "BaseHost",
    "BaseBackupHost",
    "BaseDomainHost",
    "BaseLDAPDomainHost",
]


class BaseHost(MultihostHost[SSSDMultihostDomain]):
    """
    Base class for all SSSD hosts.
    """

    pass


class BaseBackupHost(BaseHost, ABC):
    """
    Base class for all hosts that supports automatic backup and restore.

    A backup of the host is created before starting a test case and all changes
    done in the test case to the host are automatically reverted when the test
    run is finished.

    .. warning::

        There might be some limitations on what data can and can not be restored
        that depends on particular host. See the documentation of each host
        class to learn if a full or partial restoration is done.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.__backup_created: bool = False
        """True if backup of the backend was already created."""

        self._backup_location: str | None = None
        """Backup file or folder location."""

    def pytest_teardown(self) -> None:
        """
        Called once after all tests are finished.
        """
        if self._backup_location is not None:
            if self.ssh.shell is SSHPowerShellProcess:
                self.ssh.exec(["Remove-Item", "-Force", "-Recurse", self._backup_location])
            else:
                self.ssh.exec(["rm", "-fr", self._backup_location])

        super().teardown()

    def setup(self) -> None:
        """
        Called before execution of each test.

        Perform backup of the backend.
        """
        super().setup()

        # Make sure to backup the data only once
        if not self.__backup_created:
            self.backup()
            self.__backup_created = True

    def teardown(self) -> None:
        """
        Called after execution of each test.

        Perform teardown of the backend, the backend is restored to its original
        state where is was before the test was executed.
        """
        if self.__backup_created:
            self.restore()
        super().teardown()

    @abstractmethod
    def backup(self) -> None:
        """
        Backup backend data.
        """
        pass

    @abstractmethod
    def restore(self) -> None:
        """
        Restore backend data.
        """
        pass


class BaseDomainHost(BaseBackupHost):
    """
    Base class for all domain (backend) hosts.

    This class extends the multihost configuration with ``config.client``
    section that can contain additional SSSD configuration for the domain to
    allow connection to the domain (like keytab and certificate locations,
    domain name, etc.).

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 4-7

        - hostname: master.ipa.test
          role: ipa
          config:
            client:
              ipa_domain: ipa.test
              krb5_keytab: /enrollment/ipa.keytab
              ldap_krb5_keytab: /enrollment/ipa.keytab
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.client: dict[str, Any] = self.config.get("client", {})


class BaseLDAPDomainHost(BaseDomainHost):
    """
    Base class for all domain (backend) hosts that require direct LDAP access to
    manipulate data (like 389ds or SambaDC).

    Extends :class:`BaseDomainHost` to manage LDAP connection and adds
    ``config.binddn`` and ``config.bindpw`` multihost configuration options.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 6-7

        - hostname: master.ldap.test
          role: ldap
          config:
            binddn: cn=Directory Manager
            bindpw: Secret123
            client:
              ldap_tls_reqcert: demand
              ldap_tls_cacert: /data/certs/ca.crt
              dns_discovery_domain: ldap.test

    .. note::

        The LDAP connection is not opened immediately, but only when
        :attr:`conn` is accessed for the first time.
    """

    def __init__(self, *args, tls: bool = True, **kwargs) -> None:
        """
        :param tls: Require TLS connection, defaults to True
        :type tls: bool, optional
        """
        super().__init__(*args, **kwargs)

        self.tls: bool = tls
        """Use TLS when establishing connection or no?"""

        self.binddn: str = self.config.get("binddn", "cn=Directory Manager")
        """Bind DN ``config.binddn``, defaults to ``cn=Directory Manager``"""

        self.bindpw: str = self.config.get("bindpw", "Secret123")
        """Bind password ``config.bindpw``, defaults to ``Secret123``"""

        # Lazy properties.
        self.__conn: ldap.ldapobject.LDAPObject | None = None
        self.__naming_context: str | None = None

    @property
    def conn(self) -> ldap.ldapobject.LDAPObject:
        """
        LDAP connection (``python-ldap`` library).

        :rtype: ldap.ldapobject.LDAPObject
        """
        if not self.__conn:
            newconn = ldap.initialize(f"ldap://{self.ssh_host}")
            newconn.protocol_version = ldap.VERSION3
            newconn.set_option(ldap.OPT_REFERRALS, 0)

            if self.tls:
                newconn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                newconn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                newconn.start_tls_s()

            newconn.simple_bind_s(self.binddn, self.bindpw)
            self.__conn = newconn

        return self.__conn

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :raises ValueError: If default naming context can not be obtained.
        :rtype: str
        """
        if not self.__naming_context:
            attr = "defaultNamingContext"
            result = self.conn.search_s("", ldap.SCOPE_BASE, attrlist=[attr])
            if len(result) != 1:
                raise ValueError(f"Unexpected number of results for rootDSE query: {len(result)}")

            (_, values) = result[0]
            if attr not in values:
                raise ValueError(f"Unable to find {attr}")

            self.__naming_context = str(values[attr][0].decode("utf-8"))

        return self.__naming_context

    def disconnect(self) -> None:
        """
        Disconnect LDAP connection.
        """
        if self.__conn is not None:
            self.__conn.unbind()
            self.__conn = None

    def ldap_result_to_dict(
        self, result: list[tuple[str, dict[str, list[bytes]]]]
    ) -> dict[str, dict[str, list[bytes]]]:
        """
        Convert result from python-ldap library from tuple into a dictionary
        to simplify lookup by distinguished name.

        :param result: Search result from python-ldap.
        :type result: tuple[str, dict[str, list[bytes]]]
        :return: Dictionary with distinguished name as key and attributes as value.
        :rtype: dict[str, dict[str, list[bytes]]]
        """
        return dict((dn, attrs) for dn, attrs in result if dn is not None)
