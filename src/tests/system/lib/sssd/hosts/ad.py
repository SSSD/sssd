"""Active Directory multihost host."""

from __future__ import annotations

from .base import BaseDomainHost

__all__ = [
    "ADHost",
]


class ADHost(BaseDomainHost):
    """
    Active Directory host object.

    Provides features specific to Active Directory domain controller.

    .. warning::

        Backup and restore functionality of a domain controller is quite limited
        when compared to other backends. Unfortunately, a full backup and
        restore of a domain controller is not possible without a complete system
        backup and reboot which takes too long time and is not suitable for
        setting an exact state for each test. Therefore a limited backup and
        restore is provided which only deletes all added objects. It works well
        if a test does not modify any existing data but only uses new
        objects like newly added users and groups.

        If the test modifies existing data, it needs to make sure to revert
        the modifications manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Additional client configuration
        self.client.setdefault("id_provider", "ad")
        self.client.setdefault("access_provider", "ad")
        self.client.setdefault("ad_server", self.hostname)
        self.client.setdefault("dyndns_update", False)

        # Lazy properties
        self.__naming_context: str | None = None

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :raises ValueError: If default naming context can not be obtained.
        :rtype: str
        """
        if not self.__naming_context:
            result = self.ssh.run("Write-Host (Get-ADRootDSE).rootDomainNamingContext")
            nc = result.stdout.strip()
            if not nc:
                raise ValueError("Unable to find default naming context")

            self.__naming_context = nc

        return self.__naming_context

    def disconnect(self) -> None:
        return

    def backup(self) -> None:
        """
        Perform limited backup of the domain controller data. Currently only
        content under ``$default_naming_context`` is backed up.

        This is done by performing simple LDAP search on the base dn. This
        operation is usually very fast.
        """
        self.ssh.run(
            rf"""
        Remove-Item C:\multihost_backup.txt
        $result = Get-ADObject -SearchBase '{self.naming_context}' -Filter "*"
        foreach ($r in $result) {{
            $r.DistinguishedName | Add-Content -Path C:\multihost_backup.txt
        }}
        """
        )
        self._backup_location = "C:\\multihost_backup.txt"

    def restore(self) -> None:
        """
        Perform limited restoration of the domain controller state.

        This is done by removing all records under ``$default_naming_context``
        that are not present in the original state.
        """
        if not self._backup_location:
            return

        self.ssh.run(
            rf"""
        $backup = Get-Content "{self._backup_location}"
        $result = Get-ADObject -SearchBase '{self.naming_context}' -Filter "*"
        foreach ($r in $result) {{
            if (!$backup.contains($r.DistinguishedName)) {{
                Write-Host "Removing: $r"
                Try {{
                   Remove-ADObject -Identity $r.DistinguishedName -Recursive -Confirm:$False
                }} Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {{
                    # Ignore not found error as the object may have been deleted by recursion
                }}
            }}
        }}

        # If we got here, make sure we exit with 0
        Exit 0
        """
        )
