"""KDC multihost host."""

from __future__ import annotations

from .base import BaseDomainHost

__all__ = [
    "KDCHost",
]


class KDCHost(BaseDomainHost):
    """
    Kerberos KDC server host object.

    Provides features specific to Kerberos KDC.

    This class adds ``config.realm`` and ``config.domain`` multihost
    configuration options to set the default kerberos realm and domain.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 6-7

        - hostname: kdc.test
          role: kdc
          config:
            realm: TEST
            domain: test
            client:
              krb5_server: kdc.test
              krb5_kpasswd: kdc.test
              krb5_realm: TEST

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.realm: str = self.config.get("realm", "TEST")
        self.krbdomain: str = self.config.get("domain", "test")

        self.client["auth_provider"] = "krb5"

    def backup(self) -> None:
        """
        Backup KDC server.
        """
        self.ssh.run('kdb5_util dump /tmp/mh.kdc.kdb.backup && rm -f "/tmp/mh.kdc.kdb.backup.dump_ok"')
        self._backup_location = "/tmp/mh.kdc.kdb.backup"

    def restore(self) -> None:
        """
        Restore KDC server to its initial contents.
        """
        if not self._backup_location:
            return

        self.ssh.run(f'kdb5_util load "{self._backup_location}"')
