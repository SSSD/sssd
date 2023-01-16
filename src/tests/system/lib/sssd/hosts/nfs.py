"""NFS multihost host."""

from __future__ import annotations

from .base import BaseBackupHost

__all__ = [
    "NFSHost",
]


class NFSHost(BaseBackupHost):
    """
    NFS server host object.

    Provides features specific to NFS server.

    This class adds ``config.exports_dir`` multihost configuration option to set
    the top level NFS exports directory where additional shares are created by
    individual test cases.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 4

        - hostname: nfs.test
          role: nfs
          config:
            exports_dir: /dev/shm/exports

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.exports_dir: str = self.config.get("exports_dir", "/exports").rstrip("/")
        """Top level NFS exports directory, defaults to ``/exports``."""

    def backup(self) -> None:
        """
        Backup NFS server.
        """
        self.ssh.run(
            rf"""
        tar --ignore-failed-read -czvf /tmp/mh.nfs.backup.tgz "{self.exports_dir}" /etc/exports /etc/exports.d
        """
        )
        self._backup_location = "/tmp/mh.nfs.backup.tgz"

    def restore(self) -> None:
        """
        Restore NFS server to its initial contents.
        """
        if not self._backup_location:
            return

        self.ssh.run(
            rf"""
        rm -fr "{self.exports_dir}/*"
        rm -fr /etc/exports.d/*
        tar -xf "{self._backup_location}" -C /
        exportfs -r
        """
        )
