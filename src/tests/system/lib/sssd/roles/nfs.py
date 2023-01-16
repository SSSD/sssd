"""NFS multihost role."""

from __future__ import annotations

from ..hosts.nfs import NFSHost
from .base import BaseLinuxRole, BaseObject

__all__ = [
    "NFS",
    "NFSExport",
]


class NFS(BaseLinuxRole[NFSHost]):
    """
    NFS role.

    Provides unified Python API for managing shared folders on the NFS server.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_example(nfs: NFS):
            nfs.export('test').add()

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.hostname: str = self.host.hostname
        """NFS server hostname."""

        self.exports_dir: str = self.host.exports_dir
        """Top level exports directory."""

    def exportfs_reload(self) -> None:
        """
        Reexport all directories.
        """
        self.host.ssh.run("exportfs -r && exportfs -s")

    def export(
        self,
        path: str,
    ) -> NFSExport:
        """
        Get export object.

        :param path: Path relative to the top level exports directory.
        :type path: str
        :return: New export object.
        :rtype: NFSExport
        """
        return NFSExport(self, path)


class NFSExport(BaseObject[NFSHost, NFS]):
    """
    NFS shared folder management.
    """

    def __init__(self, role: NFS, path: str) -> None:
        super().__init__(role)

        self.hostname: str = role.hostname
        """NFS server hostname."""

        self.path: str = path.strip("/")
        """Exported path relative to the top level exports directory."""

        self.fullpath: str = f"{self.role.exports_dir}/{self.path}"
        """Absolute path of the exported directory."""

        self.exports_file = f'/etc/exports.d/{path.replace("/", "_")}.exports'
        """NFS exports file that manages this directory."""

        self.opts: str = "rw,sync,no_root_squash"
        """NFS export options, defaults to ``rw,sync,no_root_squash``."""

    def add(self, *, opts: str = "rw,sync,no_root_squash", reload: bool = True) -> NFSExport:
        """
        Start sharing this directory.

        :param opts: NFS export options, defaults to 'rw,sync,no_root_squash'
        :type opts: str, optional
        :param reload: Immediately reexport all directories, defaults to True
        :type reload: bool, optional
        :return: Self.
        :rtype: NFSExport
        """
        self.role.fs.mkdir_p(self.fullpath, mode="a=rwx")
        self.role.fs.write(self.exports_file, f"{self.fullpath} *({opts})")
        self.opts = opts

        if reload:
            self.role.exportfs_reload()

        return self

    def get(self) -> str:
        """
        Get NFS export specification for automounter.

        :rtype: str
        """
        return f"-fstype=nfs,{self.opts} {self.hostname}:{self.fullpath}"
