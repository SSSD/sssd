"""Testing autofs/automount."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.utils.services import SystemdServices

if TYPE_CHECKING:
    from ..roles.nfs import NFSExport


__all__ = [
    "AutomountUtils",
]


class AutomountUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing automount.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_example_(client: Client, provider: GenericProvider, nfs: NFS):
            nfs_export1 = nfs.export('export1').add()
            nfs_export2 = nfs.export('export2').add()
            nfs_export3 = nfs.export('sub/export3').add()

            # Create automount maps
            auto_master = provider.automount.map('auto.master').add()
            auto_home = provider.automount.map('auto.home').add()
            auto_sub = provider.automount.map('auto.sub').add()

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

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost, svc: SystemdServices) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)
        self.svc: SystemdServices = svc
        self.__started: bool = False

    def reload(self) -> None:
        """
        Reload autofs maps.
        """
        self.svc.start("autofs")
        self.svc.reload("autofs")

    def mount(self, path: str, export: NFSExport) -> bool:
        """
        Try to mount the autofs directory by accessing it. Returns ``True``
        if the mount was successful, ``False`` otherwise.

        :param path: Path to the autofs mount point.
        :type path: str
        :param export: Expected NFS location that should be mounted on the mount point.
        :type export: NFSExport
        :return: ``True`` if the mount was successful, ``False`` otherwise.
        :rtype: bool
        """

        result = self.host.ssh.run(
            rf"""
        set -ex
        pushd "{path}"
        mount | grep "{export.hostname}:{export.fullpath} on {path}"
        popd
        umount "{path}"
        """,
            raise_on_error=False,
        )

        return result.rc == 0

    def dumpmaps(self) -> dict[str, dict[str, str | list[str]]]:
        """
        Calls ``automount -m``, parses its output into a dictionary and returns the dictionary.

        .. code-block:: python
            :caption: Dictionary format

            {
                '$mountpoint': {
                    'map': '$mapname',
                    'keys': ['$key1', '$key2']
                }
            }

        .. code-block:: python
            :caption: Example

            {
                '/ehome': {
                    'map': 'auto.home',
                    'keys': [
                        'export1 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export1',
                        'export2 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export2'
                    ]
                },
                '/esub/sub1/sub2': {
                    'map': 'auto.sub',
                    'keys': ['export3 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/sub/export3']
                },
            }

        .. note::

            Only mountpoints defined by SSSD are present in the output.

        :return: Parsed ``automount -m`` output.
        :rtype: dict[str, dict[str, list[str]]]
        """
        result = self.host.ssh.run("automount -m")

        def parse_result(lines: list[str]) -> dict[str, dict[str, str | list[str]]]:
            mountpoints: dict[str, dict[str, str | list[str]]] = {}
            for i, l in enumerate(lines):
                if l.startswith("Mount point: "):
                    point = l.replace("Mount point: ", "").strip()
                    for k, l2 in enumerate(lines[i + 1 :], i + 1):
                        if l2.startswith("Mount point: "):
                            break

                    data = lines[i + 1 : k]
                    if "instance type(s): sss" not in data:
                        continue

                    data.remove("source(s):")
                    data.remove("instance type(s): sss")

                    mapname = None
                    for k, item in enumerate(data):
                        if item.startswith("map: "):
                            mapname = item.replace("map: ", "").strip()
                            del data[k]

                    # Ignore if the map name is unreadable, this should not happen
                    if mapname is None:
                        continue

                    data = [x.strip() for x in data if x]
                    mountpoints[point] = {"map": mapname, "keys": data}

            return mountpoints

        return parse_result([x.strip() for x in result.stdout_lines])
