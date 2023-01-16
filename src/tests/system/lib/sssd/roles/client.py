"""Client multihost role."""

from __future__ import annotations

from ..hosts.base import BaseHost
from ..topology import SSSDTopologyMark
from ..utils.automount import AutomountUtils
from ..utils.local_users import LocalUsersUtils
from ..utils.sssd import SSSDUtils
from .base import BaseLinuxRole

__all__ = [
    "Client",
]


class Client(BaseLinuxRole[BaseHost]):
    """
    SSSD Client role.

    Provides unified Python API for managing and testing SSSD.

    .. code-block:: python
        :caption: Starting SSSD

        @pytest.mark.topology(KnownTopology.Client)
        def test_example(client: Client):
            client.sssd.start()

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.sssd: SSSDUtils = SSSDUtils(self.host, self.fs, self.svc, self.authselect, load_config=False)
        """
        Managing and configuring SSSD.
        """

        self.automount: AutomountUtils = AutomountUtils(self.host, self.svc)
        """
        Methods for testing automount.
        """

        self.local: LocalUsersUtils = LocalUsersUtils(self.host)
        """
        Managing local users and groups.
        """

    def setup(self) -> None:
        """
        Called before execution of each test.

        Setup client host:

        #. stop sssd
        #. clear sssd cache, logs and configuration
        #. import implicit domains from topology marker
        """
        super().setup()
        self.sssd.stop()
        self.sssd.clear(db=True, memcache=True, logs=True, config=True)

        if self.mh.data.topology_mark is not None:
            if not isinstance(self.mh.data.topology_mark, SSSDTopologyMark):
                raise ValueError("Multihost data does not have SSSDTopologyMark")

            for domain, path in self.mh.data.topology_mark.domains.items():
                role = self.mh._lookup(path)
                if isinstance(role, list):
                    raise ValueError("List is not expected")

                self.sssd.import_domain(domain, role)
