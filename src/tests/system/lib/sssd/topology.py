"""SSSD predefined well-known topologies."""

from __future__ import annotations

from enum import unique
from typing import Any, Mapping, Tuple, final

import pytest
from pytest_mh import KnownTopologyBase, KnownTopologyGroupBase, Topology, TopologyDomain, TopologyMark

__all__ = [
    "KnownTopology",
    "KnownTopologyGroup",
]


class SSSDTopologyMark(TopologyMark):
    """
    Topology mark is used to describe test case requirements. It defines:

    * **name**, that is used to identify topology in pytest output
    * **topology** (:class:Topology) that is required to run the test
    * **fixtures** that are available during the test run
    * **domains** that will be automatically configured on the client

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(name, topology, domains, fixture1='path1', fixture2='path2', ...)
        def test_fixture_name(fixture1: BaseRole, fixture2: BaseRole, ...):
            assert True

    Fixture path points to a host in the multihost configuration and can be
    either in the form of ``$domain-type.$role`` (all host of given role) or
    ``$domain-type.$role[$index]`` (specific host on given index).

    The ``name`` is visible in verbose pytest output after the test name, for example:

    .. code-block:: console

        tests/test_basic.py::test_case (topology-name) PASSED
    """

    def __init__(
        self,
        name: str,
        topology: Topology,
        fixtures: dict[str, str] | None = None,
        domains: dict[str, str] | None = None,
    ) -> None:
        """
        :param name: Topology name used in pytest output.
        :type name: str
        :param topology: Topology required to run the test.
        :type topology: Topology
        :param fixtures: Dynamically created fixtures available during the test run.
        :type fixtures: dict[str, str] | None, optional
        :param domains: Automatically created SSSD domains on client host
        :type domains: dict[str, str] | None, optional
        """
        super().__init__(name, topology, fixtures)

        self.domains: dict[str, str] = domains if domains is not None else {}
        """Map hosts to SSSD domains."""

    def export(self) -> dict:
        """
        Export the topology mark into a dictionary object that can be easily
        converted to JSON, YAML or other formats.

        .. code-block:: python

            {
                'name': 'client',
                'fixtures': { 'client': 'sssd.client[0]' },
                'topology': [
                    {
                        'type': 'sssd',
                        'hosts': { 'client': 1 }
                    }
                ],
                'domains': { 'test': 'sssd.ldap[0]' },
            }

        :rtype: dict
        """
        d = super().export()
        d["domains"] = self.domains

        return d

    @classmethod
    def _CreateFromArgs(cls, item: pytest.Function, args: Tuple, kwargs: Mapping[str, Any]) -> TopologyMark:
        """
        Create :class:`TopologyMark` from pytest marker arguments.

        .. warning::

            This should only be called internally. You can inherit from
            :class:`TopologyMark` and override this in order to add additional
            attributes to the marker.

        :param item: Pytest item.
        :type item: pytest.Function
        :raises ValueError: If the marker is invalid.
        :return: Instance of TopologyMark.
        :rtype: TopologyMark
        """
        # First three parameters are positional, the rest are keyword arguments.
        if len(args) != 2 and len(args) != 3:
            nodeid = item.parent.nodeid if item.parent is not None else ""
            error = f"{nodeid}::{item.originalname}: invalid arguments for @pytest.mark.topology"
            raise ValueError(error)

        name = args[0]
        topology = args[1]
        domains = args[2] if len(args) == 3 else {}
        fixtures = {k: str(v) for k, v in kwargs.items()}

        return cls(name, topology, fixtures, domains)


@final
@unique
class KnownTopology(KnownTopologyBase):
    """
    Well-known topologies that can be given to ``pytest.mark.topology``
    directly. It is expected to use these values in favor of providing
    custom marker values.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_ldap(client: Client, ldap: LDAP):
            assert True
    """

    Client = SSSDTopologyMark(
        name="client",
        topology=Topology(TopologyDomain("sssd", client=1, kdc=1)),
        fixtures=dict(client="sssd.client[0]", kdc="sssd.kdc[0]"),
    )
    """
    .. topology-mark:: KnownTopology.Client
    """

    LDAP = SSSDTopologyMark(
        name="ldap",
        topology=Topology(TopologyDomain("sssd", client=1, ldap=1, nfs=1, kdc=1)),
        domains=dict(test="sssd.ldap[0]"),
        fixtures=dict(
            client="sssd.client[0]", ldap="sssd.ldap[0]", provider="sssd.ldap[0]", nfs="sssd.nfs[0]", kdc="sssd.kdc[0]"
        ),
    )
    """
    .. topology-mark:: KnownTopology.LDAP
    """

    IPA = SSSDTopologyMark(
        name="ipa",
        topology=Topology(TopologyDomain("sssd", client=1, ipa=1, nfs=1)),
        domains=dict(test="sssd.ipa[0]"),
        fixtures=dict(client="sssd.client[0]", ipa="sssd.ipa[0]", provider="sssd.ipa[0]", nfs="sssd.nfs[0]"),
    )
    """
    .. topology-mark:: KnownTopology.IPA
    """

    AD = SSSDTopologyMark(
        name="ad",
        topology=Topology(TopologyDomain("sssd", client=1, ad=1, nfs=1)),
        domains=dict(test="sssd.ad[0]"),
        fixtures=dict(client="sssd.client[0]", ad="sssd.ad[0]", provider="sssd.ad[0]", nfs="sssd.nfs[0]"),
    )
    """
    .. topology-mark:: KnownTopology.AD
    """

    Samba = SSSDTopologyMark(
        name="samba",
        topology=Topology(TopologyDomain("sssd", client=1, samba=1, nfs=1)),
        domains={"test": "sssd.samba[0]"},
        fixtures=dict(client="sssd.client[0]", samba="sssd.samba[0]", provider="sssd.samba[0]", nfs="sssd.nfs[0]"),
    )
    """
    .. topology-mark:: KnownTopology.Samba
    """


class KnownTopologyGroup(KnownTopologyGroupBase):
    """
    Groups of well-known topologies that can be given to ``pytest.mark.topology``
    directly. It is expected to use these values in favor of providing
    custom marker values.

    The test is parametrized and runs multiple times, once per each topology.

    .. code-block:: python
        :caption: Example usage (runs on AD, IPA, LDAP and Samba topology)

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_ldap(client: Client, provider: GenericProvider):
            assert True
    """

    AnyProvider = [KnownTopology.AD, KnownTopology.IPA, KnownTopology.LDAP, KnownTopology.Samba]
    """
    .. topology-mark:: KnownTopologyGroup.AnyProvider
    """

    AnyAD = [KnownTopology.AD, KnownTopology.Samba]
    """
    .. topology-mark:: KnownTopologyGroup.AnyAD
    """
