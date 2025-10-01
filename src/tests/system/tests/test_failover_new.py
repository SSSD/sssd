"""
This module contains tests for the new failover implementation utilizing
the minimal provider. These tests should not be merged to master.

:requirement: Failover
"""

from __future__ import annotations

import pytest
from pytest_mh import Topology, TopologyDomain
from sssd_test_framework.config import SSSDTopologyMark
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology_controllers import LDAPTopologyController

MINIMAL = SSSDTopologyMark(
    name="minimal",
    topology=Topology(TopologyDomain("sssd", client=1, ldap=1, nfs=1, kdc=1)),
    controller=LDAPTopologyController(),
    domains=dict(test="sssd.ldap[0]"),
    fixtures=dict(
        client="sssd.client[0]", ldap="sssd.ldap[0]", provider="sssd.ldap[0]", nfs="sssd.nfs[0]", kdc="sssd.kdc[0]"
    ),
)


@pytest.mark.topology(MINIMAL)
def test_failover_new__getent_services(client: Client, ldap: LDAP):
    """
    :title: Test new failover with minimal provider
    :setup:
        1. Add service
        2. Update sssd.conf
    :steps:
        1. Lookup service
    :expectedresults:
        1. Lookup is successful
    :customerscenario: False
    """
    ldap.services("my-service").add(protocol="tcp", port=9999)

    client.sssd.domain["id_provider"] = "minimal"
    client.sssd.start()

    svc = client.tools.getent.services("my-service", service="sss")
    assert svc is not None
    assert svc.name == "my-service"
    assert svc.port == 9999
    assert svc.protocol == "tcp"
