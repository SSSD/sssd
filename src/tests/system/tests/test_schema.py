"""
SSSD Schema Tests.

Tests related to directory schemas, formal definitions of LDAP objectClasses and attributes.

These tests are generic topology and will run against AD, Samba, IPA and LDAP.
Specific topologies test may reside in their corresponding test file.

:requirement: ldap_extra_attrs
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("high")
@pytest.mark.ticket(gh=4153, bz=1362023)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize("attrs", ["mail, firstname:givenname, lastname:sn", "given_email:mail"])
def test_schema__user_extra_attributes_are_populated(client: Client, provider: GenericProvider, attrs: str):
    """
    :title: SSSD starts correctly when ldap_extra_attrs is configured
    :setup:
        1. Create user "user1"
        2. Configure SSSD with "ldap_user_extra_attrs = attribute:value"
    :steps:
        1. Start SSSD
        2. Lookup user
    :expectedresults:
        1. SSSD starts with no errors
        2. User found and name matches
    :customerscenario: False
    """
    provider.user("user1").add()
    client.sssd.domain["ldap_user_extra_attrs"] = attrs

    try:
        client.sssd.start()
    except Exception as e:
        pytest.fail(f"Exception shouldn't be raised but we got {type(e)}: str(e)")

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User not found!"
    assert result.name == "user1", f"User 'user1' name is not the expected value `{result.name}`!"
