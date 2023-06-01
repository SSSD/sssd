"""
ldap_user_extra_attrs tests.

:requirement: ldap_extra_attrs
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.ticket(gh=4153, bz=1362023)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("attrs", ["mail, firstname:givenname, lastname:sn", "given_email:mail"])
def test_ldap_extra_attrs__filled(client: Client, provider: GenericProvider, attrs: str):
    """
    :title: SSSD starts correctly when ldap_user_extra_attrs is filled
    :setup:
        1. Create new user "tuser"
        2. Add "given_email:mail" to ldap_user_extra_attrs
    :steps:
        1. Start SSSD
        2. Run "getent passwd tuser"
    :expectedresults:
        1. SSSD starts successfully
        2. "tuser" is present in the passwd db
    :customerscenario: False
    """
    provider.user("tuser").add()
    client.sssd.domain["ldap_user_extra_attrs"] = attrs

    try:
        client.sssd.start()
    except Exception as e:
        pytest.fail(f"Exception shouldn't be raised but we got {type(e)}: str(e)")

    result = client.tools.getent.passwd("tuser")
    assert result is not None
    assert result.name == "tuser"
