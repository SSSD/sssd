"""
SSSD AD Provider Test Cases

:requirement: ad
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=7174)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_ad__using_the_users_email_address(client: Client, ad: AD, method: str, sssd_service_user: str):
    """
    :title: Login using the user's email address
    :description:
        Testing the feature to login using an email address instead of the userid. The username used,
        must match one of the user's LDAP attribute values, "EmailAddress". The login should be
        case-insensitive and permit special characters.
    :setup:
        1. Add AD users with different email addresses
        2. Start SSSD
    :steps:
        1. Authenticate users using their email address and in different cases
    :expectedresults:
        1. Authentication is successful using the email address and is case-insensitive
    :customerscenario: False
    """
    ad.user("user-1").add(password="Secret123", email=f"user-1@{ad.host.domain}")
    ad.user("user-2").add(password="Secret123", email="user-2@alias-domain.com")
    ad.user("user_3").add(password="Secret123", email="user_3@alias-domain.com")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(
        f"user-1@{ad.host.domain}", "Secret123"
    ), f"User user-1@{ad.host.domain} failed login!"
    assert client.auth.parametrize(method).password(
        "user-2@alias-domain.com", "Secret123"
    ), "User user-2@alias-domain.com failed login!"
    assert client.auth.parametrize(method).password(
        "uSEr_3@alias-dOMain.com", "Secret123"
    ), "User uSEr_3@alias-dOMain.com failed login!"


@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.importance("critical")
def test_ad__group_with_fsp_member(client: Client, provider: GenericADProvider):
    """
    :title: Lookup a group which has a foreign security principal (FSP) as member
    :description:
        Testing groups lookups for AD/Samba groups which have a foreign
        security principal as a member. Since SSSD currently cannot resolve the
        FSPs e.g. to determine if it is a user a a group they should be ignored
        by default without any extra setting in sssd.conf.
    :setup:
        1. Create a test user
        2. Create a test group
        3. Add test user and a FSP by SID to the test group
    :steps:
        1. Lookup test group
    :expectedresults:
        1. Lookup is successful and the test user is returned as a member of
           the test group
    :customerscenario: False
    """

    user = provider.user("testuser").add()
    group = provider.group("testgroup").add().add_member(user)

    # Samba automagically creates an FSP object if a random SID is added to a
    # group. I didn't find a similar way in AD to add a FSP entry to a group.
    # If someone finds a way, the test can be run against AD as well.
    provider.host.conn.run(f"samba-tool group addmembers {group.name} S-1-5-21-123-456-789-1234")

    client.sssd.start()

    result = client.tools.getent.group(group.name)
    assert result is not None, f"Failed to lookup group {group.name}!"
    assert user.name in result.members, f"User {user.name} is not a member of {group.name}!"
