"""
SSSD Feature Presence Tests

:requirement: features
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.parametrize(
    "distribution, distro_major, distro_minor, sssd_major, sssd_minor, feature, presence",
    [
        ("Fedora", 39, 0, 2, 9, "passkey", True),
        ("CentOS Stream", 9, 0, 2, 9, "passkey", True),
        ("Red Hat Enterprise Linux", 9, 4, 2, 9, "passkey", True),
        ("Ubuntu", 23, 10, 2, 9, "passkey", True),
        (None, None, None, 2, 10, "knownhosts", True),
        (None, None, None, 2, 10, "ldap_use_ppolicy", True),
        ("Fedora", 41, 0, 2, 10, "non-privileged", True),
        ("CentOS Stream", 9, 0, 2, 10, "non-privileged", True),
        ("Red Hat Enterprise Linux", 10, 0, 2, 10, "non-privileged", True),
    ],
)
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__presence(
    client: Client,
    distribution: str | None,
    distro_major: int | None,
    distro_minor: int | None,
    sssd_major: int,
    sssd_minor: int,
    feature: str,
    presence: bool,
):
    """
    :title: Feature presence
    :description:
        The parametrization states the distribution name, distribution version, SSSD version and feature
        presence.
        As an example, ("Fedora", 39, 0, 2, 9, "passkey", True) should be read in the following way:
        In a Fedora 39 or higher system with SSSD 2.9 or higher, passkey feature shall be present.
        Another example, (None, None, None, 2, 10, "knownhosts", True):
        In a system with SSSD 2.10 or higher, knownhosts feature shall be present.
    :setup:
        1. Skip if distribution name doesn't match
        2. Skip if distribution version doesn't match
    :steps:
        1. Check SSSD version and feature presence
    :expectedresults:
        1. Depending on the parameterization, the feature shall be present or not
    :customerscenario: False
    """
    if distribution is not None and distribution not in client.host.distro_name:
        pytest.skip(f"Distribution doesn't match:  {distribution} != {client.host.distro_name}")
    if (distro_major is not None and client.host.distro_major < distro_major) or (
        distro_major is not None
        and distro_minor is not None
        and client.host.distro_major == distro_major
        and client.host.distro_minor < distro_minor
    ):
        pytest.skip(
            f"Lower distribution version: {client.host.distro_major}.{client.host.distro_minor} < "
            "{distro_major}.{distro_minor}"
        )

    sssd_version = client.host.get_package_version(package="sssd", raise_on_error=False)
    if sssd_version["major"] > sssd_major or (
        sssd_version["major"] == sssd_major and sssd_version["minor"] >= sssd_minor
    ):
        state = "" if presence else "not"
        expected = presence
    else:
        state = "not" if presence else ""
        expected = not presence

    assert client.features[feature] == expected, (
        f"Feature {feature} should {state} be present in {client.host.distro_name} "
        f"{client.host.distro_major}.{client.host.distro_minor} with "
        f"sssd-{sssd_version['major']}.{sssd_version['minor']}"
    )
