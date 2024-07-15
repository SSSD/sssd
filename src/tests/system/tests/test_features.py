"""
SSSD Feature presence suite

:requirement: features
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__sss_ssh_knownhosts(client: Client):
    """
    :title: Feature sss_ssh_knownhosts presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check sss_ssh_knownhosts feature presence
    :expectedresults:
        1. The feature is present in sssd 2.10 and higher
    :customerscenario: False
    :requirement: Support 'KnownHostsCommand' and deprecate 'sss_ssh_knownhostsproxy'
    """
    v = client.host.get_package_version(package="sssd", raise_on_error=False)
    if (v["major"] == 2 and v["minor"] >= 10) or v["major"] > 2:
        assert client.features["knownhosts"]
    else:
        assert not client.features["knownhosts"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__files_provider(client: Client):
    """
    :title: Feature files-provider presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check files-provider feature presence
    :expectedresults:
        1. The feature should not be present in sssd 2.10 and higher
    :customerscenario: False
    """
    v = client.host.get_package_version(package="sssd", raise_on_error=False)
    if (v["major"] == 2 and v["minor"] >= 10) or v["major"] > 2:
        assert not client.features["files-provider"]
    else:
        assert client.features["files-provider"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__passkey(client: Client):
    """
    :title: Feature passkey presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check passkey feature presence
    :expectedresults:
        1. The feature should be on RHEL 9.4+, CentOS 9+, Fedora 39+ and Ubuntu 23.10+
    :customerscenario: False
    :requirement: passkey
    """
    expect_passkey = False
    if "Fedora" in client.host.distro_name:
        expect_passkey = client.host.distro_major >= 39
    elif "Red Hat Enterprise Linux" in client.host.distro_name:
        expect_passkey = bool(
            (client.host.distro_major == 9 and client.host.distro_minor >= 4) or client.host.distro_major > 9
        )
    elif "CentOS Stream" in client.host.distro_name:
        expect_passkey = client.host.distro_major >= 9
    elif "Ubuntu" in client.host.distro_name:
        expect_passkey = not (
            client.host.distro_major <= 23 or (client.host.distro_major == 23 and client.host.distro_minor < 10)
        )
    else:
        pytest.skip("Unknown distro, no expectations set for passkey feature presence")

    assert bool(client.features["passkey"] == expect_passkey), (
        f"Passkey does not match expectations on"
        f" {client.host.distro_name} {client.host.distro_major} {client.host.distro_minor}."
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__ldap_use_ppolicy(client: Client):
    """
    :title: Feature ldap_use_ppolicy presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check ldap_use_ppolicy feature presence
    :expectedresults:
        1. The feature should be present in sssd 2.10 and higher
    :customerscenario: False
    """
    v = client.host.get_package_version(package="sssd", raise_on_error=False)
    if (v["major"] == 2 and v["minor"] >= 10) or v["major"] > 2:
        assert client.features["ldap_use_ppolicy"]
    else:
        assert not client.features["ldap_use_ppolicy"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__non_privileged(client: Client):
    """
    :title: Feature non-privileged presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check non-privileged feature presence
    :expectedresults:
        1. The feature should be present in sssd 2.10 and higher
    :customerscenario: False
    """
    v = client.host.get_package_version(package="sssd", raise_on_error=False)
    if (v["major"] == 2 and v["minor"] >= 10) or v["major"] > 2:
        assert client.features["non-privileged"]
    else:
        assert not client.features["non-privileged"]
