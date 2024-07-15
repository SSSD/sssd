"""
sss_ssh_knownhosts tests.

:requirement: Support 'KnownHostsCommand' and deprecate 'sss_ssh_knownhostsproxy'
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.fixture(scope="module")
def public_keys(moduledatadir: str) -> list[str]:
    """
    Read list of public keys from module data file.

    :return: List of public keys.
    :rtype: list[str]
    """
    keys: list[str] = []
    with open(f"{moduledatadir}/public_keys") as f:
        for line in f.readlines():
            stripped = line.strip()
            if stripped:
                keys.append(stripped)

    return keys


@pytest.mark.ticket(gh=5518)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_sss_ssh_knownhosts__by_name(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by name
    :setup:
        1. Create IPA host "ssh.ipa.test", public keys and IP resolvable via DNS
        2. Enable ssh responder
        3. Start SSSD
    :steps:
        1. Run "sss_ssh_knownhosts ssh.ipa.test"
    :expectedresults:
        1. All public keys were printed
    :customerscenario: False
    """
    hostname = f"ssh.{ipa.domain}"
    ip = "10.255.251.10"
    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)

    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.sss_ssh_knownhosts(hostname)
    assert result.rc == 0
    assert len(public_keys) == len(result.stdout_lines)
    for key in public_keys:
        assert f"{hostname} {key}" in result.stdout_lines


@pytest.mark.ticket(gh=5518)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_sss_ssh_knownhosts__by_shortname(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by short name using the search domain
    :setup:
        1. Create IPA host "ssh.ipa.test", public keys and IP resolvable via DNS
        2. Add "search ipa.test" to /etc/resolv.conf
        3. Enable ssh responder
        4. Start SSSD
    :steps:
        1. Run "sss_ssh_knownhosts ssh"
    :expectedresults:
        1. All public keys were printed
    :customerscenario: False
    """
    hostname = f"ssh.{ipa.domain}"
    ip = "10.255.251.10"
    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)

    client.fs.append("/etc/resolv.conf", f"search {ipa.domain}")
    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.sss_ssh_knownhosts("ssh")
    assert result.rc == 0
    assert len(public_keys) == len(result.stdout_lines)
    for key in public_keys:
        assert f"ssh {key}" in result.stdout_lines


@pytest.mark.ticket(gh=5518)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_sss_ssh_knownhosts__by_ip(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by IP
    :setup:
        1. Create IPA host "ssh.ipa.test", public keys and IP resolvable via DNS
        2. Enable ssh responder
        3. Start SSSD
    :steps:
        1. Run "sss_ssh_knownhosts $ip"
    :expectedresults:
        1. All public keys were printed
    :customerscenario: False
    """
    hostname = f"ssh.{ipa.domain}"
    ip = "10.255.251.10"
    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)

    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.sss_ssh_knownhosts(ip)
    assert result.rc == 0
    assert len(public_keys) == len(result.stdout_lines)
    for key in public_keys:
        assert f"{ip} {key}" in result.stdout_lines
