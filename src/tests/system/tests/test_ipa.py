"""
IPA SSH Public Host Keys Tests.

:requirement: IPA: hostpublickeys

sss_ssh_knownhosts acquires SSH public keys for host and outputs them in OpenSSH known_hosts key format.
Support for 'KnownHostsCommand' and deprecate 'sss_ssh_knownhostsproxy'
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
def test_ipa__hostpublickeys_by_name(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by name
    :setup:
        1. Create host with SSH key
        2. Configure SSSD with SSH responder
        3. Start SSSD
    :steps:
        1. Lookup SSH key
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
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        assert f"{hostname} {key}" in result.stdout_lines, "Did not get expected public keys!"


@pytest.mark.ticket(gh=5518)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hostpublickeys_by_shortname(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by short name using the search domain
    :setup:
        1. Create host with SSH key and add "search ipa.test" to /etc/resolv.conf
        2. Configure SSSD with SSH responder
        3. Start SSSD
    :steps:
        1. Lookup SSH key by running "sss_ssh_knownhosts ssh"
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
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        assert f"ssh {key}" in result.stdout_lines, "Did not get expected public keys!"


@pytest.mark.ticket(gh=5518)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hostpublickeys_by_ip(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by IP
    :setup:
        1. Create host with SSH key
        2. Configure SSSD with SSH responder
        3. Start SSSD
    :steps:
        1. Lookup SSH key by running "sss_ssh_knownhosts $ip"
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
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        assert f"{ip} {key}" in result.stdout_lines, "Did not get expected public keys!"
