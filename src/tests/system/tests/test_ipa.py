"""
IPA SSH Public Host Keys Tests.

:requirement: IPA: hostpublickeys

sss_ssh_knownhosts acquires SSH public keys for host and outputs them in OpenSSH known_hosts key format.
Support for 'KnownHostsCommand' and deprecate 'sss_ssh_knownhostsproxy'
"""

from __future__ import annotations

import time

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
    hostname = f"ssh-host.{ipa.domain}"
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
        1. Lookup SSH key by running "sss_ssh_knownhosts ssh-host"
    :expectedresults:
        1. All public keys were printed
    :customerscenario: False
    """
    shortname = "ssh-host"
    hostname = f"{shortname}.{ipa.domain}"
    ip = "10.255.251.10"
    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)

    client.fs.append("/etc/resolv.conf", f"search {ipa.domain}")
    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.sss_ssh_knownhosts(shortname)
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        assert f"{shortname} {key}" in result.stdout_lines, "Did not get expected public keys!"


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
    hostname = f"ssh-host.{ipa.domain}"
    ip = "10.255.251.10"
    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)

    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.sss_ssh_knownhosts(ip)
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        assert f"{ip} {key}" in result.stdout_lines, "Did not get expected public keys!"


@pytest.mark.ticket(bz=1926622)
@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__check_gssapi_authentication_indicator(client: Client, ipa: IPA):
    """
    :title: Check logs for authentication indicator
    :description:
        Checks that logs for the authentication indicator showing that the kerberos ticket was obtained using GSSAPI
    :setup:
        1. Configure SSSD for sudo and gssapi
        2. Start SSSD
        3. Create sudo configuration that allows user to run SUDO rules
    :steps:
        1. Login as the test user and obtain ticket
        2. Try 'sudo -l' as user
        3. Check if acquired service ticket has req. indicators: 0 in sssd_pam.log
        4. Update config with 'pam_gssapi_service, pam_gssaspi_indicator_map and restart sssd
        5. Login as the test user and obtain a new ticket
        6. Check if acquired service ticket has req. indicators: 2 in sssd_pam.log
    :expectedresults:
        1. Login successful and ticket obtained
        2. "Sudo -l" should run without password
        3. "indicators: 0" should be there in the sssd_pam.log
        4. Configuration is updated and SSSD is restarted
        5. Login successful and new ticket obtained
        6. "indicators: 2" should be there in the sssd_pam.log
    :customerscenario: True
    """
    user = ipa.user("user-1").add(password="Secret123")
    password = "Secret123"

    # In future some other string replacement module may be created, for now generic sed module is used.
    for path in ["/etc/pam.d/sudo", "/etc/pam.d/sudo-i"]:
        client.fs.sed(path=path, command="2s/^/auth sufficient pam_sss_gss.so debug\\n/", args=["-i"])

    client.sssd.config["pam"] = {
        "pam_gssapi_services": "sudo, sudo-i",
        "pam_gssapi_indicators_map": "hardened, sudo:pkinit, sudo-i:otp",
    }
    client.sssd.start()

    with client.ssh(user.name, password) as ssh:
        ssh.run(f"kinit {user.name}@{ipa.host.realm}", input=password)
        ssh.run("klist")
        ssh.disconnect()
    ipa.sudorule("testrule").add(user=user.name, host="ALL", command="sudo -l")
    assert not client.auth.sudo.list(user.name), "User found in sudo rule!"
    time.sleep(3)
    log1 = client.fs.read(client.sssd.logs.pam)
    assert "indicators: 0" in log1, "String `indicators: 0` not found in logs!"

    client.sssd.config["pam"] = {"pam_gssapi_services": "sudo, sudo-i", "pam_gssapi_indicators_map": "sudo-i:hardened"}
    client.sssd.clear(logs=True)
    client.sssd.restart()

    with client.ssh(user.name, password) as ssh:
        ssh.run(f"kinit {user.name}@{ipa.host.realm}", input=password)
        ssh.run("klist")
        ssh.disconnect()
    assert not client.auth.sudo.list(user.name), "User found in sudo rule!"
    time.sleep(3)
    log2 = client.fs.read(client.sssd.logs.pam)
    assert "indicators: 2" in log2, "String `indicators: 2` not found in logs!"
