"""
LDAPS support verification tests for sssd-test-framework.

Covers :meth:`~sssd_test_framework.utils.sssd.SSSDCommonConfiguration.ssl_tls`
which configures SSSD to connect to a provider over LDAPS (AD/Samba) or
STARTTLS (IPA). The CA certificate is pre-installed on the client by the
topology controller during setup.
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.Samba)
def test_ldaps__samba_user_lookup_over_ldaps(client: Client, samba: Samba):
    """
    :title: User lookup works when SSSD is configured to use LDAPS with Samba
    :setup:
        1. Create user 'tuser' in Samba
        2. Call ssl_tls(samba) to configure SSSD to connect over LDAPS
        3. Start SSSD
    :steps:
        1. Look up 'tuser' with getent passwd
        2. Check SSSD domain log for ldaps:// URI
    :expectedresults:
        1. User is returned correctly
        2. Log contains ldaps://dc.samba.test
    """
    samba.user("tuser").add(uid=10001, gid=10001)

    client.sssd.common.ssl_tls(samba)
    client.sssd.start()

    result = client.tools.getent.passwd("tuser@samba.test")
    assert result is not None, "User lookup failed over LDAPS"
    assert result.name == "tuser"

    log = client.fs.read(client.sssd.logs.domain())
    assert f"ldaps://{samba.host.hostname}" in log, f"Expected ldaps:// connection in SSSD log, got:\n{log[-2000:]}"


@pytest.mark.topology(KnownTopology.Samba)
def test_ldaps__samba_ca_cert_present_on_client(client: Client, samba: Samba):
    """
    :title: The CA certificate is pre-installed on the client by the topology controller
    :setup:
        1. Topology controller installs the Samba CA cert during provisioning
    :steps:
        1. Verify /etc/pki/ca-trust/source/anchors/test-ca.crt exists on the client
        2. Verify it contains a valid PEM certificate
    :expectedresults:
        1. File exists
        2. File contains BEGIN CERTIFICATE header
    """
    cert = client.fs.read("/etc/pki/ca-trust/source/anchors/test-ca.crt")
    assert "-----BEGIN CERTIFICATE-----" in cert, "CA cert not present or not valid PEM"


@pytest.mark.topology(KnownTopology.Samba)
def test_ldaps__samba_ssl_tls_sets_sssd_options(client: Client, samba: Samba):
    """
    :title: ssl_tls() sets the correct SSSD domain options for Samba
    :setup:
        1. Call ssl_tls(samba)
    :steps:
        1. Check ad_use_ldaps is set to True in the domain config
        2. Check ldap_tls_cacert is set to the expected path
    :expectedresults:
        1. ad_use_ldaps = True
        2. ldap_tls_cacert = /etc/pki/ca-trust/source/anchors/test-ca.crt
    """
    client.sssd.common.ssl_tls(samba)

    assert client.sssd.domain.get("ad_use_ldaps") == "True"
    assert client.sssd.domain.get("ldap_tls_cacert") == "/etc/pki/ca-trust/source/anchors/test-ca.crt"


@pytest.mark.topology(KnownTopology.IPA)
def test_ldaps__ipa_ssl_tls_sets_sssd_options(client: Client, ipa: IPA):
    """
    :title: ssl_tls() sets the correct SSSD domain options for IPA (STARTTLS)
    :setup:
        1. Call ssl_tls(ipa)
    :steps:
        1. Check ldap_id_use_start_tls is set to True
        2. Check ldap_tls_cacert is set to the expected path
    :expectedresults:
        1. ldap_id_use_start_tls = True
        2. ldap_tls_cacert = /etc/pki/ca-trust/source/anchors/test-ca.crt
    """
    client.sssd.common.ssl_tls(ipa)

    assert client.sssd.domain.get("ldap_id_use_start_tls") == "True"
    assert client.sssd.domain.get("ldap_tls_cacert") == "/etc/pki/ca-trust/source/anchors/test-ca.crt"


@pytest.mark.topology(KnownTopology.IPA)
def test_ldaps__ipa_user_lookup_over_starttls(client: Client, ipa: IPA):
    """
    :title: User lookup works when SSSD is configured to use STARTTLS with IPA
    :setup:
        1. Create user 'tuser' in IPA
        2. Call ssl_tls(ipa) to configure SSSD to connect with STARTTLS
        3. Start SSSD
    :steps:
        1. Look up 'tuser' with getent passwd
    :expectedresults:
        1. User is returned correctly
    """
    ipa.user("tuser").add()

    client.sssd.common.ssl_tls(ipa)
    client.sssd.start()

    result = client.tools.getent.passwd("tuser@ipa.test")
    assert result is not None, "User lookup failed with ssl_tls() for IPA (STARTTLS)"
    assert result.name == "tuser"
