"""
SSSD oidc_child Test Cases

:requirement: oidc_child
"""

from __future__ import annotations

import json

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology

oidc_child_path = "/usr/libexec/sssd/oidc_child"
args = (
    "--libcurl-debug -d 9 --logger=stderr "
    "--idp-type=keycloak:https://master.keycloak.test:8443/auth/admin/realms/master/ "
    "--token-endpoint=https://master.keycloak.test:8443/auth/realms/master/protocol/openid-connect/token "
    "--client-id=myclient --client-secret=ClientSecret123 --scope='profile'"
)

args_get_device_code = (
    "--libcurl-debug -d 9 --logger=stderr "
    "--get-device-code --issuer-url=https://master.keycloak.test:8443/auth/realms/master"
)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_user(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
    :steps:
        1. Lookup user with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixUsername and posixObjectType are correct
    :customerscenario: False
    """

    keycloak.user("user1").add(password="Secret123")

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-user --name=user1")
    data = json.loads(out.stdout)
    assert data[0]["posixUsername"] == "user1"
    assert data[0]["posixObjectType"] == "user"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_group(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create group
    :steps:
        1. Lookup group with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixGroupname and posixObjectType are correct
    :customerscenario: False
    """

    keycloak.group("group1").add()

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-group --name=group1")
    data = json.loads(out.stdout)
    assert data[0]["posixGroupname"] == "group1"
    assert data[0]["posixObjectType"] == "group"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_user_groups(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
    :steps:
        1. Lookup groups of user with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixGroupname and posixObjectType are correct
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-user-groups --name=user1")
    data = json.loads(out.stdout)
    assert data[0]["posixGroupname"] == "group1"
    assert data[0]["posixObjectType"] == "group"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_group_members(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
    :steps:
        1. Lookup group members with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixUsername and posixObjectType are correct
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-group-members --name=group1")
    data = json.loads(out.stdout)
    assert data[0]["posixUsername"] == "user1"
    assert data[0]["posixObjectType"] == "user"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_device_code(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. no specific setup needed
    :steps:
        1. Request device code with oidc_child
    :expectedresults:
        1. oidc_child is successful and device code and other data is returned
    :customerscenario: False
    """

    out = client.host.conn.run(
        oidc_child_path + " " + args_get_device_code + " " + "--client-id=myclient --client-secret=ClientSecret123"
    )
    data = json.loads(out.stdout_lines[0])
    assert "device_code" in data, "Missing device_code!"
    assert "expires_in" in data, "Missing expires_in!"
    assert "interval" in data, "Missing interval!"

    assert out.stdout_lines[1][:8] == "oauth2 {", "Second line does not start with 'oauth2 {'!"
    data = json.loads(out.stdout_lines[1][7:])
    assert "verification_uri" in data, "Missing verification_uri!"
    assert "user_code" in data, "Missing user_code"


@pytest.mark.parametrize("key_type", ["RSA", "EC"])
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_device_code_jwt(client: Client, keycloak: Keycloak, key_type: str):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create certificate, key and PKCS#12 file
        2. Create JWT client in Keycloak with certificate
    :steps:
        1. Request device code with oidc_child with JWT client authentication
    :expectedresults:
        1. oidc_child is successful and device code and other data is returned
    :customerscenario: False
    """

    p12_pwd = "Secret123"
    p12_path = "/tmp/my.p12"

    key, cert = client.smartcard.generate_cert(key_type=key_type)

    client.host.conn.run(f"openssl pkcs12 -export -password pass:{p12_pwd} -inkey {key} -in {cert}  -out {p12_path}")
    out = client.host.conn.run(f"openssl x509 -in {cert} -outform der | openssl base64 -A")
    cert_b64 = out.stdout

    # Create an IdP JWT client
    keycloak.host.kclogin()
    keycloak.host.conn.run(
        "/opt/keycloak/bin/kcadm.sh create clients -r master "
        '-b \'{"clientId": "my_jwt_client", "clientAuthenticatorType": "client-jwt", '
        '"serviceAccountsEnabled": true, '
        '"attributes": {"oauth2.device.authorization.grant.enabled": "true", '
        f'"jwt.credential.certificate": "{cert_b64}"}}}}\' '
    )

    out = client.host.conn.run(
        oidc_child_path
        + " "
        + args_get_device_code
        + " "
        + f"--client-id=my_jwt_client --client-secret={p12_pwd} --pkcs12-client-creds={p12_path} "
        + "--client-auth-method=jwt"
    )
    data = json.loads(out.stdout_lines[0])
    assert "device_code" in data, "Missing device_code!"
    assert "expires_in" in data, "Missing expires_in!"
    assert "interval" in data, "Missing interval!"

    assert out.stdout_lines[1][:8] == "oauth2 {", "Second line does not start with 'oauth2 {'!"
    data = json.loads(out.stdout_lines[1][7:])
    assert "verification_uri" in data, "Missing verification_uri!"
    assert "user_code" in data, "Missing user_code"


@pytest.mark.parametrize("key_type", ["RSA", "EC"])
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_device_code_mtls(client: Client, keycloak: Keycloak, key_type: str):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create certificate, key and PKCS#12 file
        2. Let keycloak trust the client certificate
        3. Enable HTTPS client authentication in Keycloak
        4. Create MTLS client in Keycloak with the subject DN of the certificate
    :steps:
        1. Request device code with oidc_child with MTLS client authentication
    :expectedresults:
        1. oidc_child is successful and device code and other data is returned
    :customerscenario: False
    """

    p12_pwd = "Secret123"
    p12_path = "/tmp/my.p12"

    key, cert = client.smartcard.generate_cert(key_type=key_type)

    client.host.conn.run(f"openssl pkcs12 -export -password pass:{p12_pwd} -inkey {key} -in {cert}  -out {p12_path}")
    out = client.host.conn.run(f"openssl x509 -in {cert} -noout -subject")
    assert out.stdout[:8] == "subject=", "Unexpected output!"
    subject_dn = out.stdout[8:]
    cert_content = client.host.fs.read(cert)

    # Add client certificate to Keycloak's kestore
    keycloak.fs.write(cert, cert_content)
    keycloak.host.conn.run(
        "keytool -storepass Secret123 -keystore /var/data/certs/master.keycloak.test.keystore -noprompt "
        + f"-importcert -file {cert} -alias mtls"
    )
    keycloak.svc.restart("keycloak.service")

    # Create an IdP MTLS client
    keycloak.host.kclogin()
    keycloak.host.conn.run(
        "/opt/keycloak/bin/kcadm.sh create clients -r master "
        '-b \'{"clientId": "my_mtls_client", "clientAuthenticatorType": "client-x509", '
        '"serviceAccountsEnabled": true, '
        '"attributes": {"oauth2.device.authorization.grant.enabled": "true", '
        f'"x509.subjectdn": "{subject_dn}"}}}}\' '
    )

    out = client.host.conn.run(
        oidc_child_path
        + " "
        + args_get_device_code
        + " "
        + f"--client-id=my_mtls_client --client-secret={p12_pwd} --pkcs12-client-creds={p12_path} "
        + "--client-auth-method=mtls"
    )
    # Currently the keystore is not restored by the framework
    keycloak.host.conn.run(
        "keytool -storepass Secret123 -keystore /var/data/certs/master.keycloak.test.keystore -delete -alias mtls"
    )
    data = json.loads(out.stdout_lines[0])
    assert "device_code" in data, "Missing device_code!"
    assert "expires_in" in data, "Missing expires_in!"
    assert "interval" in data, "Missing interval!"

    assert out.stdout_lines[1][:8] == "oauth2 {", "Second line does not start with 'oauth2 {'!"
    data = json.loads(out.stdout_lines[1][7:])
    assert "verification_uri" in data, "Missing verification_uri!"
    assert "user_code" in data, "Missing user_code"
