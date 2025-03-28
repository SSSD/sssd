from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_krishna():
    pass

@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__with_default_settings_alternative(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    user_credentials = {"username": "user1", "password": "Secret123", "wrong_password": "NOTSecret123"}
    provider.user(user_credentials["username"]).add(password=user_credentials["password"])
    
    if method == "ssh" and "ssh" not in client.sssd.sssd["services"]:
        client.sssd.sssd["services"] = "nss, pam, ssh"
    
    client.sssd.start(service_user=sssd_service_user)
    
    assert client.auth.parametrize(method).password(
        user_credentials["username"], user_credentials["password"]
    ), "User failed login!"
    
    assert not client.auth.parametrize(method).password(
        user_credentials["username"], user_credentials["wrong_password"]
    ), "User logged in with an invalid password!"