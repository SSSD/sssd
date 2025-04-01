"""
SSSD oidc_child Test Cases

:requirement: oidc_child
"""

from __future__ import annotations

import json
import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.keycloak import Keycloak, KeycloakObject
from sssd_test_framework.topology import KnownTopologyGroup
from sssd_test_framework.topology_controllers import ProvisionedBackupTopologyController
from pytest_mh import Topology, TopologyDomain

oidc_child_path = "/usr/bin/valgrind --leak-check=full /usr/libexec/sssd/oidc_child"
args = "--libcurl-debug -d 9 --logger=stderr --idp-type=keycloak:https://master.keycloak.test:8443/auth/admin/realms/master/ --token-endpoint=https://master.keycloak.test:8443/auth/realms/master/protocol/openid-connect/token --client-id=myclient --client-secret=ClientSecret123 --scope='profile'"

class KeycloakIdPClient(KeycloakObject):
    """
    Keycloak IdP client management.
    """

    def __init__(self, role: Keycloak, name: str) -> None:
        """
        :param role: Keycloak role object.
        :type role: Keycloak
        :param name: IdP client name.
        :type name: str
        """
        super().__init__(role, name)

    def add(
        self,
        *,
        password: str | None = "Secret123",
    ) -> KeycloakIdPClient:
        """
        Create new Keycloak IdP client.

        Parameters that are not set are ignored.

        :param password: Password, defaults to 'Secret123'
        :type password: str | None, optional
        :return: Self.
        :rtype: KeycloakIdPClient
        """
        create_idp_client = (
            'create clients -r master -b \'{"'
            f'clientId": "{self.name}", '
            f'"clientAuthenticatorType": "client-secret", "secret": "{password}", '
            '"serviceAccountsEnabled": true, "attributes": {"oauth2.device.authorization.grant.enabled": "true"}}\' '
        )
        result = self.role.kcadm(create_idp_client)

        self.id = result.stderr.split()[-1].strip("'")

        self.role.kcadm('add-roles -r master --cclientid account --rolename view-groups --uusername service-account-myclient')
        self.role.kcadm('add-roles -r master --cclientid master-realm --rolename view-users --uusername service-account-myclient')
        self.role.kcadm('add-roles -r master --cclientid master-realm --rolename query-users --uusername service-account-myclient')
        self.role.kcadm('add-roles -r master --cclientid master-realm --rolename query-groups --uusername service-account-myclient')

        return self

    def delete(self) -> None:
        """
        Delete Keycloak IdP client.
        """
        del_idp_client = f"delete clients/{self.id}"
        self.role.kcadm(del_idp_client)


@pytest.mark.topology('keycloak', Topology(TopologyDomain('sssd', client=1, keycloak=1)),
                                  controller=ProvisionedBackupTopologyController(),
                                  fixtures=dict(client='sssd.client[0]', keycloak='sssd.keycloak[0]'))
def test_oidc_child__get_user(
    client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create IdP client
        2. Create user
    :steps:
        1. Lookup user with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixUsername and posixObjectType are correct
    """

    idp_client = KeycloakIdPClient(keycloak, "myclient").add(password="ClientSecret123")
    user = keycloak.user("user1").add(password="Secret123")

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-user --name=user1")
    data = json.loads(out.stdout)
    assert data[0]['posixUsername'] == 'user1'
    assert data[0]['posixObjectType'] == 'user'


@pytest.mark.topology('keycloaka', Topology(TopologyDomain('sssd', client=1, keycloak=1)),
                                  controller=ProvisionedBackupTopologyController(),
                                  fixtures=dict(client='sssd.client[0]', keycloak='sssd.keycloak[0]'))
def test_oidc_child__get_group(
    client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create IdP client
        2. Create group
    :steps:
        1. Lookup group with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixGroupname and posixObjectType are correct
    """

    idp_client = KeycloakIdPClient(keycloak, "myclient").add(password="ClientSecret123")
    group = keycloak.group("group1").add()

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-group --name=group1")
    data = json.loads(out.stdout)
    assert data[0]['posixGroupname'] == 'group1'
    assert data[0]['posixObjectType'] == 'group'

@pytest.mark.topology('keycloakb', Topology(TopologyDomain('sssd', client=1, keycloak=1)),
                                  controller=ProvisionedBackupTopologyController(),
                                  fixtures=dict(client='sssd.client[0]', keycloak='sssd.keycloak[0]'))
def test_oidc_child__get_user_groups(
    client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create IdP client
        2. Create user
        3. Create group with user as member
    :steps:
        1. Lookup groups of user with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixGroupname and posixObjectType are correct
    """

    idp_client = KeycloakIdPClient(keycloak, "myclient").add(password="ClientSecret123")
    user = keycloak.user("user1").add(password="Secret123")
    group = keycloak.group("group1").add().add_member(user)

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-user-groups --name=user1")
    data = json.loads(out.stdout)
    assert data[0]['posixGroupname'] == 'group1'
    assert data[0]['posixObjectType'] == 'group'


@pytest.mark.topology('keycloakc', Topology(TopologyDomain('sssd', client=1, keycloak=1)),
                                  controller=ProvisionedBackupTopologyController(),
                                  fixtures=dict(client='sssd.client[0]', keycloak='sssd.keycloak[0]'))
def test_oidc_child__get_group_members(
    client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create IdP client
        2. Create user
        3. Create group with user as member
    :steps:
        1. Lookup group members with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixUsername and posixObjectType are correct
    """

    idp_client = KeycloakIdPClient(keycloak, "myclient").add(password="ClientSecret123")
    user = keycloak.user("user1").add(password="Secret123")
    group = keycloak.group("group1").add().add_member(user)

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-group-members --name=group1")
    data = json.loads(out.stdout)
    assert data[0]['posixUsername'] == 'user1'
    assert data[0]['posixObjectType'] == 'user'
