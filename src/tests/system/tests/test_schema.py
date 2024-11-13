"""
schema tests.

:requirement: ldap_extra_attrs
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("high")
@pytest.mark.schema
@pytest.mark.ticket(gh=4153, bz=1362023)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("attrs", ["mail, firstname:givenname, lastname:sn", "given_email:mail"])
def test_schema__ldap_extra_attrs_filled(client: Client, provider: GenericProvider, attrs: str):
    """
    :title: SSSD starts correctly when ldap_user_extra_attrs is filled
    :setup:
        1. Create new user "tuser"
        2. Add "given_email:mail" to ldap_user_extra_attrs
    :steps:
        1. Start SSSD
        2. Run "getent passwd tuser"
    :expectedresults:
        1. SSSD starts successfully
        2. "tuser" is present in the passwd db
    :customerscenario: False
    """
    provider.user("tuser").add()
    client.sssd.domain["ldap_user_extra_attrs"] = attrs

    try:
        client.sssd.start()
    except Exception as e:
        pytest.fail(f"Exception shouldn't be raised but we got {type(e)}: str(e)")

    result = client.tools.getent.passwd("tuser")
    assert result is not None
    assert result.name == "tuser"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_schema__ldap_extra_attrs_check_ldb(client: Client, provider: GenericProvider):
    """
    :title: Recently added extra attributes should be in cache db along with their value
    :setup:
        1. Create new user "user1"
        2. Add "description:gecos, userID:uidNumber, shell:loginShell, groupID:gidNumber" to ldap_user_extra_attrs
        3. Add "ldap_id_mapping" to domain config, to ensure correct ids on all topologies
        4. Start SSSD
    :steps:
        1. Run "getent passwd user1" to store user attributes to cache
        2. Run ldbsearch command
    :expectedresults:
        1. User is found
        2. Result has correct values
    :customerscenario: True
    """
    provider.user("user1").add(gid=111111, uid=100110, gecos="gecos user1", shell="/bin/sh", home="/home/user1")
    client.sssd.domain["ldap_user_extra_attrs"] = (
        "description:gecos, userID:uidNumber, shell:loginShell, groupID:gidNumber"
    )
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "getent passwd user1 failed"

    search = client.ldb.search(
        f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", f"cn=users,cn={client.sssd.default_domain},cn=sysdb"
    )

    user_dict = search["name=user1@test,cn=users,cn=test,cn=sysdb"]
    assert user_dict["description"] == ["gecos user1"], "attribute 'description' was not correct"
    assert user_dict["shell"] == ["/bin/sh"], "attribute 'shell' was not correct"
    assert user_dict["userID"] == ["100110"], "attribute 'userID' was not correct"
    assert user_dict["groupID"] == ["111111"], "attribute 'groupID' was not correct"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_schema__ldap_extra_attrs_negative_cache(client: Client, provider: GenericProvider):
    """
    :title: When extra attribute of user is added but not assigned, it is neither cached nor displayed
    :setup:
        1. Create new user "user1"
        2. Add "number:telephonenumber" to ldap_user_extra_attrs
        3. Start SSSD
    :steps:
        1. Run "getent passwd user1" to store user to cache
        2. Run ldbsearch command
    :expectedresults:
        1. User is found
        2. "number" is not in the output
    :customerscenario: False
    """
    provider.user("user1").add()

    client.sssd.domain["ldap_user_extra_attrs"] = "number:telephonenumber"

    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User is not found"
    assert result.name == "user1", "User has wrong name"

    search = client.ldb.search(
        f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", f"cn=users,cn={client.sssd.default_domain},cn=sysdb"
    )

    user_dict = search["name=user1@test,cn=users,cn=test,cn=sysdb"]
    with pytest.raises(KeyError):
        user_dict["number"]


@pytest.mark.topology(KnownTopology.LDAP)
def test_schema__ldap_extra_attrs_extra_email(client: Client, ldap: LDAP):
    """
    :title: SSSD starts with ldap_user_email and ldap_user_extra_attrs and checks cached attributes
    :setup:
        1. Create new user "user1", set them mail and gecos
        2. Edit config - ldap_user_extra_attrs = "email:mail, description:gecos" and ldap_user_email = "mail"
        3. Start SSSD
    :steps:
        1. Run "getent passwd user1" to store user to cache
        2. Run ldbsearch command to get cached info
    :expectedresults:
        1. User is found
        2. "mail" and "email" are in the output with correct value
    :customerscenario: False
    """
    ldap.user("user1").add(gecos="gecos1", mail="user1@example.test")

    client.sssd.domain["ldap_user_email"] = "mail"
    client.sssd.domain["ldap_user_extra_attrs"] = "email:mail, description:gecos"
    client.sssd.sssd["services"] = "nss, pam, ifp"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User is not found"
    assert result.name == "user1", "User has wrong name"

    search = client.ldb.search(
        f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", f"cn=users,cn={client.sssd.default_domain},cn=sysdb"
    )

    user_dict = search["name=user1@test,cn=users,cn=test,cn=sysdb"]
    assert user_dict["description"] == ["gecos1"], "attribute 'descripion' was not correct"
    assert user_dict["mail"] == ["user1@example.test"], "attribute 'mail' was not correct"
    assert user_dict["email"] == ["user1@example.test"], "attribute 'email' was not correct"


@pytest.mark.ticket(bz=1667252)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_schema__ldap_extra_attrs_ifp(client: Client, provider: GenericProvider):
    """
    :title: ifp do not crash when requesting extra attributes
    :setup:
        1. Create new user "user1"
        2. Configure 'test' ldap user extra attribute
        3. Start SSSD
    :steps:
        1. Run "sssctl user-checks user1"
        2. Check SSSD status
    :expectedresults:
        1. Command succeeded
        2. Checked successfully
    :customerscenario: True
    """
    provider.user("user1").add()
    client.sssd.sssd["services"] = "nss, pam, ifp"
    client.sssd.domain["ldap_user_extra_attrs"] = "test:homeDirectory"
    client.sssd.ifp["user_attributes"] = "+test"
    client.sssd.start()

    result = client.sssctl.user_checks("user1")
    assert result.rc == 0, "sssctl user-checks command failed"

    result = client.sssd.svc.status("sssd")
    assert result.rc == 0, "service status sssd failed"
