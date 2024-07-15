"""
Infopipe tests.

:requirement: Service/IFP
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__get_user_properties(client: Client, provider: GenericProvider):
    """
    :title: Get a user's property
    :setup:
        1. Add 'user-1' to the provider
        2. Launch SSSD
    :steps:
        1. Call FindByName() to get the user's object path
        2. Create a new object associated to that user using its object path
        3. Get the UID property using Get()
        4. Get the GID property with direct access
        5. Get all the properties
    :expectedresults:
        1. User is found and object path retrieved
        2. The object is created
        3. Property is returned and has the right value
        4. Property is returned and has the right value
        5. Some sample properties are present and have the right value
    :customerscenario: False
    """
    provider.user("user-1").add(uid=10001, gid=20001)

    client.sssd.start()

    users = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")
    user_path = users.FindByName("user-1")
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10001" == user_path
    ), "FindByName('user-1') returned an unexpected user path"

    user = client.ifp.getObject(user_path)
    uid = user.Get("org.freedesktop.sssd.infopipe.Users.User", "uidNumber")
    assert uid == 10001, "user.Get(user_path, 'uidNumber') returned an unexpected UID"

    gid = user.gidNumber
    assert gid == 20001, "user.gidNumber returned an unexpected GID"

    props = user.GetAll("org.freedesktop.sssd.infopipe.Users.User")
    assert props["uidNumber"] == 10001, "GetAll(Users.User) returned an unexpected uidNumber"
    assert props["gidNumber"] == 20001, "GetAll(Users.User) returned an unexpected gidNumber"
    assert props["name"] == "user-1", "GetAll(Users.User) returned an unexpected name"
    assert props["homeDirectory"] == "/home/user-1", "GetAll(Users.User) returned an unexpected homeDirectory"


@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__get_domain_properties(client: Client, provider: GenericProvider):
    """
    :title: Access a domain's information through InfoPipe
    :setup:
        1. Launch SSSD
    :steps:
        1. Call IsOnline()
        2. Call GetAll() with "org.freedesktop.sssd.infopipe.Domains"
        3. Read the property enumerable
    :expectedresults:
        1. Domain is online
        2. All data is returned
        3. Is enumerable
    :customerscenario: False
    """
    client.sssd.start()

    domain = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Domains/test")

    res = domain.IsOnline()
    assert isinstance(res, bool), "IsOnline() didn't return a boolean"
    assert res, "IsOnline() returned false"

    res = domain.GetAll("org.freedesktop.sssd.infopipe.Domains")
    assert isinstance(res, dict), "GetAll(infopipe.Domains) didn't return a dict"
    assert res["name"] == "test", "GetAll(infopipe.Domains) returned an unexpected name"
    assert res["provider"] == "ldap", "GetAll(infopipe.Domains) returned an unexpected provider"
    assert (
        res["login_format"] == r"^((?P<name>.+)@(?P<domain>[^@]+)|(?P<name>[^@]+))$"
    ), "GetAll(infopipe.Domains) returned an unexpected login_format"
    assert isinstance(
        res["primary_servers"], list
    ), "GetAll(infopipe.Domains) returned a primary_servers which is not a list"
    assert (
        len(res["primary_servers"]) == 1
    ), "GetAll(infopipe.Domains) returned a wrong number of elements in primary_servers"
    assert (
        res["primary_servers"][0] == "ldap://master.ldap.test"
    ), "GetAll(infopipe.Domains) returned a wrong URI in primary_servers"

    res = domain.enumerable
    assert isinstance(res, bool), "Property enumerable didn't return a boolean"
    assert not res, "Property enumerable returned the wrong value"


@pytest.mark.ticket(gh=6020, bz=2128840, jira="SSSD-5054")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__list_by_attr(client: Client, provider: GenericProvider):
    """
    :title: Test InfoPipe.Users.ListByAttr()
    :setup:
        1. Add 'user-1' to the provider
        2. Add 'user-2' to the provider
        3. Add 'user-3' to the provider
        4. Add "user_attributes = +extraName" to the [ifp] configuration section
        5. Add "ldap_user_extra_attrs = extraName:uid" to the 'test' domain configuration
        6. Create the 'app' application domain inheriting from 'test'
        7. Launch SSSD
    :steps:
        1. Call ListByAttr() with "extraName=user-2" and no limit
        2. Call ListByAttr() with "extraName=user-*" and no limit
        3. Call ListByAttr() with "extraName=user-*" and a limit of 4
        4. Call ListByAttr() with "extraName=nouser-*" and no limit
        5. Call ListByAttr() with "noName=*" and no limit
    :expectedresults:
        1. User is found exactly once for 'test' and once for 'app'
        2. All three users are found on each domain
        3. Four of the six user entries are returned
        4. No user is returned
        5. No user is returned
    :customerscenario: False
    """
    provider.user("user-1").add(uid=10001)
    provider.user("user-2").add(uid=10002)
    provider.user("user-3").add(uid=10003)

    cfg = client.sssd.config
    cfg.set("sssd", "domains", cfg.get("sssd", "domains") + ",app")
    cfg.add_section("ifp")
    cfg.set("ifp", "user_attributes", "+extraName")
    cfg.set("domain/test", "ldap_user_extra_attrs", "extraName:uid")
    cfg.add_section("application/app")
    cfg.set("application/app", "inherit_from", "test")

    client.sssd.start()

    users = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")

    list = users.ListByAttr("extraName", "user-2", 0)
    assert len(list) == 2, "ListByAttr('extraName', 'user-2', 0) returned a wrong number of elements"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10002" in list
    ), "ListByAttr('extraName', 'user-2', 0) is missing element test/user-2"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/app/user_2d2_40app" in list
    ), "ListByAttr('extraName', 'user-2', 0) is missing element app/user-2"

    list = users.ListByAttr("extraName", "user-*", 0)
    assert len(list) == 6, "Wrong number of elements in list"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10001" in list
    ), "ListByAttr('extraName', 'user-*', 0) is missing element test/10001"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10002" in list
    ), "ListByAttr('extraName', 'user-*', 0) is missing element test/10002"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10003" in list
    ), "ListByAttr('extraName', 'user-*', 0) is missing element test/10003"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/app/user_2d1_40app" in list
    ), "ListByAttr('extraName', 'user-*', 0) is missing element app/user-1"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/app/user_2d2_40app" in list
    ), "ListByAttr('extraName', 'user-*', 0) is missing element app/user-2"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/app/user_2d3_40app" in list
    ), "ListByAttr('extraName', 'user-*', 0) is missing element app/user-3"

    model = list  # We'll use this list as model for the next check
    list = users.ListByAttr("extraName", "user-*", 4)
    assert len(list) == 4, "ListByAttr('extraName', 'user-*', 4) returned a wrong number of elements"
    # We don't know which two will be returned
    for user in list:
        assert user in model, "ListByAttr('extraName', 'user-*', 4) returned an unexpected element"

    list = users.ListByAttr("extraName", "nouser-*", 0)
    assert len(list) == 0, "ListByAttr('extraName', 'nouser-*', 0) returned unexpected elements"

    list = users.ListByAttr("noattr", "*", 0)
    assert len(list) == 0, "ListByAttr('noattr', '*', 0) returned unexpected elements"


@pytest.mark.ticket(gh=[6360, 6361], jira="SSSD-5054")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__list_by_name(client: Client, provider: GenericProvider):
    """
    :title: Test InfoPipe.Users.ListByName()
    :setup:
        1. Add 'user-1' to the provider
        2. Add 'user-2' to the provider
        3. Add 'user-3' to the provider
        4. Launch SSSD
    :steps:
        1. Call ListByName() with "user-2" and no limit
        2. Call ListByName() with "user-*" and no limit
        3. Call ListByName() with "user-*" and a limit of 2
        4. Call ListByName() with "nouser-*" and no limit
    :expectedresults:
        1. User is found and none else
        2. All three users are found
        3. Two of the three users are returned
        4. No user is returned
    :customerscenario: False
    """
    provider.user("user-1").add(uid=10001)
    provider.user("user-2").add(uid=10002)
    provider.user("user-3").add(uid=10003)
    client.sssd.start()

    users = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")

    result = users.ListByName("user-2", 0)
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10002" in result
    ), "ListByName('user-2', 0) returned unexpected element"
    assert len(result) == 1, "ListByName('user-2', 0) returned a wrong number of elements"

    result = users.ListByName("user-*", 0)
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10001" in result
    ), "ListByName('user-*', 0) is missing element 10001"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10002" in result
    ), "ListByName('user-*', 0) is missing element 10002"
    assert (
        "/org/freedesktop/sssd/infopipe/Users/test/10003" in result
    ), "ListByName('user-*', 0) is missing element 10003"
    assert len(result) == 3, "ListByName('user-*', 0) returned a wrong number of elements"

    model = result  # We'll use this list as model for the next check
    result = users.ListByName("user-*", 2)
    assert len(result) == 2, "ListByName('user-*', 2) returned a wrong number of elements"
    # We don't know which two will be returned
    for user in result:
        assert user in model, "ListByName('user-*', 2) returned an unexpected element"

    result = users.ListByName("nouser*", 0)
    assert len(result) == 0, "ListByName('nouser*', 0) returned unexpected elements"
