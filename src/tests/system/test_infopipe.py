"""
Infopipe tests.

:requirement: Service/IFP
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
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
def test_infopipe__get_domain_properties(client: Client):
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


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1667252)
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__lookup_user_with_extra_attributes(client: Client, provider: GenericProvider):
    """
    :title: Infopipe does not crash looking up extra attribute
    :setup:
        1. Create user "user1"
        2. Enable infopipe, add a test attribute and start SSSD
    :steps:
        1. Lookup user using sssctl
        2. Check SSSD service
    :expectedresults:
        1. User found
        2. Service is running
    :customerscenario: True
    """
    provider.user("user1").add()
    client.sssd.sssd["services"] = "nss, pam, ifp"
    client.sssd.domain["ldap_user_extra_attrs"] = "test:homeDirectory"
    client.sssd.ifp["user_attributes"] = "+test"
    client.sssd.start()

    result = client.sssctl.user_checks("user1")
    assert result.rc == 0, "User not found!"

    result = client.sssd.svc.status("sssd")
    assert result.rc == 0, "Service is not running!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__lookup_group_and_properties(client: Client, provider: GenericProvider):
    """
    :title: Infopipe lookup group, members and properties
    :setup:
        1. Create users and group
        2. Add users to groups
        3. Start SSSD
    :steps:
        1. Find group object
        2. Get GID from group object
        3. Get all properties from object
    :expectedresults:
        1. Group object is found
        2. GID found and matches expected value
        3. Properties are returned with correct members and properties
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=10001)
    u2 = provider.user("user2").add(uid=10002)
    provider.group("group-1").add(gid=30001).add_members([u1, u2])
    client.sssd.start()

    groups = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Groups")
    group_path = groups.FindByName("group-1")
    group = client.ifp.getObject(group_path)

    gid = group.Get("org.freedesktop.sssd.infopipe.Groups.Group", "gidNumber")
    assert gid == 30001, f"Expected GID 30001, got {gid}"

    # Initially the list is empty and to update the groups UpdateMemberList needs to be issued
    group.UpdateMemberList()

    props = group.GetAll("org.freedesktop.sssd.infopipe.Groups.Group")

    assert props["name"] == "group-1", f"Unexpected name: {props['name']}"
    assert props["gidNumber"] == 30001, f"Unexpected gidNumber: {props['gidNumber']}"

    assert len(props["users"]) == 2, f"Expected 2 members, got {len(props['users'])}"
    assert any("10001" in str(u) for u in props["users"]), "user1 (uid=10001) not found"
    assert any("10002" in str(u) for u in props["users"]), "user2 (uid=10002) not found"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__lookup_returns_latest_group_membership(client: Client, provider: GenericProvider):
    """
    :title: Infopipe returns latest group changes
    :setup:
       1. Create user and two groups
       2. Add user to first group
       3. Start SSSD
    :steps:
       1. Lookup user’s group
       2. Move user to the other group
       3. Lookup user’s group
    :expectedresults:
       1. User is the first group
       2. User is moved to second group
       3. User is the second group
    :customerscenario: False
    """
    user = provider.user("user1").add(uid=10001)
    group1 = provider.group("group1").add(gid=20001)
    group2 = provider.group("group2").add(gid=20002)
    group1.add_member(user)

    client.sssd.start()

    users_iface = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")
    groups_iface = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Groups")

    user_path = users_iface.FindByName("user1")
    user_obj = client.ifp.getObject(user_path)

    group1_path = groups_iface.FindByName("group1")
    initial_groups = user_obj.groups

    assert len(initial_groups) == 2, f"Expected 2 groups initially (primary + group1), got {len(initial_groups)}"
    assert group1_path in initial_groups, "user1 not in group1 initially"

    group1.remove_member(user)
    group2.add_member(user)

    client.sssd.restart(clean=True)

    user_path = users_iface.FindByName("user1")
    user_obj = client.ifp.getObject(user_path)

    group2_path = groups_iface.FindByName("group2")
    updated_groups = user_obj.groups

    assert len(updated_groups) == 2, f"Expected 2 groups after update (primary + group2), got {len(updated_groups)}"
    assert group2_path in updated_groups, "user1 not in group2 after update"
    assert group1_path not in updated_groups, "user1 still in group1 after removal"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__lookup_user_attributes(client: Client, provider: LDAP):
    """
    :title: Infopipe looks up user attributes
    :setup:
       1. Create user with ‘sn’, ‘givenName” and ‘mail’ attributes set
       2. Configure sssd with ‘parameter to fetch custom attributes = sn, givenName, mail’
       3. Start SSSD
    :steps:
       1. Look up user attributes
    :expectedresults:
       1. All requested attributes are returned with expected values
    :customerscenario: False
    """
    provider.user("user1").add(uid=10001, gid=10001, sn="Test", givenName="User", mail="user1@example.com")

    client.sssd.domain["ldap_user_extra_attrs"] = "sn:sn,givenName:givenName,mail:mail"
    client.sssd.ifp["user_attributes"] = "+sn,+givenName,+mail"
    client.sssd.start()

    users = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")
    user_path = users.FindByName("user1")
    user = client.ifp.getObject(user_path)
    results = user.GetAll("org.freedesktop.sssd.infopipe.Users.User")
    user_attrs = results["extraAttributes"]

    for i in [
        ("sn", "Test"),
        ("givenName", "User"),
        ("mail", "user1@example.com"),
    ]:
        assert i[0] in user_attrs and user_attrs[i[0]] == [i[1]], f"Expected {i[0]} to be {i[1]}"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__ping(client: Client):
    """
    :title: Call the infopipe ping method
    :setup:
        1. Start SSSD
    :steps:
        1. Call ping method
    :expectedresults:
        1. Ping success
    :customerscenario: False
    """
    client.sssd.start()

    ifp = client.ifp.getObject("/org/freedesktop/sssd/infopipe")

    for i in ["ping", "PinG", "PING"]:
        assert ifp.Ping(i) == "PONG", "Ping() did not return expected value"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__list_components(client: Client):
    """
    :title: Call infopipe ListComponents method
    :setup:
        1. Start SSSD
    :steps:
        1. Call ListComponents method
        2. Verify returned components
    :expectedresults:
        1. Method returns list of components
        2. At least monitor component is present
    :customerscenario: False
    """
    client.sssd.start()

    ifp = client.ifp.getObject("/org/freedesktop/sssd/infopipe")
    components = ifp.ListComponents()
    assert len(components) > 0, "No components returned"

    component = client.ifp.getObject(components[0])
    results = {}
    properties = ["name", "type", "enabled", "debug_level"]
    for prop in properties:
        results[prop] = component.Get("org.freedesktop.sssd.infopipe.Components", prop)

    for i in properties:
        assert i in results, f"Component missing {i} property"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__find_monitor(client: Client):
    """
    :title: Call infopipe FindMonitor method
    :setup:
        1. Start SSSD
    :steps:
        1. Call FindMonitor method
        2. Get monitor properties
    :expectedresults:
        1. Returns monitor object path
        2. Monitor properties contain expected values
    :customerscenario: False
    """
    client.sssd.start()

    ifp = client.ifp.getObject("/org/freedesktop/sssd/infopipe")
    monitor_path = ifp.FindMonitor()
    assert monitor_path.startswith(
        "/org/freedesktop/sssd/infopipe/Components/"
    ), f"Monitor path '{monitor_path}' should start with '/org/freedesktop/sssd/infopipe/Components/'"

    monitor = client.ifp.getObject(monitor_path)
    results = {}
    for properties in ["name", "type", "enabled"]:
        results[properties] = monitor.Get("org.freedesktop.sssd.infopipe.Components", properties)

    assert results["name"] == "monitor", f"Expected monitor name 'monitor', got '{results['name']}'"
    assert results["type"] == "monitor", f"Expected monitor type 'monitor', got '{results['type']}'"
    assert results["enabled"] is True, f"Expected monitor to be enabled (True), got '{results['enabled']}'"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__find_user_by_id(client: Client, provider: GenericProvider):
    """
    :title: Test FindByID method of Users interface
    :setup:
        1. Add user 'iduser' with specific UID
        2. Start SSSD
    :steps:
        1. Call FindByID() with user's UID
        2. Verify returned user object
    :expectedresults:
        1. Correct user path is returned
        2. User object has expected properties
    :customerscenario: False
    """
    provider.user("iduser").add(uid=10011)
    client.sssd.start()

    users = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")
    user_path = users.FindByID(10011)
    assert user_path == "/org/freedesktop/sssd/infopipe/Users/test/10011", "FindByID returned wrong path"

    user = client.ifp.getObject(user_path)
    assert user.name == "iduser", "User name incorrect"
    assert user.uidNumber == 10011, "User UID incorrect"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__find_group_by_id(client: Client, provider: GenericProvider):
    """
    :title: Test FindByID method of Groups interface
    :setup:
        1. Add group 'idgroup' with specific gid
        2. Start SSSD
    :steps:
        1. Call FindByID() with group's GID
        2. Verify returned group object
    :expectedresults:
        1. Correct group path is returned
        2. Group object has expected properties
    :customerscenario: False
    """
    provider.group("idgroup").add(gid=20011)
    client.sssd.start()

    groups = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Groups")
    group_path = groups.FindByID(20011)
    assert group_path == "/org/freedesktop/sssd/infopipe/Groups/test/20011", "FindByID returned wrong path"

    group = client.ifp.getObject(group_path)
    assert group.name == "idgroup", "Group name incorrect"
    assert group.gidNumber == 20011, "Group GID incorrect"


@pytest.mark.xfail(reason="https://issues.redhat.com/browse/IDM-1940")
@pytest.mark.ticket(jira="IDM-1940")
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_infopipe__update_user_groups(client: Client, provider: GenericProvider):
    """
    :title: Call infopipe UpdateGroupsList method
    :setup:
        1. Create user and groups, with the user as a member
        2. Start SSSD
    :steps:
        1. Get user object
        2. Refresh group membership
        3. Verify groups are updated
    :expectedresults:
        1. User object retrieved
        2. Refresh succeeds
        3. Group membership is correct
    :customerscenario: False
    """
    user = provider.user("user1").add(uid=10001, gid=10001)
    group1 = provider.group("group1").add(gid=20001)
    group2 = provider.group("group2").add(gid=20002)
    group1.add_member(user)

    client.sssd.start()

    users_iface = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Users")
    groups_iface = client.ifp.getObject("/org/freedesktop/sssd/infopipe/Groups")

    user_path = users_iface.FindByName("user1")
    assert (
        user_path == "/org/freedesktop/sssd/infopipe/Users/test/10001"
    ), "FindByName('user1') returned an unexpected user path"

    user_obj = client.ifp.getObject(user_path)
    group1_path = groups_iface.FindByName("group1")
    initial_groups = user_obj.groups

    assert len(initial_groups) == 2, f"Expected 2 groups initially (primary + group1), got {len(initial_groups)}"
    assert group1_path in initial_groups, "user1 not in group1 initially"

    group2.add_member(user)
    user_obj.UpdateGroupsList()

    updated_groups = user_obj.groups
    group2_path = groups_iface.FindByName("group2")

    assert (
        len(updated_groups) == 3
    ), f"Expected 3 groups after update (primary + group1 + group2), got {len(updated_groups)}"
    assert group1_path in updated_groups, "user1 not in group1 after update"
    assert group2_path in updated_groups, "user1 not in group2 after update"
