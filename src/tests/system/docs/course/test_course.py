from __future__ import annotations

import pytest

from lib.sssd.roles.client import Client
from lib.sssd.roles.generic import GenericADProvider, GenericProvider
from lib.sssd.roles.ipa import IPA
from lib.sssd.roles.ldap import LDAP
from lib.sssd.topology import KnownTopology, KnownTopologyGroup


# start:task_01
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__skeleton(client: Client, ldap: LDAP):
    """
    :title: Pytest-mh test skeleton for the LDAP topology that does nothing
    :customerscenario: False
    """
    pass
    # end:task_01


# start:task_02
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__name(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user" yields the expected user
    :setup:
        1. Add LDAP user "tuser"
        2. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned
    :customerscenario: False
    """
    ldap.user("tuser").add()

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    # end:task_02


# start:task_03
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__name_and_id(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user" yields the expected user, uid and gid
    :setup:
        1. Add LDAP user "tuser" with uid=10001, gid=10001
        2. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned, uid is 10001, gid is 10001
    :customerscenario: False
    """
    ldap.user("tuser").add(uid=10001, gid=10001)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name is None
    assert result.group.id == 10001
    # end:task_03


# start:task_04
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__primary_group(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user" yields the expected user and expected primary group
    :setup:
        1. Add LDAP user "tuser" with uid=10001, gid=10001
        2. Add LDAP group "tuser" with gid 10001
        3. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned, user and group name is "tuser", uid and gid is 10001
    :customerscenario: False
    """
    ldap.user("tuser").add(uid=10001, gid=10001)
    ldap.group("tuser").add(gid=10001)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    # end:task_04


# start:task_05
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__one_supplementary_group(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user" yields the expected user and one expected supplementary groups
    :setup:
        1. Add LDAP user "tuser" with uid=10001, gid=10001
        2. Add LDAP group "tuser" with gid 10001
        3. Add LDAP group "users" with gid 20001
        4. Make user "tuser" member of "users"
        5. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the user is member of "users"
    :customerscenario: False
    """
    u = ldap.user("tuser").add(uid=10001, gid=10001)
    ldap.group("tuser").add(gid=10001)
    ldap.group("users").add(gid=20001).add_member(u)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    assert result.memberof("users")
    # end:task_05


# start:task_06
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__two_supplementary_groups(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user" yields the expected user and two expected supplementary groups
    :setup:
        1. Add LDAP user "tuser" with uid=10001, gid=10001
        2. Add LDAP group "tuser" with gid 10001
        3. Add LDAP group "users"
        4. Add LDAP group "admins"
        5. Make user "tuser" member of "users" and "admins"
        6. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the user is member of "users" and "admins"
    :customerscenario: False
    """
    u = ldap.user("tuser").add(uid=10001, gid=10001)
    ldap.group("tuser").add(gid=10001)
    ldap.group("users").add().add_member(u)
    ldap.group("admins").add().add_member(u)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    assert result.memberof(["users", "admins"])
    # end:task_06


# start:task_07
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__su(client: Client, ldap: LDAP):
    """
    :title: LDAP: Authenticate user with password using "su"
    :setup:
        1. Add LDAP user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Run "su tuser" with correct password
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    ldap.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.su.password("tuser", "Secret123")
    # end:task_07


# start:task_08
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__ssh(client: Client, ldap: LDAP):
    """
    :title: LDAP: Authenticate user with password using "ssh"
    :setup:
        1. Add LDAP user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Run "ssh tuser@localhost" with correct password
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    ldap.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.ssh.password("tuser", "Secret123")
    # end:task_08


# start:task_09
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_ldap__password_authentication(client: Client, ldap: LDAP, method: str):
    """
    :title: LDAP: Authenticate user with password using "@method"
    :setup:
        1. Add LDAP user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Try authenticate the user with password using @method
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    ldap.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.parametrize(method).password("tuser", "Secret123")
    # end:task_09


# start:task_10
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__sudo__passwd(client: Client, ldap: LDAP):
    """
    :title: LDAP: User can run command via sudo when authentication is required
    :setup:
        1. Add LDAP user "tuser" with password "Secret123"
        2. Create sudo rule that allows the user to run "/bin/ls" as root on all hosts
        3. Enable SSSD sudo responder and configure sudo to use SSSD
        4. Start SSSD
    :steps:
        1. Login as "tuser" and run "sudo -l" with user password
        2. Login as "tuser" and run "sudo /bin/ls /root" with user password
    :expectedresults:
        1. The created rule is listed in the output
        2. The command run successfully as root
    :customerscenario: False
    """
    u = ldap.user("tuser").add(password="Secret123")
    ldap.sudorule("allow_ls").add(user=u, host="ALL", command="/bin/ls")

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("tuser", "Secret123", expected=["(root) /bin/ls"])
    assert client.auth.sudo.run("tuser", "Secret123", command="/bin/ls /root")
    # end:task_10


# start:task_11
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__sudo__nopasswd(client: Client, ldap: LDAP):
    """
    :title: LDAP: User can run command via sudo when authentication is not required
    :setup:
        1. Add LDAP user "tuser"
        2. Create sudo rule that allows the user to run "/bin/ls" as root on all hosts, !authenticate option is set
        3. Enable SSSD sudo responder and configure sudo to use SSSD
        4. Start SSSD
    :steps:
        1. Login as "tuser" and run "sudo -l", no password is provided
        2. Login as "tuser" and run "sudo /bin/ls /root", no password is provided
    :expectedresults:
        1. The created rule is listed in the output
        2. The command run successfully as root
    :customerscenario: False
    """
    u = ldap.user("tuser").add()
    ldap.sudorule("allow_ls").add(user=u, host="ALL", command="/bin/ls", nopasswd=True)

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("tuser", expected=["(root) NOPASSWD: /bin/ls"])
    assert client.auth.sudo.run("tuser", command="/bin/ls /root")
    # end:task_11


# start:task_12
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__required_fqn(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user@domain" yields the expected user
    :setup:
        1. Add LDAP user "tuser"
        2. Set use_fully_qualified_names to true for the LDAP domain
        3. Start SSSD
    :steps:
        1. Run "id tuser@domain"
    :expectedresults:
        1. "tuser" is returned
    :customerscenario: False
    """
    ldap.user("tuser").add()

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.start()

    assert client.tools.id("tuser") is None
    assert client.tools.id("tuser@test") is not None
    # end:task_12


# start:task_13
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__config_typo(client: Client, ldap: LDAP):
    """
    :title: LDAP: Typo in SSSD option makes sssctl config-check fail
    :setup:
        1. Add LDAP user "tuser"
        2. Set use_fully_qualified_name (not _names) to true for the LDAP domain
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. The command fails
    :customerscenario: False

    Note that client.sssd.start() calls sssctl config-check prior starting SSSD.
    """
    ldap.user("tuser").add()

    with pytest.raises(Exception):
        client.sssd.domain["use_fully_qualified_name"] = "true"
        client.sssd.start()
    # end:task_13


# start:task_14
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__id__rfc2307bis(client: Client, ldap: LDAP):
    """
    :title: LDAP: Calling "id user" yields the expected user and groups with rfc2307bis schema
    :setup:
        1. Add LDAP user "tuser" with uid=10001, gid=10001
        2. Add LDAP group "tuser" with gid 10001 using rfc2307bis schema
        3. Add LDAP group "users" using rfc2307bis schema
        4. Add LDAP group "admins" using rfc2307bis schema
        5. Make user "tuser" member of "users" and "admins"
        6. Set ldap_schema = rfc2307bis for the LDAP domain
        7. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the user is member of "users" and "admins"
    :customerscenario: False
    """
    u = ldap.user("tuser").add(uid=10001, gid=10001)
    ldap.group("tuser", rfc2307bis=True).add(gid=10001)
    ldap.group("users", rfc2307bis=True).add().add_member(u)
    ldap.group("admins", rfc2307bis=True).add().add_member(u)

    client.sssd.domain["ldap_schema"] = "rfc2307bis"
    client.sssd.start()

    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    assert result.memberof(["users", "admins"])
    # end:task_14


# start:task_15
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__skeleton(client: Client, ipa: IPA):
    """
    :title: Pytest-mh test skeleton for the IPA topology that does nothing
    :customerscenario: False
    """
    pass
    # end:task_15


# start:task_16
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__id__name(client: Client, ipa: IPA):
    """
    :title: IPA: Calling "id user" yields the expected user
    :setup:
        1. Add IPA user "tuser"
        2. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned
    :customerscenario: False
    """
    ipa.user("tuser").add()

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    # end:task_16


# start:task_17
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__id__primary_group(client: Client, ipa: IPA):
    """
    :title: IPA: Calling "id user" yields the expected user and primary group
    :setup:
        1. Add IPA user "tuser" with uid=10001, gid=10001
        2. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned, uid is 10001, gid is 10001
    :customerscenario: False
    """
    ipa.user("tuser").add(uid=10001, gid=10001)

    # Primary group is created automatically, we need to skip this step
    # ipa.group('tuser').add(gid=10001)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    # end:task_17


# start:task_18
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__id__one_supplementary_group(client: Client, ipa: IPA):
    """
    :title: IPA: Calling "id user" yields the expected user and one expected supplementary groups
    :setup:
        1. Add IPA user "tuser" with uid=10001, gid=10001
        2. Add IPA group "users" with gid 20001
        3. Make user "tuser" member of "users"
        4. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the user is member of "users"
    :customerscenario: False
    """
    u = ipa.user("tuser").add(uid=10001, gid=10001)
    # Primary group is created automatically, we need to skip this step
    # ipa.group('tuser').add(gid=10001)
    ipa.group("users").add(gid=20001).add_member(u)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    assert result.memberof("users")
    # end:task_18


# start:task_19
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__id__two_supplementary_groups(client: Client, ipa: IPA):
    """
    :title: IPA: Calling "id user" yields the expected user and two expected supplementary groups
    :setup:
        1. Add IPA user "tuser" with uid=10001, gid=10001
        2. Add IPA group "users"
        3. Make user "tuser" member of "users" and "admins"
        4. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the user is member of "users" and "admins"
    :customerscenario: False
    """
    u = ipa.user("tuser").add(uid=10001, gid=10001)
    # Primary group is created automatically, we need to skip this step
    # ipa.group('tuser').add(gid=10001)
    ipa.group("users").add().add_member(u)
    # Group admins is already present in IPA so we just omit add() and use add_member() only
    # ipa.group('admins').add().add_member(u)
    ipa.group("admins").add_member(u)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    assert result.memberof(["users", "admins"])
    # end:task_19


# start:task_20
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__su(client: Client, ipa: IPA):
    """
    :title: IPA: Authenticate user with password using "su"
    :setup:
        1. Add IPA user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Run "su tuser" with correct password
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    ipa.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.su.password("tuser", "Secret123")
    # end:task_20


# start:task_21
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__ssh(client: Client, ipa: IPA):
    """
    :title: IPA: Authenticate user with password using "ssh"
    :setup:
        1. Add IPA user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Run "ssh tuser@localhost" with correct password
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    ipa.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.ssh.password("tuser", "Secret123")
    # end:task_21


# start:task_22
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_ipa__password_authentication(client: Client, ipa: IPA, method: str):
    """
    :title: IPA: Authenticate user with password using "@method"
    :setup:
        1. Add IPA user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Try authenticate the user with password using @method
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    ipa.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.parametrize(method).password("tuser", "Secret123")
    # end:task_22


# start:task_23
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__sudo__passwd(client: Client, ipa: IPA):
    """
    :title: IPA: User can run command via sudo when authentication is required
    :setup:
        1. Add IPA user "tuser" with password "Secret123"
        2. Create sudo rule that allows the user to run "/bin/ls" as root on all hosts
        3. Enable SSSD sudo responder and configure sudo to use SSSD
        4. Start SSSD
    :steps:
        1. Login as "tuser" and run "sudo -l" with user password
        2. Login as "tuser" and run "sudo /bin/ls /root" with user password
    :expectedresults:
        1. The created rule is listed in the output
        2. The command run successfully as root
    :customerscenario: False
    """
    u = ipa.user("tuser").add(password="Secret123")
    ipa.sudorule("allow_ls").add(user=u, host="ALL", command="/bin/ls")

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("tuser", "Secret123", expected=["(root) /bin/ls"])
    assert client.auth.sudo.run("tuser", "Secret123", command="/bin/ls /root")
    # end:task_23


# start:task_24
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__sudo__nopasswd(client: Client, ipa: IPA):
    """
    :title: IPA: User can run command via sudo when authentication is not required
    :setup:
        1. Add IPA user "tuser"
        2. Create sudo rule that allows the user to run "/bin/ls" as root on all hosts, !authenticate option is set
        3. Enable SSSD sudo responder and configure sudo to use SSSD
        4. Start SSSD
    :steps:
        1. Login as "tuser" and run "sudo -l", no password is provided
        2. Login as "tuser" and run "sudo /bin/ls /root", no password is provided
    :expectedresults:
        1. The created rule is listed in the output
        2. The command run successfully as root
    :customerscenario: False
    """
    u = ipa.user("tuser").add()
    ipa.sudorule("allow_ls").add(user=u, host="ALL", command="/bin/ls", nopasswd=True)

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("tuser", expected=["(root) NOPASSWD: /bin/ls"])
    assert client.auth.sudo.run("tuser", command="/bin/ls /root")
    # end:task_24


# start:task_25
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__id__required_fqn(client: Client, ipa: IPA):
    """
    :title: IPA: Calling "id user@domain" yields the expected user
    :setup:
        1. Add IPA user "tuser"
        2. Set use_fully_qualified_names to true for the IPA domain
        3. Start SSSD
    :steps:
        1. Run "id tuser@domain"
    :expectedresults:
        1. "tuser" is returned
    :customerscenario: False
    """
    ipa.user("tuser").add()

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.start()

    assert client.tools.id("tuser") is None
    assert client.tools.id("tuser@test") is not None
    # end:task_25


# start:task_26
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__config_typo(client: Client, ipa: IPA):
    """
    :title: IPA: Typo in SSSD option makes sssctl config-check fail
    :setup:
        1. Add IPA user "tuser"
        2. Set use_fully_qualified_name (not _names) to true for the IPA domain
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. The command fails
    :customerscenario: False

    Note that client.sssd.start() calls sssctl config-check prior starting SSSD.
    """
    ipa.user("tuser").add()

    with pytest.raises(Exception):
        client.sssd.domain["use_fully_qualified_name"] = "true"
        client.sssd.start()
    # end:task_26


# start:task_27
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__supplementary_groups(client: Client, provider: GenericProvider):
    """
    :title: Calling "id user" yields the expected user and supplementary groups
    :setup:
        1. Add user "tuser"
        2. Add group "tgroup_1"
        3. Add group "tgroup_2"
        4. Make user "tuser" member of "tgroup_1" and "tgroup_2"
        5. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the user is member of "tgroup_1" and "tgroup_2"
    :customerscenario: False
    """
    u = provider.user("tuser").add()
    provider.group("tgroup_1").add().add_member(u)
    provider.group("tgroup_2").add().add_member(u)

    client.sssd.start()
    result = client.tools.id("tuser")

    assert result is not None
    assert result.user.name == "tuser"
    assert result.memberof(["tgroup_1", "tgroup_2"])
    # end:task_27


# start:task_28
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_ad__id__domain_users(client: Client, provider: GenericADProvider):
    """
    :title: AD: The primary user group is "Domain Users"
    :setup:
        1. Add user "tuser"
        2. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned and the primary group is "Domain Users" (case insensitive)
    :customerscenario: False
    """
    provider.user("tuser").add()

    client.sssd.start()

    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.group.name is not None
    assert result.group.name.lower() == "domain users"
    # end:task_28


# start:task_29
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
def test_id__primary_group(client: Client, provider: GenericProvider):
    """
    :title: Calling "id user" yields the expected user and expected primary group
    :setup:
        1. Add user "tuser" with uid=10001, gid=10001
        2. Add group "tuser" with gid 10001
        3. Start SSSD
    :steps:
        1. Run "id tuser"
    :expectedresults:
        1. "tuser" is returned, user and group name is "tuser", uid and gid is 10001
    :customerscenario: False
    """
    provider.user("tuser").add(uid=10001, gid=10001)

    if isinstance(provider, LDAP):
        provider.group("tuser").add(gid=10001)

    client.sssd.start()
    result = client.tools.id("tuser")
    assert result is not None
    assert result.user.name == "tuser"
    assert result.user.id == 10001
    assert result.group.name == "tuser"
    assert result.group.id == 10001
    # end:task_29


# start:task_30
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_sudo__defaults_nopasswd(client: Client, provider: GenericProvider):
    """
    :title: User can run command via sudo when authentication is not required in defaults
    :setup:
        1. Add user "tuser"
        2. Create sudo rule "defaults" with sudoOption set to !authenticate
        3. Create sudo rule that allows the all users to run all commands as root on all hosts
        4. Enable SSSD sudo responder and configure sudo to use SSSD
        5. Start SSSD
    :steps:
        1. Login as "tuser" and run "sudo -l", no password is provided
        2. Login as "tuser" and run "sudo /bin/ls /root", no password is provided
    :expectedresults:
        1. The created rule is listed in the output
        2. The command run successfully as root
    :customerscenario: False
    """
    provider.user("tuser").add()
    provider.sudorule("defaults").add(nopasswd=True)
    provider.sudorule("allow_all").add(user="ALL", host="ALL", command="ALL")

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("tuser", expected=["(root) ALL"])
    assert client.auth.sudo.run("tuser", command="/bin/ls /root")
    # end:task_30


# start:task_31
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_authentication__password(client: Client, provider: GenericProvider, method: str):
    """
    :title: Authenticate user with password using "@method"
    :setup:
        1. Add user "tuser" with password "Secret123"
        2. Start SSSD
    :steps:
        1. Try authenticate the user with password using @method
    :expectedresults:
        1. Authentication is successful
    :customerscenario: False
    """
    provider.user("tuser").add(password="Secret123")

    client.sssd.start()
    assert client.auth.parametrize(method).password("tuser", "Secret123")
    # end:task_31
