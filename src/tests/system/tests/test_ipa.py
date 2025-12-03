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
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="knownhosts")
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
@pytest.mark.builtwith(client="knownhosts")
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
@pytest.mark.builtwith(client="knownhosts")
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

    # Workaround issue where reverse lookup of
    # 10.251.255.10.in-addr.arpa. fails, causing ssh_knownhosts
    # getnameinfo() to fail
    # https://pagure.io/freeipa/issue/9783
    ipa.host.conn.run("systemctl restart named")

    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.sss_ssh_knownhosts(ip)
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        assert f"{ip} {key}" in result.stdout_lines, "Did not get expected public keys!"


@pytest.mark.ticket(gh=7583)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("option", [(None), ("-o")])
@pytest.mark.builtwith(client="knownhosts")
def test_ipa__hostpublickeys_by_name_with_port(client: Client, ipa: IPA, public_keys: list[str], option: str | None):
    """
    :title: sss_ssh_knownhosts returns public keys by host name with port
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
    port = 3333

    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)
    client.sssd.enable_responder("ssh")
    client.sssd.start()

    args = []
    if option is not None:
        args.append(option)
    args.append(f"[{hostname}]:{port}")

    result = client.sss_ssh_knownhosts(*args)
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    assert len(public_keys) == len(result.stdout_lines), "Did not get expected number of public keys!"
    for key in public_keys:
        if option == "-o":
            output = f"{hostname} {key}"
        else:
            output = f"[{hostname}]:{port} {key}"
        assert output in result.stdout_lines, "Did not get expected public keys!"


@pytest.mark.ticket(gh=7583)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="knownhosts")
def test_ipa__hostpublickeys_with_non_default_port(client: Client, ipa: IPA, public_keys: list[str]):
    """
    :title: sss_ssh_knownhosts returns public keys by hostname with non-default port
    :setup:
        1. Create host with SSH key
        2. Add the ipasshpubkey with hostname and port
        3. Configure SSSD with SSH responder
        4. Start SSSD
    :steps:
        1. Lookup SSH key
    :expectedresults:
        1. All public keys were printed
    :customerscenario: False
    """
    hostname = f"ssh-host.{ipa.domain}"
    ip = "10.255.251.10"
    port = 4444

    ipa.host_account(hostname).add(ip=ip, sshpubkey=public_keys)
    client.sssd.enable_responder("ssh")
    client.sssd.start()

    # IPA doesn't currently ipa host-mod with hostname and key
    # this is workaround till IPA add the support.
    for key in public_keys:
        modify_content = ipa.fs.mktmp(
            rf"""
                        dn: fqdn={hostname},cn=computers,cn=accounts,dc=ipa,dc=test
                        changetype: modify
                        add: ipaSshPubKey
                        ipaSshPubKey: [{hostname}]:{port} {key}
                        """,
            mode="a=rx",
        )
        ipa.host.conn.run(command=f"ldapmodify -H ldap://master.ipa.test -f {modify_content}")

    result = client.sss_ssh_knownhosts(f"[{hostname}]:{port}")
    assert result.rc == 0, "Did not get OpenSSH known hosts public keys!"
    for key in public_keys:
        assert f"[{hostname}]:{port} {key}" in result.stdout_lines, (
            "Did not get expected public keys with " " the host name with port"
        )


@pytest.mark.importance("medium")
@pytest.mark.integration
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__user_authorized_public_ssh_key(client: Client, ipa: IPA):
    """
    :title: Check sss_ssh_authorizedkeys succeeds
    :setup:
        1. Configure SSHD for authorized_keys
        2. Create users 'user1' and 'user2'
        3. Configure and start SSSD with SSH responder
        4. Lookup 'user1' and create SSH key pair
        5. Add public key to IPA user 'user1'
        6. Restart SSSD and clear the cache
    :steps:
        1. Lookup 'user1' and 'user2' using sss_ssh_authorizedkeys
    :expectedresults:
        1. Lookup for 'user1' passes and 'user2' fails
    :customerscenario: False
    """
    client.sshd.config_set(
        [
            {
                "AuthorizedKeysCommand": "/usr/bin/sss_ssh_authorizedkeys",
                "AuthorizedKeysCommandUser": "nobody",
            }
        ]
    )
    client.sshd.reload()

    user = ipa.user("user1").add()
    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User not found!"
    assert result.name is not None, "User name is missing!"
    assert result.home is not None, "home directory is missing!"

    key = client.tools.sshkey.generate(result.name, result.home)[0]
    user.modify(sshpubkey=key)
    client.sssd.restart(clean=True)

    # This will change soon, currently when a user is found but contains no key, the return code is 0.
    # It is planned to change the return code for this condition, so asserting for an empty output can be updated.
    keys = client.sss_ssh_authorizedkeys("user1").stdout
    assert keys, f"Public SSH keys was not found for {user.name}!"
    _keys = keys.split(",")
    assert key in _keys, f"Public SSH key '{key}' does not match for {user.name}!"
    assert not client.sss_ssh_authorizedkeys("user2").stdout, "SSH keys found for user2!"


@pytest.mark.importance("medium")
@pytest.mark.integration
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__user_several_authorized_public_ssh_key(client: Client, ipa: IPA):
    """
    :title: Check sss_ssh_authorizedkeys succeeds when user has multiple public keys
    :setup:
        1. Configure SSHD for authorized_keys
        2. Create user 'user1' and 'user2'
        3. Configure and start SSSD with SSH responder
        4. Lookup 'user1' and create three SSH key pairs
        5. Add public key(s) to IPA user 'user1'
        6. Restart SSSD and clear the cache
    :steps:
        1. Lookup 'user1' and 'user2' using sss_ssh_authorizedkeys
    :expectedresults:
        1. Lookup for 'user1' passes and 'user2' fails
    :customerscenario: False
    """
    client.sshd.config_set(
        [
            {
                "AuthorizedKeysCommand": "/usr/bin/sss_ssh_authorizedkeys",
                "AuthorizedKeysCommandUser": "nobody",
            }
        ]
    )
    client.sshd.reload()

    user = ipa.user("user1").add()
    client.sssd.enable_responder("ssh")
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User not found!"
    assert result.name is not None, "User name is missing!"
    assert result.home is not None, "home directory is missing!"

    key = client.tools.sshkey.generate(result.name, result.home, file="id_rsa0")[0]
    key1 = client.tools.sshkey.generate(result.name, result.home, file="id_rsa1")[0]
    key2 = client.tools.sshkey.generate(result.name, result.home, file="id_rsa2")[0]
    user.modify(sshpubkey=f"{key},{key1},{key2}")
    client.sssd.restart(clean=True)

    # This will change soon, currently when a user is found but contains no key, the return code is 0.
    # It is planned to change the return code for this condition, so asserting for an empty output can be updated.
    keys = client.sss_ssh_authorizedkeys("user1").stdout
    assert keys, f"Public SSH keys was not found for {user.name}!"
    _keys = keys.split(",")
    assert any(key in x for x in _keys), f"Public SSH key '{key}' does not match for {user.name}!"
    assert any(key1 in x for x in _keys), f"Public SSH key '{key1}' does not match for {user.name}!"
    assert any(key2 in x for x in _keys), f"Public SSH key '{key2}' does not match for {user.name}'!"
    assert not client.sss_ssh_authorizedkeys("user2").stdout, "SSH keys found for user2!"


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


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize(
    "override_attrs",
    [
        {"uid": 1234567},
        {"gid": 7654321},
        {"gecos": "This is the ID user override"},
        {"home": "/home/newhomedir"},
        {"shell": "/bin/newloginshell"},
        {"login": "newuser"},
    ],
    ids=[
        "uid=1234567",
        "gid=7654321",
        "gecos=This is the ID user override",
        "home=/home/newhomedir",
        "shell=/bin/newloginshell",
        "login=newuser",
    ],
)
def test_ipa__idview_useroverride_attribute(client: Client, ipa: IPA, override_attrs):
    """
    :title: Verify an IPA ID view can override a user attribute on the client
    :setup:
        1. Create an ID view and apply the view to the client
        2. Create a user and override an attribute
    :steps:
        1. Look up the user
    :expectedresults:
        1. The user is found and the attributes match the overridden values
    :customerscenario: False
    """
    ipa.idview("testview1").add(description="This is a new view")
    ipa.idview("testview1").apply(hosts=[f"{client.host.hostname}"])

    attr, expected_value = next(iter(override_attrs.items()))

    ipa.user("user-1").add().iduseroverride().add_override("testview1", **override_attrs)
    client.sssd.restart()
    # If the attribute being overridden is "login", check both "user-1" and the new login name.
    users_to_check = ["user-1", expected_value] if attr == "login" else ["user-1"]

    for user in users_to_check:
        result = client.tools.getent.passwd(user)
        assert result is not None, f"user {user} not found in system lookup!"

        # For non-login attributes, confirm that the result's attribute matches the expected value.
        if attr != "login":
            result_value = getattr(result, attr, None)
            assert result_value == expected_value, f"Overridden {attr}: expected {expected_value}, got {result_value}!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize(
    "override_attrs",
    [
        {"name": "newgroup"},
        {"gid": 88888},
    ],
    ids=["name=newgroup", "gid=88888"],
)
def test_ipa__idview_groupoverride_attribute(client: Client, ipa: IPA, override_attrs):
    """
    :title: Verify an IPA ID view can override a group attribute on the client
    :setup:
        1. Create an ID view and apply the view to the client
        2. Create a group and override attributes
    :steps:
        1. Look up the group
    :expectedresults:
        1. The group is found and its attributes match the overridden values
    :customerscenario: False
    """
    ipa.idview("testview1").add(description="This is a new view")
    ipa.idview("testview1").apply(hosts=[f"{client.host.hostname}"])

    attr, expected_value = next(iter(override_attrs.items()))
    ipa.group("group-1").add().idgroupoverride().add_override("testview1", **override_attrs)
    client.sssd.restart()

    # If the attribute is "name", check both the original and the new group name.
    groups_to_check = ["group-1", expected_value] if attr == "name" else ["group-1"]

    for group in groups_to_check:
        result = client.tools.getent.group(group)
        assert result is not None, f"group {group} not found in system lookup!"

        # For attributes other than 'name', check that the attribute matches the expected value.
        result_value = getattr(result, attr, None)
        assert result_value == expected_value, f"Overridden {attr}: expected {expected_value}, got {result_value}!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__idview_groupoverride_group_members(client: Client, ipa: IPA):
    """
    :title: Verify members of a group and membership of user with override attributes
    :setup:
        1. Create an ID view and apply the view to the client
        2. Create users and a group with override attributes
    :steps:
        1. Look up the group
        2. Look up the users
    :expectedresults:
        1. The group is found and get users as overridden values
        2. The users and overridden login names are found and get group as overridden value
    :customerscenario: False
    """
    ipa.idview("testview1").add(description="This is a new view")
    ipa.idview("testview1").apply(hosts=[f"{client.host.hostname}"])

    u1 = ipa.user("user-1").add()
    u2 = ipa.user("user-2").add()
    u3 = ipa.user("user-3").add()

    g1 = ipa.group("group-1").add()
    g1.add_members([u1, u2, u3])

    u1.iduseroverride().add_override("testview1", login="newu1")
    u2.iduseroverride().add_override("testview1", login="newu2")
    u3.iduseroverride().add_override("testview1", login="newu3")

    g1.idgroupoverride().add_override("testview1", name="new-group1", gid=88888)
    client.sssd.restart()

    # Check lookup for both the original and the new group name.
    groups_to_check = ["group-1", "new-group1"]
    for group in groups_to_check:
        result = client.tools.getent.group(group)
        assert result is not None, f"group {group} not found in system lookup!"
        assert result.members == [
            "newu1",
            "newu2",
            "newu3",
        ], f"Expected ['newu1', 'newu2', 'newu3'], but got {result.members}!"

    # User's login attribute is being overridden check lookup for both original and the new login name.
    for user in ["user-1", "user-2", "user-3", "newu1", "newu2", "newu3"]:
        result1 = client.tools.id(user)
        assert result1 is not None, f"User {user} was not found using id!"
        assert result1.memberof("new-group1"), f"User {user} is not a member of overriden group 'new-group1'!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__idview_append_user_cert(client: Client, ipa: IPA, moduledatadir: str):
    """
    :title: ID view overrides user certificate from file contents, but value is appended
    :setup:
        1. Create ID view and apply view to client
        2. Add a user that overrides the user's certificate
    :steps:
        1. Look up user certificate
    :expectedresults:
        1. Certificate contains expected data and matches file contents
    :customerscenario: False
    """
    ipa.idview("testview1").add(description="This is a new view")
    ipa.idview("testview1").apply(hosts=[f"{client.host.hostname}"])

    with open(f"{moduledatadir}/certificate") as f:
        certificate_content = f.read().strip()

    ipa.user("user-1").add().iduseroverride().add_override(
        "testview1",
        certificate=certificate_content,
    )

    client.sssd.restart()

    result = ipa.user("user-1").iduseroverride().show_override("testview1")

    assert certificate_content in result.get("usercertificate", [""])[0], "Certificate content mismatch!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__idview_fails_to_apply_on_ipa_master(ipa: IPA):
    """
    :title: ID views does not work on IPA master
    :setup:
        1. Add IPA ID view with description
    :steps:
        1. Apply ID view to IPA master
    :expectedresults:
        1. Applying ID view fails
    :customerscenario: False
    """
    ipa.idview("testview1").add(description="This is a new view")
    result = ipa.idview("testview1").apply(hosts=f"{ipa.host.hostname}")

    assert result.rc == 1, "An IPA ID view should not apply on server!"

    assert (
        "ID View cannot be applied to IPA master" in result.stdout
    ), "Did not get an error message when trying to apply ID view on server!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_ipa__switch_user_with_smartcard_authentication(client: Client, ipa: IPA):
    """
    :title: Smart card authentication allows nested 'su' as IPA user
    :setup:
        1. Create IPA user with key pair and certificate
        2. Copy certificate to client and initialize virtual smart card
        3. Configure SSSD with smart card support and start SSSD services
    :steps:
        1. Execute 'su - ipacertuser1' as root (no authentication required due to pam_rootok.so)
        2. From within the user session, execute nested 'su - ipacertuser1 -c whoami' as ordinary user
    :expectedresults:
        1. First 'su' succeeds without authentication as it's executed by root
        2. Second 'su' prompts for PIN and successfully authenticates with smart card
            a. PIN prompt appears, indicating smart card authentication is triggered for ordinary user
            b. 'whoami' command returns 'ipacertuser1', confirming successful smart card authentication
    :customerscenario: False
    """
    ipa.user("ipacertuser1").add()
    cert, key, _ = ipa.ca.request("ipacertuser1")
    cert_content = ipa.fs.read(cert)
    key_content = ipa.fs.read(key)

    client.fs.write("/opt/test_ca/ipacertuser1.crt", cert_content)
    client.fs.write("/opt/test_ca/ipacertuser1.key", key_content)
    client.smartcard.initialize_card()
    client.smartcard.add_key("/opt/test_ca/ipacertuser1.key")
    client.smartcard.add_cert("/opt/test_ca/ipacertuser1.crt")

    client.authselect.select("sssd", ["with-smartcard"])
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()
    client.svc.restart("virt_cacard.service")
    time.sleep(1)

    result = client.host.conn.run("su - ipacertuser1 -c 'su - ipacertuser1 -c whoami'", input="123456")
    assert "PIN" in result.stderr, f"String 'PIN' was not found in stderr! Stderr content: {result.stderr}"
    assert (
        "ipacertuser1" in result.stdout
    ), f"'ipacertuser1' not found in 'whoami' output! Stdout content: {result.stdout}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_permitted_users_can_login(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based SSH access control using the `sshd` service
    :setup:
      1. Add users
      2. Disable any existing HBAC rules
      3. Create an HBAC rule granting a user access and restart SSSD
    :steps:
      1. Test login for users
      2. Remove the HBAC rule, restart SSSD and test login for users
    :expectedresults:
      1. Users have access
      2. All users are denied access after rule removal
    :customerscenario: False
    """
    # Expected failed logins during testing might trigger the per-source penalty protection inside of sshd
    # so we exempt local SSH connections (::1, 127.0.0.1) from per-source connection penalties
    client.sshd.config_set(
        [
            {
                "PerSourcePenaltyExemptList": "::1,127.0.0.1",
            }
        ]
    )
    client.sshd.reload()

    users = ["user1", "user2", "user3"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    ssh_access_rule = ipa.hbac("ssh_access_user1").create(
        description="SSH access rule for user1", users=["user1"], hosts=["client.test"], services=["sshd"]
    )
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access!"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 should be denied!"
    assert not client.auth.ssh.password("user3", "Secret123"), "user3 should be denied!"

    ssh_access_rule.delete()
    client.sssd.restart()
    for user in users:
        assert not client.auth.ssh.password(user, "Secret123"), f"{user} should be denied!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_permitted_group_users_can_login(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based access control using user groups
    :setup:
      1. Create users and groups
      2. Add users to the appropriate group
      4. Disable default HBAC rule
      5. Create HBAC rule for a group SSH access and restart SSSD
    :steps:
      1. Test login for users in group
      2. Remove a user from the group, restart SSSD and test login for users in group
    :expectedresults:
      1. Users in group have access
      2. User is removed and SSSD has restarted and users in group still have access
    :customerscenario: False
    """
    u1 = ipa.user("user1").add()
    u2 = ipa.user("user2").add()
    u3 = ipa.user("user3").add()
    ipa.user("user4").add()
    allow_group = ipa.group("allow_group").add()
    admin_group = ipa.group("admins")

    allow_group.add_members([u1, u2])
    admin_group.add_members([u3])

    ipa.hbac("allow_all").disable()

    ipa.hbac("allow_group_ssh_access").create(
        description="SSH access for allow group", groups="allow_group", hosts="client.test", services="sshd"
    )
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed!"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 SSH should succeed!"
    assert not client.auth.ssh.password("user3", "Secret123"), "user3 SSH should fail!"
    assert not client.auth.ssh.password("user4", "Secret123"), "user4 SSH should fail!"

    allow_group.remove_member(u1)
    client.sssd.restart()
    # The 10-second wait is crucial to ensure SSSD updates its cached group-to-HBAC mappings so that
    # access control changes take effect correctly during tests.
    time.sleep(10)
    assert not client.auth.ssh.password("user1", "Secret123"), "user1 should be denied after group removal!"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 should still have access!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_permitted_host_group_members_can_login(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based access control using host groups
    :setup:
      1. Create test users: user1 (privileged), user2, user3
      2. Create hostgroups:
         - ipa-client -> contains all enrolled client hosts
         - ipa-master -> contains only the IPA server host
      3. Assign the respective hosts to their hostgroups
      4. Disable the default "allow_all" HBAC rule
      5. Create two explicit HBAC rules:
         - Allow all test users -> hostgroup ipa-client
         - Allow user1 -> hostgroup ipa-master
      6. Restart SSSD
    :steps:
      1. All users attempt to login to ipa-client
      2. All users attempt to login to ipa-master
    :expectedresults:
      1. All three users can log in to ipa-client
      2. Only user1 can log in to ipa-master
    :customerscenario: False
    """
    users = ["user1", "user2", "user3"]
    for user in users:
        ipa.user(user).add()

    ipa_client = ipa.hostgroup("ipa-client").add(description="client host group")
    ipa_client.add_member(host="client.test")
    ipa_master = ipa.hostgroup("ipa-master").add(description="IPA server host group")
    ipa_master.add_member(host="master.ipa.test")

    ipa.hbac("allow_all").disable()

    ipa.hbac("allow_ipa_client_ssh_access").create(
        description="SSH access for ipa-client hostgroup",
        users=["user1", "user2", "user3"],
        hostgroups="ipa-client",
        services="sshd",
    )
    ipa.hbac("allow_ipa_master_ssh_access").create(
        description="SSH access for ipa-master hostgroup",
        users="user1",
        hostgroups="ipa-master",
        services="sshd",
    )
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access!"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 should have access!"
    assert client.auth.ssh.password("user3", "Secret123"), "user3 should have access!"

    assert ipa.auth.ssh.password("user1", "Secret123"), "user1 should have access!"
    assert not ipa.auth.ssh.password("user2", "Secret123"), "user2 should be denied!"
    assert not ipa.auth.ssh.password("user3", "Secret123"), "user3 should be denied!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_users_can_auth_by_permitted_services(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based access control using service groups
    :setup:
      1. Add user and service group
      2. Add SSH to service group and restart SSSD
    :steps:
      1. Authenticate a user using SSH and SU
      2. Disable the default HBAC rule
      3. Create an HBAC rule granting the user access to the service group and restart SSSD
      4. Authenticate a user using SSH and SU
    :expectedresults:
      1. All users have access
      2. Default HBAC rule disabled
      3. HBAC rule is created, and SSSD is restarted
      4. SSH authentication succeeds, while SU authentication fails
    :customerscenario: False
    """
    ipa.user("user1").add()
    service_group = ipa.hbacsvcgroup("service_group").add(description="Service group")

    service_group.add_member(hbacsvc=["sshd"])
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should have access!"
    assert client.auth.su.password("user1", "Secret123"), "user1 SU should succeed!"

    ipa.hbac("allow_all").disable()

    ipa.hbac("service_group").create(
        description="service group rule",
        users="user1",
        hosts="client.test",
        servicegroups="service_group",
    )
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed!"
    assert not client.auth.su.password("user1", "Secret123"), "user1 SU should fail!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_users_and_groups_in_one_rule(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with mixed users and groups
    :setup:
      1. Create users and a group, and add permitted users to group
      2. Disable default HBAC rule
      3. Create HBAC rule for mixed users and groups and restart SSSD
    :steps:
      1. Test login for users in group and individual users
    :expectedresults:
      1. Users in group and individual user have access
    :customerscenario: False
    """
    users = ["allowed_user1", "allowed_user2", "allowed_user3", "user"]
    for user in users:
        ipa.user(user).add()
    group1 = ipa.group("group1").add(description="group1")
    group1.add_members([ipa.user("allowed_user1"), ipa.user("allowed_user2")])

    ipa.hbac("allow_all").disable()

    ipa.hbac("mixed_access_rule").create(
        description="Access for mixed users and groups",
        users="allowed_user3",
        groups="group1",
        hosts="client.test",
        services="sshd",
    )
    client.sssd.restart()

    assert client.auth.ssh.password("allowed_user1", "Secret123"), "allowed_user1 should have access!"
    assert client.auth.ssh.password("allowed_user2", "Secret123"), "allowed_user2 should have access!"
    assert client.auth.ssh.password("allowed_user3", "Secret123"), "allowed_user3 should have access!"
    assert not client.auth.ssh.password("user", "Secret123"), "user should be denied!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_permitted_nested_group_users_can_login(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with nested group membership
    :setup:
      1. Create test users: user1, user2, user3, user4, user5
      2. Create groups with nested structure:
         - child_group1 -> contains user1, user2
         - child_group2 -> contains user3, user4
         - parent_group -> contains child_group1 and child_group2
      3. Disable the default "allow_all" HBAC rule
      4. Create HBAC rule allowing parent_group access to client host
      5. Restart SSSD
    :steps:
      1. All users attempt to login to client
    :expectedresults:
      1. user1, user2, user3, user4 can log in (members of nested groups); user5 is denied
    :customerscenario: False
    """
    users = ["user1", "user2", "user3", "user4", "user5"]
    for user in users:
        ipa.user(user).add()
    child_group1 = ipa.group("child_group1").add(description="child_group1")
    child_group2 = ipa.group("child_group2").add(description="child_group2")
    parent_group = ipa.group("parent_group").add(description="parent_group")

    child_group1.add_members([ipa.user("user1"), ipa.user("user2")])
    child_group2.add_members([ipa.user("user3"), ipa.user("user4")])
    parent_group.add_members([child_group1, child_group2])

    ipa.hbac("allow_all").disable()

    ipa.hbac("allow_parent_group").create(
        description="Allow parent group with nested children",
        groups="parent_group",
        hosts="client.test",
        services="sshd",
    )
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access!"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 should have access!"
    assert client.auth.ssh.password("user3", "Secret123"), "user3 should have access!"
    assert client.auth.ssh.password("user4", "Secret123"), "user4 should have access!"
    assert not client.auth.ssh.password("user5", "Secret123"), "user5 should be denied!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_rule_enable_disable_affects_login(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule enable/disable affects login
    :setup:
      1. Create a user
      2. Disable default HBAC rule
      3. Create a rule allowing SSH access and restart SSSD
    :steps:
      1. Test login for user
      2. Disable rule, restart SSSD and test login for user
      3. Enable rule, restart SSSD and test login for user
    :expectedresults:
      1. User has access
      2. Disabled rule, SSSD is restarted and User is denied access
      3. Enabled rule, SSSD is restarted and User has access
    :customerscenario: False
    """
    ipa.user("user1").add()

    ipa.hbac("allow_all").disable()

    rule1 = ipa.hbac("rule1").create(
        description="Rule 1 allowing SSH access", users="user1", hosts="client.test", services="sshd"
    )
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access!"

    rule1.disable()
    client.sssd.restart()
    assert not client.auth.ssh.password("user1", "Secret123"), "user1 should be denied after disabling rule!"

    rule1.enable()
    client.sssd.restart()
    assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access after enabling rule!"


@pytest.mark.parametrize("hbac", ["user", "host", "service"])
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__hbac_user_host_service_category_equals_all(client: Client, ipa: IPA, hbac: str):
    """
    :title: Validate HBAC rules with usercat, hostcat, and servicecat categories
    :setup:
      1. Add users
      2. Disable default HBAC rule
      3. Create an HBAC rule with category='all' based on parameter (usercat, hostcat, servicecat) and restart SSSD
    :steps:
      1. Test login for users based on category rules
      2. Modify the rule to remove category='all', restart SSSD and test login for users
    :expectedresults:
      1. Users in category have access, users not in category are denied
      2. Modified rule, SSSD is restarted and users in category are denied access
    :customerscenario: False
    """
    users = ["user1", "user2"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    ipa_rule = ipa.hbac(f"access_{hbac}_all")
    if hbac == "user":
        ipa_rule.create(description="Access to all users", usercat="all", hosts="client.test", services="sshd")
    elif hbac == "host":
        ipa_rule.create(description="Access to all hosts", hostcat="all", users="user1", services="sshd")
    elif hbac == "service":
        ipa_rule.create(description="Access to all services", servicecat="all", hosts="client.test", users="user1")
    client.sssd.restart()

    if hbac == "user":
        assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access!"
        assert client.auth.ssh.password("user2", "Secret123"), "user2 should have access!"
    else:
        assert client.auth.ssh.password("user1", "Secret123"), "user1 should have access!"
        assert not client.auth.ssh.password("user2", "Secret123"), "user2 should be denied!"

    if hbac == "user":
        ipa_rule.modify(usercat="")
    elif hbac == "host":
        ipa_rule.modify(hostcat="")
    elif hbac == "service":
        ipa_rule.modify(servicecat="")
    client.sssd.restart()
    assert not client.auth.ssh.password("user1", "Secret123"), "user1 should be denied after restriction!"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 should be denied after restriction!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__subids_configured(client: Client, ipa: IPA):
    """
    :title: SSSD can read subid ranges configured in IPA
    :setup:
        1. Create a user with generated subids and one without
        2. Configure and start SSSD with subids
    :steps:
        1. Lookup the uid start range and range size for all users
        2. Lookup the gid start range and range size for all users
    :expectedresults:
        1. The values from the client matches the server values  when the user has subids
        2. The values from the client matches the server values when the user has subids
    :customerscenario: False
    """
    user = ipa.user("user1").add()
    ipa.user("user2").add()
    ipa_sub = user.subid().generate()

    client.sssd.common.subid()
    client.sssd.start()

    subuid = client.tools.getsubid("user1")
    assert subuid is not None, "Found no subuids for User1!"
    assert (
        ipa_sub.uid_start == subuid.range_start
    ), f"User1 subordinate UID range start value {subuid.range_start} does not match: {ipa_sub.uid_start}!"
    assert (
        ipa_sub.uid_size == subuid.range_size
    ), f"User1 subordinate UID range size value {subuid.range_size} does not match: {ipa_sub.uid_size}!"
    assert client.tools.getsubid("user2") is None, "User2 has unexpected subuids configured!"

    subgid = client.tools.getsubid("user1", group=True)
    assert subgid is not None, "Found no subgids for User1"
    assert (
        ipa_sub.gid_start == subgid.range_start
    ), f"User1 subordinate GID range start value {subgid.range_start} does not match: {ipa_sub.gid_start}!"
    assert (
        ipa_sub.gid_size == subgid.range_size
    ), f"User1 subordinate GID range size value {subgid.range_size} does not match: {ipa_sub.gid_size}!"
    assert client.tools.getsubid("user2", group=True) is None, "User2 has unexpected subgids configured!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__prohibited_short_names(ipa: IPA):
    """
    :title: SSSD refuses to start with short names on IPA
    :setup:
        1. Set full_name_format to %1$s on IPA
    :steps:
        1. Restart SSSD on IPA
    :expectedresults:
        1. SSSD must refuse to start
    :customerscenario: False
    """
    ipa.sssd.dom(ipa.domain)["full_name_format"] = "%1$s"

    result = ipa.sssd.restart(raise_on_error=False)

    assert result is not None, "Test failure - no result of SSSD restart!"
    assert result.rc != 0, "SSSD should refuse to start with full_name_format set to '%1$s'!"
