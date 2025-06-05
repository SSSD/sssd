"""
IPA SSH Public Host Keys Tests.

:requirement: IPA: hostpublickeys

sss_ssh_knownhosts acquires SSH public keys for host and outputs them in OpenSSH known_hosts key format.
Support for 'KnownHostsCommand' and deprecate 'sss_ssh_knownhostsproxy'
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.misc import get_attr
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


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_check_access_sshd_service(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based SSH access control using the `sshd` service

    :setup:
      1. Add users: user1, user2, and user3 to the IPA server.
      2. Disable the default HBAC rule `allow_all` to restrict all access.
      3. Create a new HBAC rule `ssh_access_user1` for:
         - user: user1
         - host: client.test
         - service: sshd

    :steps:
      1. Run `ipa hbactest` for user1 on client.test with sshd — expect access granted.
      2. Verify that ssh_access_user1 rule is in the matched rules list.
      3. Run `ipa hbactest` for user2 on client.test with sshd — expect access denied.
      4. Verify that ssh_access_user1 rule is in the not_matched rules list for user2.
      5. Restart SSSD service on the client to reflect HBAC rule changes.
      6. Validate SSH login access for user1 (succeeds), and user2/user3 (fail).
      7. Delete ssh_access_user1 rule from IPA.
      8. Restart SSSD service after rule deletion.
      9. SSH access is denied for all users after rule deletion.

    :expectedresults:
      1. user1 access granted via HBAC test.
      2. ssh_access_user1 rule found in matched rules for user1.
      3. user2 access denied via HBAC test.
      4. ssh_access_user1 rule found in not_matched rules for user2.
      5. SSSD service restarts successfully.
      6. user1 SSH login successful and user2 and user3 SSH logins fail
      7. ssh_access_user1 rule deleted without errors.
      8. SSSD service restarts successfully after rule deletion.
      9. All users are denied SSH access after rule deletion.

    :customerscenario: False
    """
    users = ["user1", "user2", "user3"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    ssh_access_rule = ipa.hbac("ssh_access_user1").create(
        description="SSH access rule for user1", users=["user1"], hosts=["client.test"], services=["sshd"]
    )

    hbactest_out1 = ssh_access_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_out1["access_granted"], "Access was not granted as expected"
    assert (
        "ssh_access_user1" in hbactest_out1["matched_rules"]
    ), "Matched rule ssh_access_user1 was not found as expected"

    hbactest_out2 = ssh_access_rule.test(user="user2", host="client.test", service="sshd")
    assert not hbactest_out2["access_granted"], "Access was granted for user2, which is not expected"
    assert "ssh_access_user1" in hbactest_out2["not_matched_rules"], "Rule should not match for user2"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 SSH should be denied"
    assert not client.auth.ssh.password("user3", "Secret123"), "user3 SSH should be denied"

    ssh_access_rule.delete()

    client.sssd.restart()

    #for user in users:
    assert not client.auth.ssh.password("user1", "Secret123"), f"user SSH should succeed"
    assert not client.auth.ssh.password("user2", "Secret123"), f"user SSH should succeed"
    assert not client.auth.ssh.password("user3", "Secret123"), f"user SSH should succeed"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_user_group_access(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based access control using user groups

    :setup:
      1. Add users: user1, user2, user3, user4 to the IPA server.
      2. Create user groups: developers, admins
      3. Add user1 and user2 to developers group
      4. Add user3 to qs group
      5. Disable the default HBAC rule `allow_all` to restrict all access.
      6. Create a new HBAC rule `developers_ssh_access` with:
         - Description: "SSH access for developers group"
         - User group: developers
         - Host: client.test
         - Service: sshd

    :steps:
      1. Run `ipa hbactest` for user1 (developers group) — expect access granted.
      2. Run `ipa hbactest` for user2 (developers group) — expect access granted.
      3. Run `ipa hbactest` for user3 (admins group) — expect access denied.
      4. Run `ipa hbactest` for user4 (no group) — expect access denied.
      5. Validate SSH login access for all users.
      6. Remove user1 from developers group.
      7. Restart SSSD and validate user1 access is now denied.

    :expectedresults:
      1. user1 access granted and matched with developers_ssh_access rule.
      2. user2 access granted and matched with developers_ssh_access rule.
      3. user3 access denied as not in developers group.
      4. user4 access denied as not in any group.
      5. user1 and user2 login successful; user3 and user4 logins fail.
      6. user1 removed from developers group successfully.
      7. user1 access denied after group removal; user2 still has access.

    :customerscenario: False
    """
    u1 = ipa.user("user1").add()
    u2 = ipa.user("user2").add()
    u3 = ipa.user("user3").add()
    ipa.user("user4").add()

    dev_group = ipa.group("developers").add()
    admin_group = ipa.group("admins")

    dev_group.add_members([u1, u2])
    admin_group.add_members([u3])

    ipa.hbac("allow_all").disable()

    developers_ssh_rule = ipa.hbac("developers_ssh_access").create(
        description="SSH access for developers group", groups="developers", hosts="client.test", services="sshd"
    )

    hbactest_user1 = developers_ssh_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_user1["access_granted"], "user1 should have access via developers group"
    assert (
        "developers_ssh_access" in hbactest_user1["matched_rules"]
    ), "developers_ssh_access rule should match for user1"

    hbactest_user2 = developers_ssh_rule.test(user="user2", host="client.test", service="sshd")
    assert hbactest_user2["access_granted"], "user2 should have access via developers group"
    assert (
        "developers_ssh_access" in hbactest_user2["matched_rules"]
    ), "developers_ssh_access rule should match for user2"

    hbactest_user3 = developers_ssh_rule.test(user="user3", host="client.test", service="sshd")
    assert not hbactest_user3["access_granted"], "user3 should be denied (not in developers group)"

    hbactest_user4 = developers_ssh_rule.test(user="user4", host="client.test", service="sshd")
    assert not hbactest_user4["access_granted"], "user4 should be denied (no group membership)"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 SSH should succeed"
    assert not client.auth.ssh.password("user3", "Secret123"), "user3 SSH should fail"
    assert not client.auth.ssh.password("user4", "Secret123"), "user4 SSH should fail"

    dev_group.remove_member(u1)

    client.sssd.restart()
    time.sleep(10)  # Need sleep to make it passed

    assert not client.auth.ssh.password("user1", "Secret123"), "user1 should be denied after group removal"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 should still have access"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_host_group_access(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based access control using host groups

    :setup:
      1. Add users: user1, user2 to the IPA server.
      2. Create host groups: webservers, dbservers
      3. Add client.test to webservers group
      4. Disable the default HBAC rule `allow_all`.
      5. Create HBAC rule `webservers_ssh_access` for webservers host group.

    :steps:
      1. Run `ipa hbactest` for user1 on client.test with webservers rule — expect access granted.
      2. Test that rule matches webservers host group.
      3. Restart SSSD service on the client.
      4. Validate SSH access works for user1.
      5. Validate SSH access denied for user2.
      6. Remove client.test from webservers group.
      7. Restart SSSD service after host group change.
      8. Validate access is denied for user1 after host group removal.

    :expectedresults:
      1. user1 access granted and matched with webservers_ssh_access rule.
      2. Rule correctly identifies host group membership.
      3. SSSD service restarts successfully.
      4. user1 SSH login successful.
      5. user2 SSH login denied.
      6. client.test removed from webservers group successfully.
      7. SSSD service restarts successfully.
      8. user1 access denied after host group removal.

    :customerscenario: False
    """
    users = ["user1", "user2"]
    for user in users:
        ipa.user(user).add()

    web_group = ipa.hostgroup("webservers").add(description="Web servers group")
    ipa.hostgroup("dbservers").add(description="Database servers group")

    web_group.add_member(host="client.test")

    ipa.hbac("allow_all").disable()

    webservers_ssh_rule = ipa.hbac("webservers_ssh_access").create(
        description="SSH access for webservers host group", users="user1", hostgroups="webservers", services="sshd"
    )

    hbactest_result = webservers_ssh_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_result["access_granted"], "user1 should have access via host group"
    assert (
        "webservers_ssh_access" in hbactest_result["matched_rules"]
    ), "Step 2 Failed: webservers_ssh_access rule should match for host group"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 SSH should be denied"

    web_group.remove_member(host="client.test")

    client.sssd.restart()

    hbactest_result2 = webservers_ssh_rule.test(user="user1", host="client.test", service="sshd")
    assert not hbactest_result2["access_granted"], "user1 should be denied after host group removal"
    assert not client.auth.ssh.password("user1", "Secret123"), "user1 SSH should be denied after host group removal"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_service_group_access(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule-based access control using service groups

    :setup:
      1. Add users: user1, user2 to the IPA server.
      2. Create service group: remote_access
      3. Add sshd and login services to remote_access group
      4. Disable the default HBAC rule `allow_all`.
      5. Create HBAC rule using service group.

    :steps:
      1. Run `ipa hbactest` for user1 with sshd service (in remote_access group) — expect access granted.
      2. Run `ipa hbactest` for user1 with login service (in remote_access group) — expect access granted.
      3. Run `ipa hbactest` for user1 with httpd service (not in group) — expect access denied.
      4. Run `ipa hbactest` for user2 with sshd service — expect access denied.
      5. Restart SSSD service on the client.
      6. Validate SSH access works for user1 and denied for user2.
      7. Remove sshd from service group to test service group functionality.
      8. Restart SSSD and validate user1 SSH access is now denied.

    :expectedresults:
      1. user1 access granted for sshd via service group.
      2. user1 access granted for login via service group.
      3. user1 access denied for httpd (not in service group).
      4. user2 access denied (not in user list).
      5. SSSD service restarts successfully.
      6. user1 SSH login successful; user2 SSH login denied.
      7. sshd service removed from service group successfully.
      8. user1 SSH access denied after sshd removal from service group.

    :customerscenario: False
    """
    users = ["user1", "user2"]
    for user in users:
        ipa.user(user).add()

    remote_svc_group = ipa.hbacsvcgroup("remote_access").add(description="Remote access services")
    remote_svc_group.add_member(hbacsvc=["sshd", "login"])

    ipa.hbac("allow_all").disable()

    remote_services_rule = ipa.hbac("remote_services_access").create(
        description="Remote access via service groups",
        users="user1",
        hosts="client.test",
        servicegroups="remote_access",
    )

    hbactest_ssh = remote_services_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_ssh["access_granted"], "user1 should have sshd access via service group"

    hbactest_login = remote_services_rule.test(user="user1", host="client.test", service="login")
    assert hbactest_login["access_granted"], "user1 should have login access via service group"

    hbactest_http = remote_services_rule.test(user="user1", host="client.test", service="httpd")
    assert not hbactest_http["access_granted"], "user1 should be denied httpd access (not in service group)"

    hbactest_user2 = remote_services_rule.test(user="user2", host="client.test", service="sshd")
    assert not hbactest_user2["access_granted"], "user2 should be denied (not in rule)"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 SSH should be denied"

    remote_svc_group.remove_member(hbacsvc=["sshd"])

    client.sssd.restart()
    assert not client.auth.ssh.password(
        "user1", "Secret123"
    ), "user1 SSH should be denied after sshd removal from service group"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_multiple_rules_priority(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule priority when multiple rules match

    :setup:
      1. Add users: user1, user2 to the IPA server.
      2. Disable the default HBAC rule `allow_all`.
      3. Create multiple HBAC rules with different configurations.
      4. Ensure both rules could potentially match the same user.

    :steps:
      1. Create allow rule for user1 with description "Primary SSH access rule for user1".
      2. Create another rule for user1 with description "Secondary SSH access rule for user1".
      3. Run `ipa hbactest` for user1 — expect access granted.
      4. Run `ipa hbactest` for user2 — expect access denied.
      5. Restart SSSD service on the client.
      6. Validate SSH access works for user1 and denied for user2.
      7. Disable the first rule to test second rule functionality.
      8. Restart SSSD and validate user1 access still works via second rule.

    :expectedresults:
      1. First rule created successfully.
      2. Second rule created successfully.
      3. user1 access granted via available rules.
      4. user2 access denied (not in any rule).
      5. SSSD service restarts successfully.
      6. user1 SSH login successful; user2 SSH login denied.
      7. First rule disabled successfully.
      8. user1 access still granted via second rule.

    :customerscenario: False
    """
    users = ["user1", "user2"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    primary_user1_ssh_rule = ipa.hbac("primary_user1_ssh").create(
        description="Primary SSH access rule for user1", users="user1", hosts="client.test", services="sshd"
    )

    secondary_user1_ssh_rule = ipa.hbac("secondary_user1_ssh").create(
        description="Secondary SSH access rule for user1", users="user1", hosts="client.test", services="sshd"
    )

    hbactest_result1 = primary_user1_ssh_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_result1["access_granted"], "user1 should have access via multiple rules"

    hbactest_result2 = primary_user1_ssh_rule.test(user="user2", host="client.test", service="sshd")
    assert not hbactest_result2["access_granted"], "user2 should be denied (not in any rule)"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 SSH should be denied"

    primary_user1_ssh_rule.disable()

    client.sssd.restart()
    hbactest_result3 = secondary_user1_ssh_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_result3["access_granted"], "user1 should still have access via second rule"
    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should still work via second rule"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_category_all_users(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with userCategory='all'

    :setup:
      1. Add users: user1, user2, user3 to the IPA server.
      2. Disable the default HBAC rule `allow_all`.
      3. Create HBAC rule with userCategory='all'.

    :steps:
      1. Create rule allowing all users to specific host/service with userCategory='all'.
      2. Run `ipa hbactest` for user1 — expect access granted.
      3. Run `ipa hbactest` for user2 — expect access granted.
      4. Run `ipa hbactest` for user3 — expect access granted.
      5. Restart SSSD service on the client.
      6. Validate SSH access works for all users.
      7. Modify rule to remove userCategory='all' and add specific user.
      8. Restart SSSD service after rule modification.
      9. Validate only specific user has access after modification.

    :expectedresults:
      1. HBAC rule with userCategory='all' created successfully.
      2. user1 access granted via userCategory='all'.
      3. user2 access granted via userCategory='all'.
      4. user3 access granted via userCategory='all'.
      5. SSSD service restarts successfully.
      6. All users SSH login successful.
      7. Rule modified to specific user successfully.
      8. SSSD service restarts successfully.
      9. Only specific user has access; others denied.

    :customerscenario: False
    """
    users = ["user1", "user2", "user3"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    all_users_ssh_rule = ipa.hbac("all_users_ssh_access").create(
        description="SSH access for all users", usercat="all", hosts="client.test", services="sshd"
    )

    hbactest_result1 = all_users_ssh_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_result1["access_granted"], "user1 should have access via userCategory='all'"

    hbactest_result2 = all_users_ssh_rule.test(user="user2", host="client.test", service="sshd")
    assert hbactest_result2["access_granted"], "user2 should have access via userCategory='all'"

    hbactest_result3 = all_users_ssh_rule.test(user="user3", host="client.test", service="sshd")
    assert hbactest_result3["access_granted"], "user3 should have access via userCategory='all'"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert client.auth.ssh.password("user2", "Secret123"), "user2 SSH should succeed"
    assert client.auth.ssh.password("user3", "Secret123"), "user3 SSH should succeed"

    all_users_ssh_rule.modify(usercat="")
    all_users_ssh_rule.create(users="user1")

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 should still have access"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 should be denied after rule modification"
    assert not client.auth.ssh.password("user3", "Secret123"), "user3 should be denied after rule modification"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_host_category_all(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with hostCategory='all'

    :setup:
      1. Add users: user1, user2 to the IPA server.
      2. Create HBAC rule with hostCategory='all'.
      3. Disable default allow_all rule.

    :steps:
      1. Create rule allowing specific user to all hosts with hostCategory='all'.
      2. Run `ipa hbactest` for user1 on client.test — expect access granted.
      3. Run `ipa hbactest` for user1 on anyhost.test — expect access granted.
      4. Run `ipa hbactest` for user2 on client.test — expect access denied.
      5. Restart SSSD service on the client.
      6. Validate SSH access works for user1 and denied for user2.
      7. Modify rule to remove hostCategory='all' and add specific host.
      8. Restart SSSD service after rule modification.
      9. Validate user1 access works only for specific host after modification.

    :expectedresults:
      1. HBAC rule with hostCategory='all' created successfully.
      2. user1 access granted to client.test via hostCategory='all'.
      3. user1 access granted to anyhost.test via hostCategory='all'.
      4. user2 access denied (not in user list).
      5. SSSD service restarts successfully.
      6. user1 SSH login successful; user2 SSH login denied.
      7. Rule modified to specific host successfully.
      8. SSSD service restarts successfully.
      9. user1 access restricted to specific host only.

    :customerscenario: False
    """
    users = ["user1", "user2"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    user1_all_hosts_rule = ipa.hbac("user1_all_hosts_access").create(
        description="Allow user1 access to all hosts", hostcat="all", users="user1", services="sshd"
    )

    hbactest_result1 = user1_all_hosts_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_result1["access_granted"], "user1 should have access to client.test via hostCategory='all'"

    hbactest_result2 = user1_all_hosts_rule.test(user="user1", host="anyhost.test", service="sshd")
    assert hbactest_result2["access_granted"], "user1 should have access to anyhost.test via hostCategory='all'"

    hbactest_result3 = user1_all_hosts_rule.test(user="user2", host="client.test", service="sshd")
    assert not hbactest_result3["access_granted"], "user2 should be denied (not in rule)"

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 SSH should succeed"
    assert not client.auth.ssh.password("user2", "Secret123"), "user2 SSH should be denied"

    user1_all_hosts_rule.modify(hostcat="")
    user1_all_hosts_rule.create(hosts="client.test")

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "user1 should still have access to client.test"
    hbactest_restricted = user1_all_hosts_rule.test(user="user1", host="anyhost.test", service="sshd")
    assert not hbactest_restricted[
        "access_granted"
    ], "user1 should be denied access to anyhost.test after hostCategory removal"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_service_category_all(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with serviceCategory='all'

    :setup:
      1. Add users: user1, user2 to the IPA server.
      2. Create HBAC rule with serviceCategory='all'.
      3. Disable default allow_all rule.

    :steps:
      1. Create rule allowing specific user to all services with serviceCategory='all'.
      2. Run `ipa hbactest` for user1 with sshd service — expect access granted.
      3. Run `ipa hbactest` for user1 with login service — expect access granted.
      4. Run `ipa hbactest` for user1 with httpd service — expect access granted.
      5. Run `ipa hbactest` for user2 with sshd service — expect access denied.
      6. Restart SSSD service on the client.
      7. Validate SSH access works for user1 and denied for user2.
      8. Modify rule to remove serviceCategory='all' and add specific service.
      9. Validate user1 access works only for specific service after modification.

    :expectedresults:
      1. HBAC rule with serviceCategory='all' created successfully.
      2. user1 access granted for sshd via serviceCategory='all'.
      3. user1 access granted for login via serviceCategory='all'.
      4. user1 access granted for httpd via serviceCategory='all'.
      5. user2 access denied (not in user list).
      6. user1 SSH login successful; user2 SSH login denied.
      7. SSSD service restarts successfully.
      8. Rule modified to specific service successfully.
      9. user1 access restricted to specific service only.

    :customerscenario: False
    """
    users = ["user1", "user2"]
    for user in users:
        ipa.user(user).add()

    ipa.hbac("allow_all").disable()

    user1_all_services_rule = ipa.hbac("user1_all_services_access").create(
        description="Allow user1 access to all services", servicecat="all", users="user1", hosts="client.test"
    )

    hbactest_result1 = user1_all_services_rule.test(user="user1", host="client.test", service="sshd")
    assert hbactest_result1["access_granted"], "user1 should have sshd access via serviceCategory='all'"

    hbactest_result2 = user1_all_services_rule.test(user="user1", host="client.test", service="login")
    assert hbactest_result2["access_granted"], "user1 should have login access via serviceCategory='all'"

    hbactest_result3 = user1_all_services_rule.test(user="user1", host="client.test", service="httpd")
    assert hbactest_result3["access_granted"], "user1 should have httpd access via serviceCategory='all'"

    hbactest_result4 = user1_all_services_rule.test(user="user2", host="client.test", service="sshd")
    assert not hbactest_result4["access_granted"], "user2 should be denied (not in rule)"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_mixed_users_groups(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with mixed users and groups

    :setup:
      1. Add users: alice, bob, charlie, diana to the IPA server.
      2. Create group: power_users
      3. Add alice and bob to power_users group
      4. Disable the default HBAC rule `allow_all`.

    :steps:
      1. Create HBAC rule with both individual users and groups.
      2. Test access for users in group (alice, bob).
      3. Test access for individual user (charlie).
      4. Test access for user not in rule (diana).
      5. Validate real SSH access for all scenarios.

    :expectedresults:
      1. Rule created with mixed user and group assignments.
      2. Group members have access via group membership.
      3. Individual user has access via direct assignment.
      4. Excluded user is denied access.
      5. SSH access matches HBAC test results.

    :customerscenario: False
    """
    users = ["alice", "bob", "charlie", "diana"]
    for user in users:
        ipa.user(user).add()

    power_users = ipa.group("power_users").add(description="Power users group")
    power_users.add_members([ipa.user("alice"), ipa.user("bob")])

    ipa.hbac("allow_all").disable()

    mixed_access_rule = ipa.hbac("mixed_access_rule").create(
        description="Mixed user and group access",
        users="charlie",
        groups="power_users",
        hosts="client.test",
        services="sshd",
    )

    alice_result = mixed_access_rule.test(user="alice", host="client.test", service="sshd")
    assert alice_result["access_granted"], "alice should have access via power_users group"

    bob_result = mixed_access_rule.test(user="bob", host="client.test", service="sshd")
    assert bob_result["access_granted"], "bob should have access via power_users group"

    charlie_result = mixed_access_rule.test(user="charlie", host="client.test", service="sshd")
    assert charlie_result["access_granted"], "charlie should have access as individual user"

    diana_result = mixed_access_rule.test(user="diana", host="client.test", service="sshd")
    assert not diana_result["access_granted"], "diana should be denied (not in rule)"

    client.sssd.restart()
    assert client.auth.ssh.password("alice", "Secret123"), "alice SSH should succeed"
    assert client.auth.ssh.password("bob", "Secret123"), "bob SSH should succeed"
    assert client.auth.ssh.password("charlie", "Secret123"), "charlie SSH should succeed"
    assert not client.auth.ssh.password("diana", "Secret123"), "diana SSH should fail"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_multiple_services(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with multiple services

    :setup:
      1. Add user: service_user to the IPA server.
      2. Disable the default HBAC rule `allow_all`.
      3. Create HBAC rule with multiple services.

    :steps:
      1. Create rule allowing user access to sshd and login services.
      2. Test access to allowed services (sshd, login).
      3. Test access to denied service (httpd).
      4. Add new service to existing rule.
      5. Test access to newly added service.

    :expectedresults:
      1. Rule created with multiple services successfully.
      2. User has access to specified services.
      3. User denied access to non-specified services.
      4. Service added to rule successfully.
      5. User gains access to newly added service.

    :customerscenario: False
    """
    ipa.user("service_user").add()
    ipa.hbac("allow_all").disable()

    multi_service_rule = ipa.hbac("multi_service_access").create(
        description="Multiple services access rule",
        users="service_user",
        hosts="client.test",
        services=["sshd", "login"],
    )

    sshd_result = multi_service_rule.test(user="service_user", host="client.test", service="sshd")
    assert sshd_result["access_granted"], "service_user should have sshd access"

    login_result = multi_service_rule.test(user="service_user", host="client.test", service="login")
    assert login_result["access_granted"], "service_user should have login access"

    httpd_result = multi_service_rule.test(user="service_user", host="client.test", service="httpd")
    assert not httpd_result["access_granted"], "service_user should be denied httpd access"

    ipa.hbacsvc("httpd").add(description="Apache HTTPD service")

    multi_service_rule.create(services="httpd")

    httpd_result_after = multi_service_rule.test(user="service_user", host="client.test", service="httpd")
    assert httpd_result_after["access_granted"], "service_user should now have httpd access"

    client.sssd.restart()
    assert client.auth.ssh.password("service_user", "Secret123"), "service_user SSH should succeed"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_nested_groups(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule with nested group membership

    :setup:
      1. Add users: dev1, dev2, qa1, qa2 to the IPA server.
      2. Create groups: developers, qa_team, engineering
      3. Add users to respective groups and create nested structure.
      4. Disable the default HBAC rule `allow_all`.

    :steps:
      1. Create nested group structure (engineering contains developers and qa_team).
      2. Create HBAC rule allowing engineering group access.
      3. Test access for users in nested groups.
      4. Test access for users not in engineering hierarchy.

    :expectedresults:
      1. Nested group structure created successfully.
      2. HBAC rule created for parent group.
      3. Users in nested groups have access via group hierarchy.
      4. Users outside hierarchy are denied access.

    :customerscenario: False
    """
    users = ["dev1", "dev2", "qa1", "qa2", "manager1"]
    for user in users:
        ipa.user(user).add()

    developers = ipa.group("developers").add(description="Development team")
    qa_team = ipa.group("qa_team").add(description="QA team")
    engineering = ipa.group("engineering").add(description="Engineering department")

    developers.add_members([ipa.user("dev1"), ipa.user("dev2")])
    qa_team.add_members([ipa.user("qa1"), ipa.user("qa2")])

    engineering.add_members([developers, qa_team])

    ipa.hbac("allow_all").disable()

    engineering_access_rule = ipa.hbac("engineering_access").create(
        description="Engineering department access", groups="engineering", hosts="client.test", services="sshd"
    )

    dev1_result = engineering_access_rule.test(user="dev1", host="client.test", service="sshd")
    assert dev1_result["access_granted"], "dev1 should have access via developers->engineering"

    qa1_result = engineering_access_rule.test(user="qa1", host="client.test", service="sshd")
    assert qa1_result["access_granted"], "qa1 should have access via qa_team->engineering"

    manager_result = engineering_access_rule.test(user="manager1", host="client.test", service="sshd")
    assert not manager_result["access_granted"], "manager1 should be denied (not in engineering hierarchy)"

    client.sssd.restart()
    assert client.auth.ssh.password("dev1", "Secret123"), "dev1 SSH should succeed"
    assert client.auth.ssh.password("qa1", "Secret123"), "qa1 SSH should succeed"
    assert not client.auth.ssh.password("manager1", "Secret123"), "manager1 SSH should fail"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_status_and_contains_methods(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule status and contains methods

    :setup:
      1. Add users and create HBAC rule with various components.
      2. Test framework's status and contains methods.

    :steps:
      1. Create comprehensive HBAC rule.
      2. Test status() method returns summary and membership info.
      3. Test contains() method for checking rule components including negatives.
      4. Test contains() with multiple parameters to verify logical intersections.

    :expectedresults:
      1. Rule created with all components.
      2. status() method returns accurate summary information.
      3. contains() correctly identifies existing and missing components.
      4. contains() behaves correctly with multiple checks.

    :customerscenario: False
    """
    test_user = ipa.user("test_user").add()
    ipa.user("other_user").add()
    test_group = ipa.group("test_group").add()
    test_group.add_member(test_user)

    comprehensive_rule = ipa.hbac("comprehensive_test_rule").create(
        description="Comprehensive rule for testing framework methods",
        users="test_user",
        groups="test_group",
        hosts="client.test",
        services="sshd",
    )

    rule_status = comprehensive_rule.status(include_members=True)
    assert get_attr(rule_status, "name") == "comprehensive_test_rule"
    assert get_attr(rule_status, "enabled") is True
    assert "test_user" in get_attr(rule_status, "members.users")
    assert "test_group" in get_attr(rule_status, "members.user_groups")
    assert "client.test" in get_attr(rule_status, "members.hosts")
    assert "sshd" in get_attr(rule_status, "members.services")

    assert comprehensive_rule.contains(user="test_user") is True
    assert comprehensive_rule.contains(user="other_user") is False
    assert comprehensive_rule.contains(group="test_group") is True
    assert comprehensive_rule.contains(group="nonexistent_group") is False
    assert comprehensive_rule.contains(host="client.test") is True
    assert comprehensive_rule.contains(service="sshd") is True
    assert comprehensive_rule.contains(service="httpd") is False

    assert comprehensive_rule.contains(user="test_user", host="client.test") is True
    assert comprehensive_rule.contains(user="other_user", service="httpd") is False
    assert comprehensive_rule.contains(group="test_group", service="sshd") is True


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_conflict_resolution(client: Client, ipa: IPA):
    """
    :title: Validate HBAC rule conflict and priority handling

    :setup:
      1. Add users: priority_user to the IPA server.
      2. Disable the default HBAC rule `allow_all`.
      3. Create multiple overlapping rules.

    :steps:
      1. Create restrictive rule denying access to specific service.
      2. Create permissive rule allowing broader access.
      3. Test which rule takes precedence.
      4. Modify rule priorities and retest.

    :expectedresults:
      1. Multiple overlapping rules created.
      2. Rule evaluation follows IPA's precedence logic.
      3. More specific rules or explicit allows take precedence.
      4. Rule modifications affect access decisions.

    :customerscenario: False
    """
    ipa.user("priority_user").add()
    ipa.hbac("allow_all").disable()

    permissive_rule = ipa.hbac("permissive_ssh_rule").create(
        description="Permissive rule allowing SSH access", users="priority_user", hosts="client.test", services="sshd"
    )

    single_rule_result = permissive_rule.test(user="priority_user", host="client.test", service="sshd")
    assert single_rule_result["access_granted"], "priority_user should have access with permissive rule"

    additional_rule = ipa.hbac("additional_ssh_rule").create(
        description="Additional SSH rule for same user", users="priority_user", hosts="client.test", services="sshd"
    )

    multiple_rules_result = permissive_rule.test(user="priority_user", host="client.test", service="sshd")
    assert multiple_rules_result["access_granted"], "priority_user should have access with multiple permissive rules"
    assert len(multiple_rules_result["matched_rules"]) >= 1, "At least one rule should match"

    client.sssd.restart()
    assert client.auth.ssh.password("priority_user", "Secret123"), "priority_user SSH should succeed"

    permissive_rule.disable()
    client.sssd.restart()

    assert client.auth.ssh.password(
        "priority_user", "Secret123"
    ), "priority_user SSH should still work via second rule"

    additional_rule.disable()
    client.sssd.restart()

    assert not client.auth.ssh.password("priority_user", "Secret123"), "priority_user SSH should fail with all rules"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__validate_hbac_rule_external_users_denied(client: Client, ipa: IPA):
    """
    :title: Validate that external users are properly handled in HBAC rules.

    :setup:
      1. Add IPA users: ipauser1, ipauser2.
      2. Create external group (simulated).
      3. Create HBAC rule with IPA group and attempt to add external group.

    :steps:
      1. Verify IPA users have access via HBAC rule.
      2. Verify external user do not gain access via HBAC.

    :expectedresults:
      1. IPA users have access.
      2. External user do not get access (ignored by HBAC).

    :customerscenario: False
    """
    users = ["ipauser1", "ipauser2"]
    for user in users:
        ipa.user(user).add()

    ipa.group("external_ad_users").add(external=True)

    ipa.hbac("allow_all").disable()

    rule = ipa.hbac("mixed_group_rule").create(
        description="Mixed IPA and external groups",
        groups=["ipausers", "external_ad_users"],
        hosts="client.test",
        services="sshd",
    )
    client.sssd.restart()

    for user in users:
        hbactest_result = rule.test(user=user, host="client.test", service="sshd")
        access_granted = get_attr(hbactest_result, "Access granted") or get_attr(hbactest_result, "access_granted")
        assert access_granted in ["True", True], f"{user} should have HBAC access"

    external_user = "aduser1@ad.example.com"
    hbactest_external = rule.test(user=external_user, host="client.test", service="sshd")
    external_access = get_attr(hbactest_external, "Access granted") or get_attr(hbactest_external, "access_granted")
    assert external_access in [False, "False", None], "External user should NOT have HBAC access"

    for user in users:
        assert client.auth.ssh.password(user, "Secret123"), f"{user} SSH authentication should succeed"
