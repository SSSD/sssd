"""
IPA Tests
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


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
    :requirement: subids
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
def test_ipa__check_gssapi_authentication_indicator_apply(client: Client, ipa: IPA):
    """
    :title: Check logs for authentication indicators from PAC
    :description:
        Checks the assignment of SIDs from the PAC to authentication indicators
    :setup:
        1. Create a user and a group and make the user a member of the group
        2. Configure SSSD for sudo and gssapi, require 'pkinit' authentication
           indicator for 'sudo' services and assign a non-exiting SID to 'pkinit'
        3. Create sudo rule for the user
    :steps:
        1. Login as the test user and obtain ticket
        2. Try 'sudo -l' as user
        3. Check if acquired service ticket has indicators: 1 (denied) in sssd_pam.log
        4. Update config by assigning the SID of the new group to 'otp' and restart sssd
        5. Login as the test user and obtain a new ticket
        6. Try 'sudo -l' as user
        7. Check if acquired service ticket has indicators: 1 (denied) in sssd_pam.log
        8. Update config by assigning the SID of the new group to 'pkinit' and restart sssd
        9. Login as the test user and obtain a new ticket
       10. Try 'sudo -l' as user
       11. Check if acquired service ticket has indicators: 0 (success) in sssd_pam.log
    :expectedresults:
        1. Login successful and ticket obtained
        2. "Sudo -l" should fail
        3. "indicators: 1" should be there in the sssd_pam.log
        4. Configuration is updated and SSSD is restarted
        5. Login successful and new ticket obtained
        6. "Sudo -l" should fail
        7. "indicators: 1" should be there in the sssd_pam.log
        8. Configuration is updated and SSSD is restarted
        9. Login successful and new ticket obtained
       10. "Sudo -l" should show the expected allowed command
       11. "indicators: 0" should be there in the sssd_pam.log
    :customerscenario: True
    :requirement: authentication indicators
    """
    user = ipa.user("user-1").add(password="Secret123")
    password = "Secret123"

    group = ipa.group("group1").add().add_member(user)
    res = group.get(["ipaNTSecurityIdentifier"])
    assert res is not None, "Missing ipaNTSecurityIdentifier!"
    group_sid = res["ipaNTSecurityIdentifier"][0]

    # In future some other string replacement module may be created, for now generic sed module is used.
    for path in ["/etc/pam.d/sudo", "/etc/pam.d/sudo-i"]:
        client.fs.sed(path=path, command="2s/^/auth sufficient pam_sss_gss.so debug\\n/", args=["-i"])

    ipa.sudorule("testrule").add(user=user.name, host="ALL", command="/bin/my_precious")

    client.sssd.common.sudo()

    # wrong SID, expected authentication indicator
    client.sssd.config["pam"] = {
        "pam_gssapi_services": "sudo, sudo-i",
        "pam_gssapi_indicators_map": "sudo:pkinit, sudo-i:pkinit",
        "pam_gssapi_indicators_apply": "SID:S-1-5-21-12345-23456-34567-1234:pkinit",
    }
    client.sssd.start()

    with client.ssh(user.name, password) as ssh:
        ssh.run(f"kinit {user.name}@{ipa.host.realm}", input=password)
        ssh.run("klist")
        ssh.disconnect()
    assert not client.auth.sudo.list(user.name, expected=["(root) /bin/my_precious"]), "Sudo list did not fail!"
    time.sleep(3)
    log1 = client.fs.read(client.sssd.logs.pam)
    assert "indicators: 1" in log1, "String `indicators: 1` not found in logs!"

    # expected SID, wrong authentication indicator
    client.sssd.config["pam"] = {
        "pam_gssapi_services": "sudo, sudo-i",
        "pam_gssapi_indicators_map": "sudo:pkinit, sudo-i:pkinit",
        "pam_gssapi_indicators_apply": f"SID:{group_sid}:otp",
    }
    client.sssd.clear(logs=False)
    client.sssd.start()

    with client.ssh(user.name, password) as ssh:
        ssh.run(f"kinit {user.name}@{ipa.host.realm}", input=password)
        ssh.run("klist")
        ssh.disconnect()
    assert not client.auth.sudo.list(user.name, expected=["(root) /bin/my_precious"]), "Sudo list did not fail!"
    time.sleep(3)
    log1 = client.fs.read(client.sssd.logs.pam)
    assert "indicators: 1" in log1, "String `indicators: 1` not found in logs!"

    # expected SID, expected authentication indicator
    client.sssd.config["pam"] = {
        "pam_gssapi_services": "sudo, sudo-i",
        "pam_gssapi_indicators_map": "sudo:pkinit, sudo-i:pkinit",
        "pam_gssapi_indicators_apply": f"SID:{group_sid}:pkinit",
    }
    client.sssd.clear(logs=False)
    client.sssd.restart()

    with client.ssh(user.name, password) as ssh:
        ssh.run(f"kinit {user.name}@{ipa.host.realm}", input=password)
        ssh.run("klist")
        ssh.disconnect()
    assert client.auth.sudo.list(user.name, expected=["(root) /bin/my_precious"]), "Sudo list failed!"
    time.sleep(3)
    log2 = client.fs.read(client.sssd.logs.pam)
    assert "indicators: 0" in log2, "String `indicators: 0` not found in logs!"
