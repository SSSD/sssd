"""
SUDO responder tests.

:requirement: sudo
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider, GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_sudo__user_allowed(client: Client, provider: GenericProvider, sssd_service_user: str):
    """
    :title: One user is allowed to run command, other user is not
    :setup:
        1. Create user "user-1"
        2. Create user "user-2"
        3. Create sudorule to allow "user-1" run "/bin/ls on all hosts
        4. Enable SSSD sudo responder
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
        2. Run "sudo /bin/ls root" as user-1
        3. List sudo rules for "user-2"
        4. Run "sudo /bin/ls root" as user-2
    :expectedresults:
        1. User is able to run /bin/ls as root
        2. Command is successful
        3. User is not able to run /bin/ls as root
        4. Command failed
    :customerscenario: False
    """
    u = provider.user("user-1").add()
    provider.user("user-2").add()
    provider.sudorule("test").add(user=u, host="ALL", command="/bin/ls")

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/ls"])
    assert client.auth.sudo.run("user-1", "Secret123", command="/bin/ls /root")

    assert not client.auth.sudo.list("user-2", "Secret123")
    assert not client.auth.sudo.run("user-2", "Secret123", command="/bin/ls /root")


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
def test_sudo__duplicate_sudo_user(client: Client, provider: GenericProvider):
    """
    :title: User is mentioned twice in sudoUser attribute, once with shortname and once with fully qualified name
    :setup:
        1. Create users "user-1", "user-2", "user-3", "user-4"
        3. Create sudorule to allow "user-1", "user-2", "user-2@test", "user-3" run "/bin/ls on all hosts
        4. Enable SSSD sudo responder
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1", "user-2", "user-3"
        2. Run "sudo /bin/ls root" as "user-1", "user-2", "user-3"
        3. List sudo rules for "user-4"
        4. Run "sudo /bin/ls root" as "user-4"
    :expectedresults:
        1. User is able to run /bin/ls as root
        2. Command is successful
        3. User is not able to run /bin/ls as root
        4. Command failed
    :customerscenario: False

    Note: This test can not run on IPA since it will not allow this case to happen.
    """
    provider.user("user-1").add()
    provider.user("user-2").add()
    provider.user("user-3").add()
    provider.user("user-4").add()
    provider.sudorule("test").add(
        user=["user-1", "user-2", f"user-2@{client.sssd.default_domain}", "user-3"], host="ALL", command="/bin/ls"
    )

    client.sssd.common.sudo()
    client.sssd.start()

    # Try several users to make sure we don't mangle the list
    for user in ["user-1", "user-2", "user-3"]:
        assert client.auth.sudo.list(user, "Secret123", expected=["(root) /bin/ls"])
        assert client.auth.sudo.run(user, "Secret123", command="/bin/ls /root")

    assert not client.auth.sudo.list("user-4", "Secret123")
    assert not client.auth.sudo.run("user-4", "Secret123", command="/bin/ls /root")


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.ticket(bz=1380436, gh=4236)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_sudo__case_sensitive_false(client: Client, provider: GenericProvider):
    """
    :title: Sudo rules work correctly for case insensitive domains
    :setup:
        1. Create user "USER-1"
        2. Create sudorule to allow "user-1" run "/bin/less on all hosts
        3. Create sudorule to allow "USER-1" run "/bin/more on all hosts
        4. Enable SSSD sudo responder
        5. Set "case_sensitive" to "false"
        6. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
        2. Run "sudo /bin/less root" as user-1
        3. Run "sudo /bin/more root" as user-1
        4. List sudo rules for "USER-1"
        5. Run "sudo /bin/less root" as USER-1
        6. Run "sudo /bin/more root" as USER-1
    :expectedresults:
        1. User is able to run /bin/less and /bin/more as root
        2. Command is successful
        3. Command is successful
        4. User is able to run /bin/less and /bin/more as root
        5. Command is successful
        6. Command is successful
    :customerscenario: False
    """
    provider.user("USER-1").add()
    provider.sudorule("lowercase").add(user="user-1", host="ALL", command="/bin/less")
    provider.sudorule("uppsercase").add(user="USER-1", host="ALL", command="/bin/more")
    client.fs.write("/root/test", "test")

    client.sssd.common.sudo()
    client.sssd.domain["case_sensitive"] = "false"
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/less", "(root) /bin/more"])
    assert client.auth.sudo.run("user-1", "Secret123", command="/bin/less /root/test")
    assert client.auth.sudo.run("user-1", "Secret123", command="/bin/more /root/test")

    assert client.auth.sudo.list("USER-1", "Secret123", expected=["(root) /bin/less", "(root) /bin/more"])
    assert client.auth.sudo.run("USER-1", "Secret123", command="/bin/less /root/test")
    assert client.auth.sudo.run("USER-1", "Secret123", command="/bin/more /root/test")


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_sudo__rules_refresh(client: Client, provider: GenericProvider, sssd_service_user: str):
    """
    :title: Sudo rules refresh works
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run "/bin/ls on all hosts
        3. Enable SSSD sudo responder
        4. Set "entry_cache_sudo_timeout" to "2"
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
        2. Modify the rule to allow only "/bin/less" command
        3. Wait until the cached rule is expired (3 seconds)
        4. List sudo rules for "user-1"
    :expectedresults:
        1. User is able to run only /bin/ls
        2. Rule was modified
        3. Time passed
        4. User is bale to run only /bin/less
    :customerscenario: False
    """
    u = provider.user("user-1").add()
    r = provider.sudorule("test").add(user=u, host="ALL", command="/bin/ls")

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.common.sudo()
    client.sssd.domain["entry_cache_sudo_timeout"] = "2"
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/ls"])
    r.modify(command="/bin/less")
    time.sleep(3)
    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/less"])


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.ticket(bz=1372440, gh=4236)
@pytest.mark.contains_workaround_for(gh=4483)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_sudo__sudo_user_is_group(client: Client, provider: GenericProvider):
    """
    :title: POSIX groups can be set in sudoUser attribute
    :setup:
        1. Create user "user-1"
        2. Create group "group-1" with "user-1" as a member
        3. Create sudorule to allow "group-1" run "/bin/ls on all hosts
        4. Enable SSSD sudo responder
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
        2. Run "sudo /bin/ls" as "user-1"
    :expectedresults:
        1. User is able to run only /bin/ls
        2. Command is successful
    :customerscenario: False
    """
    u = provider.user("user-1").add()
    g = provider.group("group-1").add().add_member(u)
    provider.sudorule("test").add(user=g, host="ALL", command="/bin/ls")

    client.sssd.common.sudo()
    client.sssd.start()

    # Until https://github.com/SSSD/sssd/issues/4483 is resolved
    # Running 'id user-1' will resolve SIDs into group names
    if isinstance(provider, (AD, Samba)):
        client.tools.id("user-1")

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/ls"])
    assert client.auth.sudo.run("user-1", "Secret123", command="/bin/ls /root")


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.ticket(bz=1826272, gh=5119)
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_sudo__sudo_user_is_nonposix_group(client: Client, provider: GenericADProvider):
    """
    :title: Non-POSIX groups can be set in sudoUser attribute
    :setup:
        1. Create user "user-1"
        2. Create group "group-1" with "user-1" as a member
        3. Create sudorule to allow "group-1" run "/bin/ls on all hosts
        4. Enable SSSD sudo responder
        5. Disable ldap_id_mapping
        6. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
        2. Run "sudo /bin/ls" as "user-1"
    :expectedresults:
        1. User is able to run only /bin/ls
        2. Command is successful
    :customerscenario: False
    """
    u = provider.user("user-1").add(uid=10001, gid=10001)
    g = provider.group("group-1").add().add_member(u)
    provider.sudorule("test").add(user=g, host="ALL", command="/bin/ls")

    client.sssd.common.sudo()
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/ls"])
    assert client.auth.sudo.run("user-1", "Secret123", command="/bin/ls /root")


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.ticket(bz=1910131)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_sudo__runasuser_shortname(client: Client, provider: GenericADProvider):
    """
    :title: sudoRunAsUser contains shortname
    :setup:
        1. Create user "user-1"
        2. Create user "user-2"
        3. Create sudorule to allow "user-1" run "/bin/ls on all hosts as "user-2" using shortname
        4. Enable SSSD sudo responder
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
    :expectedresults:
        1. User is able to run /bin/ls as "user-2"
    :customerscenario: True
    """
    u1 = provider.user("user-1").add()
    provider.user("user-2").add()
    provider.sudorule("test").add(user=u1, host="ALL", command="/bin/ls", runasuser="user-2")

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(user-2) /bin/ls"])


@pytest.mark.importance("critical")
@pytest.mark.authorization
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
def test_sudo__runasuser_fqn(client: Client, provider: GenericProvider):
    """
    :title: sudoRunAsUser contains fully qualified name
    :setup:
        1. Create user "user-1"
        2. Create user "user-2"
        3. Create sudorule to allow "user-1" run "/bin/ls on all hosts as "user-2" using fully qualified name
        4. Enable SSSD sudo responder
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
    :expectedresults:
        1. User is able to run /bin/ls as "user-2"
    :customerscenario: False

    Note: This test can not run on IPA since it does not allow fully qualified name here.
    """
    u1 = provider.user("user-1").add()
    provider.user("user-2").add()
    provider.sudorule("test").add(
        user=u1, host="ALL", command="/bin/ls", runasuser=f"user-2@{client.sssd.default_domain}"
    )

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(user-2) /bin/ls"])


@pytest.mark.importance("low")
@pytest.mark.authorization
@pytest.mark.topology(KnownTopology.LDAP)
def test_sudo__sudonotbefore_shorttime(client: Client, provider: LDAP):
    """
    Test that suduNotBefore and sudoNotAfter works even without minutes and
    seconds specifier.

    :title: sudoNotBefore and sudoNotAfter do not require minutes and seconds
    :setup:
        1. Create user "user-1"
        2. Create sudorule to allow "user-1" run "/bin/ls on all hosts within given time in %Y%m%d%H format
        3. Enable SSSD sudo responder
        4. Set "sudo_timed" to "true"
        5. Start SSSD
    :steps:
        1. List sudo rules for "user-1"
    :expectedresults:
        1. User is able to run /bin/ls within given time
    :customerscenario: False

    Note: IPA does not support these attributes and AD/Samba time schema
    requires minutes and seconds to be set. Therefore this test only applies to
    LDAP.
    """

    def shorttime(t: datetime) -> str:
        return t.strftime("%Y%m%d%H") + "Z"

    def fulltime(t: datetime) -> str:
        return t.strftime("%Y%m%d%H%M%S") + "Z"

    now = datetime.today().replace(minute=0, second=0, microsecond=0)
    notbefore = now - timedelta(days=1)
    notafter = now + timedelta(days=1)

    u = provider.user("user-1").add()
    provider.sudorule("test").add(
        user=u,
        host="ALL",
        command="/bin/ls",
        notbefore=shorttime(datetime.today() - timedelta(days=1)),
        notafter=shorttime(datetime.today() + timedelta(days=1)),
    )

    client.sssd.common.sudo()
    client.sssd.sudo["sudo_timed"] = "true"
    client.sssd.start()

    assert client.auth.sudo.list(
        "user-1",
        "Secret123",
        expected=[f"(root) NOTBEFORE={fulltime(notbefore)} NOTAFTER={fulltime(notafter)} /bin/ls"],
    )


@pytest.mark.importance("low")
@pytest.mark.authorization
@pytest.mark.slow(seconds=15)
@pytest.mark.ticket(bz=1925514, gh=5609)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_sudo__refresh_random_offset(client: Client):
    """
    :title: Random offset is applied to sudo full and smart refresh.
    :setup:
        1. Set ldap_sudo_full_refresh_interval to 2
        2. Set ldap_sudo_smart_refresh_interval to 1
        3. Set ldap_sudo_random_offset to 5
        4. Start SSSD
    :steps:
        1. Grep domain log to see when the full refresh was scheduled
        2. Grep domain log to see when the smart refresh was scheduled
    :expectedresults:
        1. It was scheduled to multiple random times
        2. It was scheduled to multiple random times
    :customerscenario: True
    """
    client.sssd.domain.update(
        ldap_sudo_full_refresh_interval="2",
        ldap_sudo_smart_refresh_interval="1",
        ldap_sudo_random_offset="5",
    )
    client.sssd.start()
    time.sleep(15)
    log = client.fs.read(client.sssd.logs.domain())
    smart = set()
    full = set()
    for m in re.findall(r"Task \[SUDO (Smart|Full).*\]: scheduling task (\d+) seconds", log):
        match m[0]:
            case "Smart":
                smart.add(m[1])
            case "Full":
                full.add(m[1])

    assert len(smart) > 1
    assert len(full) > 1


@pytest.mark.importance("low")
@pytest.mark.authorization
@pytest.mark.slow(seconds=10)
@pytest.mark.ticket(bz=1925505, gh=5604)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize(["full_interval", "smart_interval"], [(2, 1), (3, 2)])
def test_sudo__prefer_full_refresh_over_smart_refresh(client: Client, full_interval: int, smart_interval: int):
    """
    :title: Sudo smart refresh does not occur at the same time as full refresh
    :setup:
        1. Set ldap_sudo_full_refresh_interval to @full_interval
        2. Set ldap_sudo_smart_refresh_interval to @smart_interval
        3. Set ldap_sudo_random_offset to 0
        4. Start SSSD
    :steps:
        1. Sleep for 10 seconds
        2. Grep domain log to see when the smart and full refresh happened
    :expectedresults:
        1. Time passed
        2. Smart refresh does not occur at the same time as full refresh
    :customerscenario: True
    """

    def is_task_start(task: str, line: str) -> bool:
        return f"Task [{task}]: executing task" in line

    def is_task_end(task: str, line: str) -> bool:
        return f"Task [{task}]: finished successfully" in line or f"Task [{task}]: failed" in line

    def is_smart_skipped(line: str) -> bool:
        return "Skipping smart refresh because there is ongoing full refresh." in line

    client.sssd.domain.update(
        ldap_sudo_full_refresh_interval=str(full_interval),
        ldap_sudo_smart_refresh_interval=str(smart_interval),
        ldap_sudo_random_offset="0",
    )
    client.sssd.start()
    time.sleep(10)
    log = client.fs.read(client.sssd.logs.domain())

    expect_skip = False
    inside_full = False
    is_skipped = False

    # Check that
    # - Either there is no smart refresh executed inside a full refresh
    # - Or the smart refresh was skipped
    for line in log.splitlines():
        if is_task_start("SUDO Full Refresh", line):
            inside_full = True

        if is_task_end("SUDO Full Refresh", line):
            inside_full = False

        if is_task_start("SUDO Smart Refresh", line):
            is_skipped = False
            if inside_full:
                expect_skip = True

        if is_task_end("SUDO Smart Refresh", line):
            assert not expect_skip or is_skipped
            is_skipped = False
            expect_skip = False

        if is_smart_skipped(line):
            is_skipped = True


@pytest.mark.importance("high")
@pytest.mark.authorization
@pytest.mark.ticket(bz=1294670, gh=3969)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_sudo__local_users_negative_cache(client: Client, provider: LDAP, sssd_service_user: str):
    """
    :title: Sudo responder hits negative cache for local users
    :setup:
        1. Create local user "user-1"
        2. Add local rule to /etc/sudoers to allow all commands for "user-1"
        3. Enable sudo responder
        4. Set entry_negative_timeout to 0 to disable standard negative cache
        5. Start SSSD
    :steps:
        1. Authenticate as "user-1" over SSH
        2. Run "sudo /bin/ls /root"
        3. Start tcpdump to capture ldap packets and run "sudo /bin/ls /root" multiple times again
    :expectedresults:
        1. User is logged into the host
        2. Command is successful, user is stored in negative cache for local users
        3. No ldap packets for "user-1" user resolution are sent
    :customerscenario: True

    First sudo goes through SSSD to lookup up the user in LDAP, since it is not
    there and the user is local, it is stored in negative cache with very long
    expiration time. Subsequent sudo requests will hit the negative cache and no
    further lookup is performed.
    """
    client.local.user("user-1").add()
    client.fs.write("/etc/sudoers.d/test", "user-1 ALL=(ALL) NOPASSWD:ALL")

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.common.sudo()
    client.sssd.nss.update(
        entry_negative_timeout="0",  # disable standard negative cache to make sure we hit the local user case
    )
    client.sssd.start()

    # Now there should be no query
    with client.ssh("user-1", "Secret123") as ssh:
        ssh.exec(["sudo", "/bin/ls", "/root"])

        with client.tools.tcpdump("/tmp/sssd.pcap", ["-s0", "host", provider.host.hostname]):
            ssh.exec(["sudo", "/bin/ls", "/root"])
            ssh.exec(["sudo", "/bin/ls", "/root"])

    result = client.tools.tshark(["-r", "/tmp/sssd.pcap", "-V", "-2", "-R", "ldap.filter"])
    assert "uid=user-1" not in result.stdout
