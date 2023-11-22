"""
IPA tests.

:requirement: ipa
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.ticket(jira="RHEL-14427")
def test_cn_in_rdn(client: Client, ipa: IPA):
    """
    :title: Expected cn in RDN, got uid
    :setup:
    `   1. Configure sssd with debug_level = 1.
        2. Create 2 users.
        3. Create hback rule.
        4. Add the rule for one user.
    :steps:
        1. Ssh to client machine with another user that was not added to hback rule.
        2. Check logs for "Expected cn in RDN".
    :expectedresults:
        1. Ssh should success.
        2. Log should not be there.
    :customerscenario: True
    """
    client.sssd.start()
    client.sssd.domain["debug_level"] = "1"
    client.sssd.config_apply(check_config=False)

    user_bob = ipa.user("bob").add(password="Secret123")
    user_alice = ipa.user("alice").add(password="Secret123")
    ipa.sssd.clear(db=True, memcache=True, logs=True)

    ipa.host.ssh.run("ipa hbacrule-add --hostcat=all foobar0-allow")
    ipa.host.ssh.run(f"ipa hbacrule-add-user --users {user_bob.name} foobar0-allow")
    client.auth.su.password(user_alice.name, "Secret123")

    time.sleep(3)
    log = client.fs.read(client.sssd.logs.domain())
    assert "Expected cn in RDN" not in log
