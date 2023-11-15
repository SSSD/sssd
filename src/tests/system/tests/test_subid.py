"""
Automation of IPA subid feature bugs.

:requirement: ipa subid range
"""

from __future__ import annotations

import pytest
from pytest_mh.ssh import SSHProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.mark.ticket(bz=2249524)
@pytest.mark.topology(KnownTopology.IPA)
def test_subid__add_local_user(client: Client, ipa: IPA):
    """
    :title: Given a FreeIPA domain managing subids, add a local user
    :setup:
        1. Enable "subid" feature in authselect
    :steps:
        1. Add local user
        2. Remove local user
    :expectedresults:
        1. User added successfully
        2. User removed successfully
    :customerscenario: False
    """
    client.authselect.enable_feature(["with-subid"])

    try:
        u = client.local.user("tuser").add()
        u.delete()
    except SSHProcessError as e:
        pytest.fail(f"Exception shouldn't be raised but we got the following error: '{e.stderr}'")
