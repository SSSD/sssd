"""
SSSD Configuration-related Test Cases

:requirement: IDM-SSSD-REQ: Configuration merging
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_config__change_config_while_sssd_running(client: Client):
    """
    :title: Re-generate config while SSSD is running
    :setup:
        1. In pam domain set "debug_level" to 9
        2. Start SSSD
    :steps:
        1. Check that "debug_level" in pam domain is 9
        2. Change "debug_level" in pam to 1
        3. Apply config changes
        4. Call "sssd --genconf"
        5. Check that "debug_level" in pam is 1
    :expectedresults:
        1. "debug_level" is set to 9
        2. "debug_level" is changed successfully
        3. Changes are apllied successfully
        4. "sssd --genconf" is called successfully
        5. "debug_level" is set to 1
    :customerscenario: False
    """
    client.sssd.pam["debug_level"] = "9"
    client.sssd.start()

    result = client.ldb.search("/var/lib/sss/db/config.ldb", "cn=pam,cn=config")
    assert result["cn=pam,cn=config"]["debug_level"] == ["9"]

    client.sssd.pam["debug_level"] = "1"
    client.sssd.config_apply()
    client.sssd.genconf()

    result = client.ldb.search("/var/lib/sss/db/config.ldb", "cn=pam,cn=config")
    assert result["cn=pam,cn=config"]["debug_level"] == ["1"]


@pytest.mark.importance("critical")
@pytest.mark.config
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_config__genconf_particular_section(client: Client):
    """
    :title: Re-generate only particular section in config while SSSD is running
    :setup:
        1. In pam domain set "debug_level" to 9
        2. In nss domain set "debug_level" to 9
        3. Start SSSD
    :steps:
        1. Check that "debug_level" in pam domain is 9
        2. Check that "debug_level" in nss domain is 9
        3. Change "debug_level" in pam and in nss to 1
        4. Apply config changes
        5. Call "sssd --genconf-section==pam"
        6. Check that "debug_level" in pam is 1
        7. Check that "debug_level" in nss remained 9
    :expectedresults:
        1. "debug_level" is set to 9
        2. "debug_level" is set to 9
        3. "debug_level" is changed successfully
        4. Changes are apllied successfully
        5. "sssd --genconf-section==pam" is called successfully
        6. "debug_level" in pam is 1
        7. "debug_level" in nss remains 9
    :customerscenario: False
    """
    client.sssd.pam["debug_level"] = "9"
    client.sssd.nss["debug_level"] = "9"
    client.sssd.start()

    result = client.ldb.search("/var/lib/sss/db/config.ldb")
    assert result["cn=pam,cn=config"]["debug_level"] == ["9"]
    assert result["cn=nss,cn=config"]["debug_level"] == ["9"]

    client.sssd.pam["debug_level"] = "1"
    client.sssd.nss["debug_level"] = "1"
    client.sssd.config_apply()

    client.sssd.genconf("pam")

    result = client.ldb.search("/var/lib/sss/db/config.ldb")
    assert result["cn=pam,cn=config"]["debug_level"] == ["1"]
    assert result["cn=nss,cn=config"]["debug_level"] == ["9"]


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_config__add_remove_section(client: Client):
    """
    :title: Add and remove new section to config file
        with --genconf-section while SSSD is running
    :setup:
        1. In pam domain set "debug_level" to 9
        2. In nss domain set "debug_level" to 9
        3. Start SSSD
    :steps:
        1. Check that "debug_level" in pam and nss is 9
        2. Add new section to config with key, value pair set
        3. Apply config changes
        4. Call "sssd --genconf-section==$newSection"
        5. Check that the new section is properly set
        6. Remove new section
        7. Call "sssd --genconf-section==$newSection"
        8. Check that the new section was deleted
        9. Check that "debug_level" in pam and nss is 9
    :expectedresults:
        1. "debug_level" is set to 9 in both domains
        2. Added successfully
        3. New configuration was written
        4. Changes are applied successfully
        5. "sssd --genconf-section==$newSection" is called successfully
        6. New section is removed successfully
        7. "sssd --genconf-section==$newSection" is called successfully
        8. New section was deleted correctly
        9. "debug_level" in pam and nss remained 9
    :customerscenario: False
    """
    client.sssd.pam["debug_level"] = "9"
    client.sssd.nss["debug_level"] = "9"
    client.sssd.start()

    result = client.ldb.search("/var/lib/sss/db/config.ldb")
    assert result["cn=pam,cn=config"]["debug_level"] == ["9"]
    assert result["cn=nss,cn=config"]["debug_level"] == ["9"]

    client.sssd.config["new_section"] = {"key": "value"}
    client.sssd.config_apply(check_config=False)
    client.sssd.genconf("new_section")

    result = client.ldb.search("/var/lib/sss/db/config.ldb", "cn=new_section,cn=config")
    assert result["cn=new_section,cn=config"]["key"] == ["value"]

    del client.sssd.config["new_section"]

    client.sssd.config_apply()
    client.sssd.genconf("new_section")

    result = client.ldb.search("/var/lib/sss/db/config.ldb")
    assert result["cn=pam,cn=config"]["debug_level"] == ["9"]
    assert result["cn=nss,cn=config"]["debug_level"] == ["9"]
    with pytest.raises(KeyError):
        assert result["cn=new_section,cn=config"]["key"] != ["value"]


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_config__genconf_no_such_section(client: Client):
    """
    :title: genconf-section with nonexisting section did not fail
    :setup:
        1. Start SSSD
    :steps:
        1. Call 'sssd --genconf-section=$nonexistingSection'
    :expectedresults:
        1. Call did not fail
    :customerscenario: False
    """
    client.sssd.start()
    result = client.sssd.genconf("nonexistingSection")
    assert result.rc == 0
    assert not result.stderr
