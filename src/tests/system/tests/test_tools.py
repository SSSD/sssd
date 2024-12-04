"""
Tools Tests.

Tests pertaining to command line tools, some tools will have their own file.

* sssctl: test_sssctl.py
* sss_cache
* sss_obfuscate
* sss_seed
* sss_debuglevel
* sss_override: sss_override.py
* sss_ssh_authorizedkeys
* sss_ssh_knownhostsproxy

:requirement: Tools
"""

from __future__ import annotations

import pytest
from pytest_mh.conn import ProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

bash
====
# sss_obfuscate
?:sss obfuscate command requires a domain name
?:help option of sss obfuscate command
?:sss obfuscate ENTER enter password
?:sss obfuscate hyphen s option reading the password from stdin
?:non default input in sssd conf file
?:Hyphen d option the domain to use the password in
?:Domain already had ldap default authtok type as password
?:SSSD with multiple domains
?:sss obfuscate to a incorrect domain
?:sss obfuscate to nss domain special domain
?:Manually added a base64 encoded password
?:Setting cleartext password while authtok type is obfuscated
?:sss obfuscate for proxy providers
?:Resetting binddn password and updating obfuscated password
?:sss obfuscate command as normal non root user
?:sss obfuscate command as normal non root user with hyphen f option and user has permissions
?:One existing domain is the default domain
?:Renaming the above domain to NewLDAP
?:Using hyphen d to this default one domain named NewLDAP
?:Adding another domain as NewLDAP2 domain
?:Changing provider to proxy for NewLDAP domain
"""


def test_tools__sss_obfuscate_convert_text_password():
    """
    :title: Obfuscate a clear text password into a hash and connect to LDAP
    """


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1661182)
@pytest.mark.topology(KnownTopology.Client)
def test_tools__sss_cache_expired_does_not_print_unrelated_message(client: Client):
    """
    :title: Usermod command does not print unrelated sss_cache messages
    :setup:
        1. Configure SSSD without any domain
        2. Set to sssd section "enable_files_domain" to "false"
        3. Create local user
    :steps:
        1. Restart SSSD
        2. Modify existing local user
        3. Expire cache with specific options
    :expectedresults:
        1. Error is raised, SSSD is not running
        2. Modified successfully
        3. Output did not contain wrong messages
    :customerscenario: True
    """
    client.sssd.sssd["enable_files_domain"] = "false"
    client.local.user("user1").add()

    with pytest.raises(ProcessError):
        client.sssd.restart()

    res = client.host.conn.run("usermod -a -G wheel user1")
    assert (
        "No domains configured, fatal error!" not in res.stdout
    ), "'No domains configured, fatal error!' printed to stdout!"

    for cmd in ("sss_cache -U", "sss_cache -G", "sss_cache -E", "sss_cache --user=nonexisting"):
        res = client.host.conn.run(cmd)
        assert (
            "No domains configured, fatal error!" not in res.stdout
        ), "'No domains configured, fatal error!' printed to stdout!"
