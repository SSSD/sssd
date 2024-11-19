"""
Files Provider Test Cases

The files provider allows SSSD to use system users to authenticate.
This feature has been removed in SSSD 2.9.0 for the proxy provider.

:requirement: IDM-SSSD-REQ :: SSSD is default for local resolution
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

notes
=====
* I think we should drop most of these tests except the ones that checks the data that is extracted from /etc/passwd, homedir, gecos
* Dropping the modifying value entry tests, cache tests, override tests 

intg
====
+:test_getpwnam_after_start
+:test_getpwuid_after_start
p:test_user_overriden::test_sss_overrides__overriding_username_and_posix_attributes
p:test_group_overriden::test_sss_overrides__overriding_group_name_and_gid
-:test_getpwnam_neg::asserts non-existent user
-:test_getpwuid_neg::asserts non-existent group
p:test_root_does_not_resolve::test_files__root_user_is_ignored_on_lookups
+:test_uid_zero_does_not_resolve::extend test_files__root_user_is_ignored_on_lookups
-:test_add_remove_add_file_user::asserts the sss ldb cache changes when modified
+:test_mod_user_shell::test_authentication.py,default_shell
+:test_user_no_shell
+:test_user_no_dir
+:test_user_no_gecos
+:test_user_no_passwd
-:test_incomplete_user_fail::asserts user with no password field
-:test_getgrnam_after_start
-:test_getgrgid_after_start
-:test_getgrnam_neg
-:test_getgrgid_neg
+:test_root_group_does_not_resolve::test_files.py
+:test_gid_zero_does_not_resolve::test_files.py
-:test_add_remove_add_file_group
-:test_mod_group_name
-:test_mod_group_gid
+:test_getgrnam_no_members
p:test_getgrnam_members_users_first
p:test_getgrnam_members_users_multiple
p:test_getgrnam_members_groups_first
-:test_getgrnam_ghost
-:test_getgrnam_user_ghost_and_member
-:test_getgrnam_user_member_and_ghost
+:test_getgrnam_add_remove_members
-:test_getgrnam_add_remove_ghosts
?:test_realloc_users_exact
?:test_realloc_users
?:test_realloc_groups_exact
?:test_realloc_groups
?:test_proxy_to_files_domain_only
+:test_disable_files_domain::test_files.py
-:test_multiple_passwd_group_files::not important
-:test_multiple_files_created_after_startup:: not important
-:test_files_with_domain_resolution_order
-:test_files_with_default_domain_suffix
-:test_files_with_override_homedir::test_sss_override.py
-:test_files_with_override_shell::test_sss_override.py
"""


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__root_user_is_ignored_on_lookups(client: Client):
    """
    :title: The root user is always ignored on sss service lookups
    :description: This ensures that the local root user is always returned
        and cannot be tampered with.
    :setup:
        1. Configure SSSD with files provider
        2. Start SSSD
    :steps:
        1. Lookup root user using sss service
        2. Lookup root user without the sss service
    :expectedresults:
        1. The root user is not found
        2. The root user is found
    :customerscenario: False
    """
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    assert client.tools.getent.passwd("root", service="sss") is None, "Root user is found using 'sss' service!"
    assert client.tools.getent.passwd("root"), "Root user is not found using all services!"


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_user(client: Client):
    """
    :title: Lookup user
    :setup:
        1. Create user
        2. Configure SSSD with files provider
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Check results
    :expectedresults:
        1. User is found
        2. The uid matches
    :customerscenario: False
    """
    client.local.user("user1").add(uid=10001)
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "User not found!"
    assert result.uid == 10001, "UID does not match!"


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__enumeration_should_not_work(client: Client):
    """
    :title: Enumeration should not work
    :description: Enumeration pulls down the directory data and stores it locally.
        Running an unspecified getent will return all users or groups.
    :setup:
        1. Configure SSSD with files provider
        2. Start SSSD
    :steps:
        1. Run getent with nothing specified
    :expectedresults:
        1. Nothing found
    :customerscenario: False
    """
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    assert not client.host.conn.run("getent passwd -s sss").stdout, "Entries found!"


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_returns_the_latest_data(client: Client):
    """
    :title: Looking up a user returns the latest data
    :setup:
        1. Create user and specify home directory
        2. Configure SSSD with files provider
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Check results
        3. Change user's home directory
        4. Lookup user again
        5. Check results
    :expectedresults:
        1. User is found
        2. The homedir matches
        3. Home directory is changed
        4. User is found
        5. Home directory reflects the new value
    :customerscenario: False
    """
    client.local.user("user1").add(password="Secret123", home="/home/user1-tmp")
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "User not found!"
    assert result.home == "/home/user1-tmp", "User's homedir is not correct!"

    client.local.user("user1").modify(home="/home/user1")

    time.sleep(1)
    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "User not found!"
    assert result.home == "/home/user1", "User's homedir is not correct!"
