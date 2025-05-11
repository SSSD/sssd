"""
Proxy Provider tests.

:requirement: Proxy Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_proxy__lookup_and_authenticate_user_using_pam_ldap_and_nslcd(client: Client, ldap: LDAP):
    """
    :title: Lookup and authenticate user using PAM LDAP and NSLCD.
    :setup:
        1. Setup SSSD to use PAM LDAP and NSLCD.
        2. Create OU, and create a user in the new OU.
    :steps:
        1. Lookup user.
        2. Login in as user.
    :expectedresults:
        1. User found.
        2. User logged in.
    :customerscenario: True
    """
    client.sssd.common.proxy("ldap", ["id", "auth", "chpass"], server_hostname=ldap.host.hostname)
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()
    ou_users = ldap.ou("users").add()
    user = ldap.user("user-1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    assert client.tools.id(user.name) is not None, "User not found!"
    assert client.auth.ssh.password(user.name, password="Secret123"), "User login failed!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.ticket(bz=895570)
def test_proxy__lookup_user_using_pam_ldap_and_nslcd_with_proxy_fast_alias_enabled(client: Client, ldap: LDAP):
    """
    :title: Lookup user using PAM LDAP and NSLCD with proxy_fast_alias enabled.
    :description: This bugzilla was created to squash 'ldb_modify failed' message when proxy_fast_alias is enabled.
    :setup:
        1. Setup SSSD to use PAM LDAP and NSLCD and set "proxy_fast_alias = true".
        2. Create OU, and create a user in the new OU.
    :steps:
        1. Lookup user.
        2. Check logs for ldb_modify errors.
    :expectedresults:
        1. User found.
        2. No error messages in log.
    :customerscenario: True
    """
    client.sssd.common.proxy("ldap", ["id", "auth", "chpass"], server_hostname=ldap.host.hostname)
    client.sssd.domain["proxy_fast_alias"] = "True"
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()
    ou_users = ldap.ou("users").add()
    user = ldap.user("user-1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    assert client.tools.id(user.name) is not None, "User not found!"

    log = client.fs.read(client.sssd.logs.domain())
    assert "ldb_modify failed: [Invalid attribute syntax]" not in log, "'ldb_modify failed' message found in logs!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_proxy__domain_separation_with_nslcd(client: Client, ldap: LDAP):
    """
    :title: Verify domain separation by restarting nslcd with different configurations
    :description: Since nslcd doesn't support multiple instances, we test proper
                 domain separation by reconfiguring and restarting nslcd.
    :setup:
        1. Configure two distinct OUs in LDAP
        2. Create users in each OU
        3. Configure SSSD with proxy provider
    :steps:
        1. Configure nslcd for domain1 and verify only domain1 users are visible
        2. Reconfigure nslcd for domain2 and verify only domain2 users are visible
        3. Verify users from one domain are not visible in the other domain
    :expectedresults:
        1. Proxy configuration success
        2. Only users from the currently configured domain are visible
        3. Users are properly isolated between domains
    :customerscenario: False
    """
    # Setup domains and users
    ou_domain1 = ldap.ou("domain1").add()
    user1 = ldap.user("user1", basedn=ou_domain1).add(uid=5000, gid=5000, password="Secret123")

    ou_domain2 = ldap.ou("domain2").add()
    user2 = ldap.user("user2", basedn=ou_domain2).add(uid=5001, gid=5001, password="Secret123")

    # Basic SSSD configuration (no domain separation needed here)
    client.sssd.common.proxy("ldap", ["id", "auth"], server_hostname=ldap.host.hostname)
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()

    # Test domain1 configuration
    client.fs.append("/etc/nslcd.conf", "base ou=domain1,dc=ldap,dc=test\n", dedent=False)
    client.sssd.svc.restart("nslcd")

    # Verify only domain1 user is visible
    assert client.tools.getent.passwd(f"{user1.name}@test") is not None
    assert client.tools.getent.passwd(f"{user2.name}@test") is None

    # Test domain2 configuration
    client.sssd.svc.stop("nslcd")
    client.fs.sed(
        path="/etc/nslcd.conf",
        command="/base ou=domain1,dc=ldap,dc=test/c\\base ou=domain2,dc=ldap,dc=test",
        args=["-i"],
    )
    client.sssd.svc.restart("nslcd")
    client.sssd.restart(clean=True)

    # Verify only domain2 user is visible
    assert client.tools.getent.passwd(f"{user2.name}@test") is not None
    assert client.tools.getent.passwd(f"{user1.name}@test") is None


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_proxy__offline_authentication(client: Client, ldap: LDAP):
    """
    :title: Verify offline authentication works with cached credentials
    :description: Test that authentication continues to work when the LDAP server
                 is unavailable, using cached credentials.
    :setup:
        1. Configure SSSD with proxy provider and credential caching enabled
        2. Create test user in LDAP
    :steps:
        1. Perform initial online authentication
        2. Stop nslcd service
        3. Verify authentication still works with cached credentials
    :expectedresults:
        1. Authentication works in online mode
        2. Nslcd stops
        3. Authentication continues to work in offline mode
    :customerscenario: False
    """
    # Setup user
    ldap.user("testuser").add(uid=5000, gid=5000, password="Secret123")

    # Configure SSSD with credential caching
    client.sssd.common.proxy("ldap", ["id", "auth"], server_hostname=ldap.host.hostname)
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.restart()

    # Initial online authentication
    assert client.auth.ssh.password("testuser", password="Secret123"), "Online auth failed"

    # Stop nslcd to simulate offline mode
    client.sssd.svc.stop("nslcd")

    # Verify offline authentication
    assert client.auth.ssh.password("testuser", password="Secret123"), "Offline auth failed"

    # Start nslcd
    client.sssd.svc.start("nslcd")


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_proxy__case_preserving_handling(client: Client, ldap: LDAP):
    """
    :title: Proxy provider preserves original username case with case_sensitive=Preserving
    :setup:
        1. Create LDAP user "TestUser" with UID 5003 in ou=users
        2. Configure SSSD with:
           - id_provider=proxy
           - proxy_lib_name=ldap
           - case_sensitive=Preserving
        3. Configure nslcd with:
           - ignorecase=yes (for case-insensitive matching)
           - validnames regex (to handle special characters)
        4. Restart SSSD and nslcd services
    :steps:
        1. Perform user lookups with different case variants:
           - getent passwd testuser
           - getent passwd TESTUSER
           - getent passwd TestUser
        2. Verify authentication with different case variants:
           - Authenticate as testuser
           - Authenticate as TestUser
           - Authenticate as TESTUSER
    :expectedresults:
        1. All case variants (testuser, TESTUSER, TestUser) should:
           - Successfully match the LDAP user "TestUser"
           - Return the original case ("TestUser") in responses
           - Return correct home directory (/home/TestUser)
        2. Authentication should succeed for all case variants
    :customerscenario: False
    """
    # Setup
    ou_users = ldap.ou("users").add()
    ldap.user("TestUser", basedn=ou_users).add(uid=5003, gid=5003, password="Secret123", home="/home/TestUser")

    # Configure SSSD with proxy provider
    client.sssd.common.proxy("ldap", ["id", "auth"], server_hostname=ldap.host.hostname)
    client.sssd.domain["case_sensitive"] = "Preserving"
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()

    client.fs.append(
        "/etc/nslcd.conf",
        "base dc=ldap,dc=test\n"
        "ignorecase yes\n"
        "validnames /^[a-z0-9._@$()]([a-z0-9._@$() ~-]*[a-z:0-9._@$()~-])?$/i\n",
        dedent=False,
    )
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()

    # Step 2: Test case preserving lookups
    # All variants should match but preserve original case in output
    for username in ["testuser", "TESTUSER", "TestUser"]:
        client.sssd.restart(clean=True)
        result = client.tools.getent.passwd(username)
        assert result is not None, f"User lookup failed for {username}"
        assert result.name == "TestUser", f"Username case not preserved for {username}"
        assert result.home == "/home/TestUser", f"Incorrect home directory for {username}"

    # Step 3: Verify authentication with different case variants
    for username in ["testuser", "TESTUSER", "TestUser"]:
        client.sssd.restart(clean=True)
        assert client.auth.ssh.password(username, password="Secret123"), f"Authentication failed for {username}"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_proxy__case_insensitive_handling(client: Client, ldap: LDAP):
    """
    :title: Case Insensitive Username Handling (case_sensitive = false)
    :setup:
        1. Configure SSSD with proxy provider
        2. Create single user "TestUser"
        3. Configure sssd.conf with:
           case_sensitive = false
    :steps:
        1. Start SSSD
        2. Test case normalization:
           - getent passwd testuser (should return lowercase name)
           - getent passwd TESTUSER (should return lowercase name)
           - getent passwd TestUser (should return lowercase name)
        3. Verify authentication:
           - ssh testuser@localhost
           - ssh TESTUSER@localhost
           - ssh TestUser@localhost
    :expectedresults:
        1. SSSD starts without errors
        2. All case variants return lowercase username
        3. Authentication succeeds for all case variants
    :customerscenario: False
    """
    # Setup
    ou_users = ldap.ou("users").add()
    ldap.user("TestUser", basedn=ou_users).add(uid=1000, gid=1000, password="Secret123")

    # Configure SSSD with proxy provider and case_sensitive=false
    client.sssd.common.proxy("ldap", ["id", "auth"], server_hostname=ldap.host.hostname)
    client.sssd.domain["case_sensitive"] = "false"

    # Configure nslcd for case insensitive matching
    client.fs.append("/etc/nslcd.conf", "ignorecase yes\n", dedent=False)

    client.sssd.svc.restart("nslcd")
    client.sssd.restart()

    # Step 2: Test case normalization
    for username in ["testuser", "TESTUSER", "TestUser"]:
        client.sssd.restart(clean=True)
        result = client.tools.getent.passwd(username)
        assert result is not None, f"User lookup failed for {username}"
        assert result.name == "testuser", f"Username not normalized to lowercase for {username}"

    # Step 3: Verify authentication with different case variants
    for username in ["testuser", "TESTUSER", "TestUser"]:
        client.sssd.restart(clean=True)
        assert client.auth.ssh.password(username, password="Secret123"), f"Authentication failed for {username}"
