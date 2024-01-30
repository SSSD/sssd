"""
Proxy Provider tests.

:requirement: Ldap Provider - nss-pam-ldapd
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.ticket(bz=895570)
def test_invalid_attribute_syntax(client: Client, ldap: LDAP):
    """
    :title: Enabling proxy_fast_alias shows "ldb_modify failed:
        [Invalid attribute syntax]" for id lookups.
    :setup:
        1. Setup sssd for proxy provider.
        2. Enable proxy_fast_alias.
        3. Setup nslcd services.
        4. Add Ou and User.
    :steps:
        1. id lookup a user.
        2. Check logs for "ldb_modify failed".
    :expectedresults:
        1. id look up should success.
        2. Errors should not be seen on enabling proxy_fast_alias.
    :customerscenario: True
    """
    client.sssd.config["domain/test"] = {
        "id_provider": "proxy",
        "debug_level": "0xFFF0",
        "proxy_lib_name": "ldap",
        "proxy_pam_target": "sssdproxyldap",
        "proxy_fast_alias": "true",
    }
    client.fs.write(
        "/etc/pam.d/sssdproxyldap",
        """
            auth    required pam_ldap.so
            account required pam_ldap.so
            password required pam_ldap.so
            session required pam_ldap.so
            """,
    )
    client.fs.write(
        "/etc/nslcd.conf",
        f"uid nslcd\ngid ldap\nuri " f"ldap://{ldap.host.hostname}\nbase " f"{ldap.ldap.naming_context}\n",
        dedent=False,
    )
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()
    ou_users = ldap.ou("users").add()
    user = ldap.user("user-1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")
    result = client.tools.id(user.name)
    assert result is not None
    assert result.user.name == user.name
    log = client.fs.read(client.sssd.logs.domain())
    assert "ldb_modify failed: [Invalid attribute syntax]" not in log
