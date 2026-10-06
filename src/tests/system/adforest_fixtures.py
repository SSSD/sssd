"""AD forest join fixtures and helpers for system tests."""

from __future__ import annotations

from pytest_mh import mh_fixture
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client


def ad_forest_leave(client: Client, domain: AD) -> None:
    client.host.conn.exec(
        ["realm", "leave", "--unattended", domain.domain],
        input=domain.host.adminpw,
        raise_on_error=False,
    )


def ad_forest_set_dns(client: Client, target: AD, forest: tuple[AD, ...]) -> None:
    """Ensure ``search`` lists all forest domains; keep prep/lab nameservers.

    Do **not** replace nameservers with AWS SSH hostnames — those are not DNS
    listeners. Lab ``dns.test`` (from IdM-CI prep) already forwards AD zones and
    answers SRV queries needed for ``ad_server = _srv_``.

    ``target`` is unused (kept for call-site compatibility with join helpers).
    """
    _ = target
    client.fs.backup("/etc/resolv.conf")
    current = client.fs.read("/etc/resolv.conf")
    kept = [line for line in current.splitlines() if not line.strip().lower().startswith("search")]
    search = " ".join(domain.domain for domain in forest)
    body = "\n".join(kept)
    client.fs.write("/etc/resolv.conf", f"search {search}\n{body}\n" if body else f"search {search}\n")


def ad_forest_restore_dns(client: Client) -> None:
    client.fs.restore("/etc/resolv.conf")


def ad_forest_remove_stale_computer(forest: tuple[AD, ...], short_hostname: str) -> None:
    """Remove leftover computer accounts before join/rejoin (legacy ad_forest)."""
    for domain in forest:
        domain.host.conn.run(
            f"""
            Import-Module ActiveDirectory
            Get-ADComputer -Identity '{short_hostname}' -ErrorAction SilentlyContinue |
                Remove-ADComputer -Confirm:$false
            """,
            raise_on_error=False,
        )


def ad_forest_remove_linuxservers_ou(domain: AD) -> None:
    """Remove ``linuxservers`` OU and contents (legacy ad_forest ldapdelete -r)."""
    domain.host.conn.run(
        """
        Import-Module ActiveDirectory
        $base = (Get-ADDomain).DistinguishedName
        $ou = Get-ADOrganizationalUnit -LDAPFilter '(ou=linuxservers)' -SearchBase $base -ErrorAction SilentlyContinue
        if ($ou) { Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false }
        """,
        raise_on_error=False,
    )


def ad_forest_configure_sssd(client: Client, joined: AD, ad_root: AD | None = None) -> None:
    """Import the joined AD domain and apply common forest client settings."""
    client.sssd.import_domain(joined.domain, joined)
    # Child/tree join: use SRV discovery so forest root/tree lookups work.
    if ad_root is not None and joined.domain != ad_root.domain:
        client.sssd.dom(joined.domain)["ad_server"] = "_srv_"
    client.sssd.dom(joined.domain)["use_fully_qualified_names"] = "True"
    client.sssd.dom(joined.domain)["fallback_homedir"] = "/home/%d/%u"
    client.sssd.dom(joined.domain)["cache_credentials"] = "True"


def ad_forest_block_servers(client: Client, ad: AD, ad_child: AD, ad_tree: AD) -> None:
    """Block outbound traffic to all forest DCs and bring SSSD offline."""
    for domain in (ad, ad_child, ad_tree):
        # Prefer AD DNS names (resolved via lab dns.test). AWS SSH hostnames often
        # fail dig and poison firewall-cmd rich rules with dig error text.
        client.firewall.outbound.drop_host(domain.host.hostname)
    client.sssd.bring_offline()


def ad_forest_rejoin_with_host_upn(client: Client, target: AD, forest: tuple[AD, ...]) -> None:
    """Rejoin with host/ UPN so ``kinit -k host/FQDN@REALM`` works (legacy ad_join … host)."""
    hostname = client.host.conn.run("hostname -f").stdout.strip()
    short_hostname = hostname.split(".")[0]

    for domain in forest:
        ad_forest_leave(client, domain)

    client.fs.rm("/etc/krb5.conf")
    client.fs.rm("/etc/krb5.keytab")
    ad_forest_remove_stale_computer(forest, short_hostname)

    client.host.conn.exec(
        [
            "realm",
            "join",
            f"--user-principal=host/{hostname}@{target.realm}",
            target.domain,
        ],
        input=target.host.adminpw,
    )
    client.sssd.stop(raise_on_error=False)
    ad_forest_set_dns(client, target, forest)
    target.host.client["ad_server"] = "_srv_"


def ad_forest_join(client: Client, target: AD, forest: tuple[AD, ...]) -> str:
    """Leave any forest domain, set hostname, join ``target``. Return prior hostname."""
    old_hostname = client.host.conn.run("hostname").stdout.strip()
    short_hostname = old_hostname.split(".")[0].strip()
    hostname = f"{short_hostname}.{target.domain}"

    client.fs.write("/etc/hostname", f"{hostname}\n")
    client.host.conn.run(f"hostname {hostname}")

    for domain in forest:
        ad_forest_leave(client, domain)

    client.fs.rm("/etc/krb5.conf")
    client.fs.rm("/etc/krb5.keytab")

    # Stale computer objects (especially after leave/rejoin across forest domains)
    # cause "Insufficient permissions to join the domain".
    ad_forest_remove_stale_computer(forest, short_hostname)

    result = client.host.conn.exec(
        ["realm", "join", target.domain],
        input=target.host.adminpw,
        raise_on_error=False,
    )
    if result.rc != 0:
        ad_forest_leave(client, target)
        ad_forest_remove_stale_computer(forest, short_hostname)
        client.host.conn.exec(["realm", "join", target.domain], input=target.host.adminpw)

    # realmd starts sssd with its own conf; stop it so later client.sssd.start()
    # applies the test-written configuration (systemctl start is a no-op if active).
    client.sssd.stop(raise_on_error=False)

    ad_forest_set_dns(client, target, forest)
    # Cross-forest GC lookups need SRV discovery (legacy ad_forest auth.sh).
    target.host.client["ad_server"] = "_srv_"

    return old_hostname


def ad_forest_restore_hostname(client: Client, hostname: str) -> None:
    client.fs.write("/etc/hostname", f"{hostname}\n")
    client.host.conn.run(f"hostname {hostname}", raise_on_error=False)


@mh_fixture()
def join_ad_root(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    Join the client to the AD forest root.

    Yields ``ad`` — use it for users/groups and ``client.sssd.import_domain``.
    For :attr:`~sssd_test_framework.topology.KnownTopology.ADForest`. Leaves on teardown.
    """
    forest = (ad, ad_child, ad_tree)
    old_hostname = ad_forest_join(client, ad, forest)
    yield ad
    ad_forest_leave(client, ad)
    ad_forest_restore_dns(client)
    ad_forest_restore_hostname(client, old_hostname)


@mh_fixture()
def join_ad_child(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    Join the client to the AD child domain.

    Yields ``ad_child`` — use it for users/groups and ``client.sssd.import_domain``.
    For :attr:`~sssd_test_framework.topology.KnownTopology.ADForest`. Leaves on teardown.
    """
    forest = (ad, ad_child, ad_tree)
    old_hostname = ad_forest_join(client, ad_child, forest)
    yield ad_child
    ad_forest_leave(client, ad_child)
    ad_forest_restore_dns(client)
    ad_forest_restore_hostname(client, old_hostname)


@mh_fixture()
def join_ad_tree(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    Join the client to the AD tree domain.

    Yields ``ad_tree`` — use it for users/groups and ``client.sssd.import_domain``.
    For :attr:`~sssd_test_framework.topology.KnownTopology.ADForest`. Leaves on teardown.
    """
    forest = (ad, ad_child, ad_tree)
    old_hostname = ad_forest_join(client, ad_tree, forest)
    yield ad_tree
    ad_forest_leave(client, ad_tree)
    ad_forest_restore_dns(client)
    ad_forest_restore_hostname(client, old_hostname)
