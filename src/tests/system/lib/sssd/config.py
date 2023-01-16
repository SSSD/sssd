from __future__ import annotations

from typing import Any, Type

from pytest_mh import MultihostConfig, MultihostDomain, MultihostHost, MultihostRole, TopologyMark

from .topology import SSSDTopologyMark

__all__ = [
    "SSSDMultihostConfig",
    "SSSDMultihostDomain",
]


class SSSDMultihostConfig(MultihostConfig):
    @property
    def TopologyMarkClass(self) -> Type[TopologyMark]:
        return SSSDTopologyMark

    @property
    def id_to_domain_class(self) -> dict[str, Type[MultihostDomain]]:
        """
        Map domain id to domain class. Asterisk ``*`` can be used as fallback
        value.

        :rtype: Class name.
        """
        return {"*": SSSDMultihostDomain}


class SSSDMultihostDomain(MultihostDomain[SSSDMultihostConfig]):
    def __init__(self, config: SSSDMultihostConfig, confdict: dict[str, Any]) -> None:
        super().__init__(config, confdict)

    @property
    def role_to_host_class(self) -> dict[str, Type[MultihostHost]]:
        """
        Map role to host class. Asterisk ``*`` can be used as fallback value.

        :rtype: Class name.
        """
        from .hosts.ad import ADHost
        from .hosts.ipa import IPAHost
        from .hosts.kdc import KDCHost
        from .hosts.ldap import LDAPHost
        from .hosts.nfs import NFSHost
        from .hosts.samba import SambaHost

        return {
            "ad": ADHost,
            "ldap": LDAPHost,
            "ipa": IPAHost,
            "samba": SambaHost,
            "nfs": NFSHost,
            "kdc": KDCHost,
        }

    @property
    def role_to_role_class(self) -> dict[str, Type[MultihostRole]]:
        """
        Map role to role class. Asterisk ``*`` can be used as fallback value.

        :rtype: Class name.
        """
        from .roles.ad import AD
        from .roles.client import Client
        from .roles.ipa import IPA
        from .roles.kdc import KDC
        from .roles.ldap import LDAP
        from .roles.nfs import NFS
        from .roles.samba import Samba

        return {
            "client": Client,
            "ad": AD,
            "ipa": IPA,
            "ldap": LDAP,
            "samba": Samba,
            "nfs": NFS,
            "kdc": KDC,
        }
