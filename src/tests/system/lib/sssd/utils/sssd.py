"""Manage and configure SSSD."""

from __future__ import annotations

import configparser
from io import StringIO
from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh._private.multihost import MultihostRole
from pytest_mh.ssh import SSHLog, SSHProcess, SSHProcessResult

from ..hosts.base import BaseDomainHost

if TYPE_CHECKING:
    from pytest_mh.utils.fs import LinuxFileSystem
    from pytest_mh.utils.services import SystemdServices

    from ..roles.base import BaseRole
    from ..roles.kdc import KDC
    from .authselect import AuthselectUtils


__all__ = [
    "SSSDCommonConfiguration",
    "SSSDUtils",
]


class SSSDUtils(MultihostUtility[MultihostHost]):
    """
    Manage and configure SSSD.

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(
        self,
        host: MultihostHost,
        fs: LinuxFileSystem,
        svc: SystemdServices,
        authselect: AuthselectUtils,
        load_config: bool = False,
    ) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        :param fs: File system utils.
        :type fs: LinuxFileSystem
        :param svc: Systemd utils.
        :type svc: SystemdServices
        :param authselect: Authselect utils.
        :type authselect: AuthselectUtils
        :param load_config: If True, existing configuration is loaded to
            :attr:`config`, otherwise default configuration is generated,
            defaults to False
        :type load_config: bool, optional
        """ """"""
        super().__init__(host)

        self.authselect: AuthselectUtils = authselect
        """Authselect utils."""

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

        self.svc: SystemdServices = svc
        """Systemd utils."""

        self.config: configparser.ConfigParser = configparser.ConfigParser(interpolation=None)
        """SSSD configuration object."""

        self.default_domain: str | None = None
        """Default SSSD domain."""

        self.__load_config: bool = load_config

        self.common: SSSDCommonConfiguration = SSSDCommonConfiguration(self)
        """
        Shortcuts to setup common SSSD configurations.
        """

        self.logs: SSSDLogsPath = SSSDLogsPath(self)
        """
        Shortcuts to SSSD log paths.
        """

    def setup(self) -> None:
        """
        Setup SSSD on the host.

        - override systemd unit to disable burst limiting, otherwise we will be
          unable to restart the service frequently
        - reload systemd to apply change to the unit file
        - load configuration from the host (if requested in constructor) or set
          default configuration otherwise

        :meta private:
        """
        # Disable burst limiting to allow often sssd restarts for tests
        self.fs.mkdir("/etc/systemd/system/sssd.service.d")
        self.fs.write(
            "/etc/systemd/system/sssd.service.d/override.conf",
            """
            [Unit]
            StartLimitIntervalSec=0
            StartLimitBurst=0
        """,
        )
        self.svc.reload_daemon()

        if self.__load_config:
            self.config_load()
            return

        # Set default configuration
        self.config.read_string(
            """
            [sssd]
            config_file_version = 2
            services = nss, pam
        """
        )

    def async_start(
        self,
        service="sssd",
        *,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
    ) -> SSHProcess:
        """
        Start SSSD service. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: Running SSH process.
        :rtype: SSHProcess
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.async_start(service)

    def start(
        self,
        service="sssd",
        *,
        raise_on_error: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
    ) -> SSHProcessResult:
        """
        Start SSSD service. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        # Also stop kcm so it can pick up changes when started again by socket-activation
        if service == "sssd":
            self.svc.stop("sssd-kcm.service")

        return self.svc.start(service, raise_on_error=raise_on_error)

    def async_stop(self, service="sssd") -> SSHProcess:
        """
        Stop SSSD service. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :return: Running SSH process.
        :rtype: SSHProcess
        """
        return self.svc.async_stop(service)

    def stop(self, service="sssd", *, raise_on_error: bool = True) -> SSHProcessResult:
        """
        Stop SSSD service. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :return: SSH process result.
        :rtype: SSHProcess
        """
        return self.svc.stop(service, raise_on_error=raise_on_error)

    def async_restart(
        self,
        service="sssd",
        *,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
    ) -> SSHProcess:
        """
        Restart SSSD service. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: Running SSH process.
        :rtype: SSHProcess
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.async_restart(service)

    def restart(
        self,
        service="sssd",
        *,
        raise_on_error: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
    ) -> SSHProcessResult:
        """
        Restart SSSD service. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        return self.svc.restart(service, raise_on_error=raise_on_error)

    def clear(self, *, db: bool = True, memcache: bool = True, config: bool = False, logs: bool = False):
        """
        Clear SSSD data.

        :param db: Remove cache and database, defaults to True
        :type db: bool, optional
        :param memcache: Remove in-memory cache, defaults to True
        :type memcache: bool, optional
        :param config: Remove configuration files, defaults to False
        :type config: bool, optional
        :param logs: Remove logs, defaults to False
        :type logs: bool, optional
        """
        cmd = "rm -fr"

        if db:
            cmd += " /var/lib/sss/db/*"

        if memcache:
            cmd += " /var/lib/sss/mc/*"

        if config:
            cmd += " /etc/sssd/*.conf /etc/sssd/conf.d/*"

        if logs:
            cmd += " /var/log/sssd/*"

        self.host.ssh.run(cmd)

    def enable_responder(self, responder: str) -> None:
        """
        Include the responder in the [sssd]/service option.

        :param responder: Responder to enable.
        :type responder: str
        """
        self.config.setdefault("sssd", {})
        svc = self.config["sssd"].get("services", "")
        if responder not in svc:
            self.config["sssd"]["services"] += ", " + responder
            self.config["sssd"]["services"].lstrip(", ")

    def import_domain(self, name: str, role: MultihostRole) -> None:
        """
        Import SSSD domain from role object.

        :param name: SSSD domain name.
        :type name: str
        :param role: Provider role object to use for import.
        :type role: MultihostRole
        :raises ValueError: If unsupported provider is given.
        """
        host = role.host

        if not isinstance(host, BaseDomainHost):
            raise ValueError(f"Host type {type(host)} can not be imported as domain")

        self.config[f"domain/{name}"] = host.client
        self.config["sssd"].setdefault("domains", "")

        if not self.config["sssd"]["domains"]:
            self.config["sssd"]["domains"] = name
        elif name not in [x.strip() for x in self.config["sssd"]["domains"].split(",")]:
            self.config["sssd"]["domains"] += ", " + name

        if self.default_domain is None:
            self.default_domain = name

    def merge_domain(self, name: str, role: BaseRole) -> None:
        """
        Merge SSSD domain configuration from role object into the domain.

        If domain name is not provided then the default domain is used.

        :param name: Target SSSD domain name
        :type name: str
        :param role: Provider role object to use for import.
        :type role: BaseRole
        :raises ValueError: If unsupported provider is given.
        """
        if not isinstance(role.host, BaseDomainHost):
            raise ValueError(f"Host type {type(role.host)} can not be imported as domain")

        if name is None:
            name = self.default_domain

        if f"domain/{name}" not in self.config:
            raise ValueError(f'Domain "{name}" does not yet exist, create it first')

        self.dom(name).update(role.host.client)

    def config_dumps(self) -> str:
        """
        Get current SSSD configuration.

        :return: SSSD configuration.
        :rtype: str
        """
        return self.__config_dumps(self.config)

    def config_load(self) -> None:
        """
        Load remote SSSD configuration.
        """
        result = self.host.ssh.exec(["cat", "/etc/sssd/sssd.conf"], log_level=SSHLog.Short)
        self.config.clear()
        self.config.read_string(result.stdout)

    def config_apply(self, check_config: bool = True, debug_level: str | None = "0xfff0") -> None:
        """
        Apply current configuration on remote host.

        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        """
        cfg = self.__set_debug_level(debug_level)
        contents = self.__config_dumps(cfg)
        self.fs.write("/etc/sssd/sssd.conf", contents, mode="0600")

        if check_config:
            self.host.ssh.run("sssctl config-check")

    def section(self, name: str) -> configparser.SectionProxy:
        """
        Get sssd.conf section.

        :param name: Section name.
        :type name: str
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        return self.__get(name)

    def dom(self, name: str) -> configparser.SectionProxy:
        """
        Get sssd.conf domain section.

        :param name: Domain name.
        :type name: str
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        return self.section(f"domain/{name}")

    def subdom(self, domain: str, subdomain: str) -> configparser.SectionProxy:
        """
        Get sssd.conf subdomain section.

        :param domain: Domain name.
        :type domain: str
        :param subdomain: Subdomain name.
        :type subdomain: str
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        return self.section(f"domain/{domain}/{subdomain}")

    @property
    def domain(self) -> configparser.SectionProxy:
        """
        Default domain section configuration object.

        Default domain is the first domain imported by :func:`import_domain`.

        :raises ValueError: If no default domain is set.
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        if self.default_domain is None:
            raise ValueError(f"{self.__class__}.default_domain is not set")

        return self.dom(self.default_domain)

    @domain.setter
    def domain(self, value: dict[str, str]) -> None:
        if self.default_domain is None:
            raise ValueError(f"{self.__class__}.default_domain is not set")

        self.config[f"domain/{self.default_domain}"] = value

    @domain.deleter
    def domain(self) -> None:
        if self.default_domain is None:
            raise ValueError(f"{self.__class__}.default_domain is not set")

        del self.config[f"domain/{self.default_domain}"]

    def __get(self, section: str) -> configparser.SectionProxy:
        self.config.setdefault(section, {})
        return self.config[section]

    def __set(self, section: str, value: dict[str, str]) -> None:
        self.config[section] = value

    def __del(self, section: str) -> None:
        del self.config[section]

    @property
    def sssd(self) -> configparser.SectionProxy:
        """
        Configuration of the sssd section of sssd.conf.
        """
        return self.__get("sssd")

    @sssd.setter
    def sssd(self, value: dict[str, str]) -> None:
        return self.__set("sssd", value)

    @sssd.deleter
    def sssd(self) -> None:
        return self.__del("sssd")

    @property
    def autofs(self) -> configparser.SectionProxy:
        """
        Configuration of the autofs section of sssd.conf.
        """
        return self.__get("autofs")

    @autofs.setter
    def autofs(self, value: dict[str, str]) -> None:
        return self.__set("autofs", value)

    @autofs.deleter
    def autofs(self) -> None:
        return self.__del("autofs")

    @property
    def ifp(self) -> configparser.SectionProxy:
        """
        Configuration of the ifp section of sssd.conf.
        """
        return self.__get("ifp")

    @ifp.setter
    def ifp(self, value: dict[str, str]) -> None:
        return self.__set("ifp", value)

    @ifp.deleter
    def ifp(self) -> None:
        return self.__del("ifp")

    @property
    def kcm(self) -> configparser.SectionProxy:
        """
        Configuration of the kcm section of sssd.conf.
        """
        return self.__get("kcm")

    @kcm.setter
    def kcm(self, value: dict[str, str]) -> None:
        return self.__set("kcm", value)

    @kcm.deleter
    def kcm(self) -> None:
        return self.__del("kcm")

    @property
    def nss(self) -> configparser.SectionProxy:
        """
        Configuration of the nss section of sssd.conf.
        """
        return self.__get("nss")

    @nss.setter
    def nss(self, value: dict[str, str]) -> None:
        return self.__set("nss", value)

    @nss.deleter
    def nss(self) -> None:
        return self.__del("nss")

    @property
    def pac(self) -> configparser.SectionProxy:
        """
        Configuration of the pac section of sssd.conf.
        """
        return self.__get("pac")

    @pac.setter
    def pac(self, value: dict[str, str]) -> None:
        return self.__set("pac", value)

    @pac.deleter
    def pac(self) -> None:
        return self.__del("pac")

    @property
    def pam(self) -> configparser.SectionProxy:
        """
        Configuration of the pam section of sssd.conf.
        """
        return self.__get("pam")

    @pam.setter
    def pam(self, value: dict[str, str]) -> None:
        return self.__set("pam", value)

    @pam.deleter
    def pam(self) -> None:
        return self.__del("pam")

    @property
    def ssh(self) -> configparser.SectionProxy:
        """
        Configuration of the ssh section of sssd.conf.
        """
        return self.__get("ssh")

    @ssh.setter
    def ssh(self, value: dict[str, str]) -> None:
        return self.__set("ssh", value)

    @ssh.deleter
    def ssh(self) -> None:
        return self.__del("ssh")

    @property
    def sudo(self) -> configparser.SectionProxy:
        """
        Configuration of the sudo section of sssd.conf.
        """
        return self.__get("sudo")

    @sudo.setter
    def sudo(self, value: dict[str, str]) -> None:
        return self.__set("sudo", value)

    @sudo.deleter
    def sudo(self) -> None:
        return self.__del("sudo")

    @staticmethod
    def __config_dumps(cfg: configparser.ConfigParser) -> str:
        """Convert configparser to string."""
        with StringIO() as ss:
            cfg.write(ss)
            ss.seek(0)
            return ss.read()

    def __set_debug_level(self, debug_level: str | None = None) -> configparser.ConfigParser:
        """Set debug level in all sections."""
        cfg = configparser.ConfigParser()
        cfg.read_dict(self.config)

        if debug_level is None:
            return self.config

        sections = ["sssd", "autofs", "ifp", "kcm", "nss", "pac", "pam", "ssh", "sudo"]
        sections += [section for section in cfg.keys() if section.startswith("domain/")]

        for section in sections:
            cfg.setdefault(section, {})
            if "debug_level" not in cfg[section]:
                cfg[section]["debug_level"] = debug_level

        return cfg


class SSSDLogsPath(object):
    def __init__(self, sssd: SSSDUtils) -> None:
        self.__sssd: SSSDUtils = sssd

    @property
    def autofs(self) -> str:
        """Return path to SSSD autofs logs."""
        return "/var/lib/sssd/sssd_autofs.log"

    @property
    def ifp(self) -> str:
        """Return path to SSSD ifp logs."""
        return "/var/lib/sssd/sssd_ifp.log"

    @property
    def kcm(self) -> str:
        """Return path to SSSD kcm logs."""
        return "/var/lib/sssd/sssd_kcm.log"

    @property
    def nss(self) -> str:
        """Return path to SSSD nss logs."""
        return "/var/lib/sssd/sssd_nss.log"

    @property
    def pac(self) -> str:
        """Return path to SSSD pac logs."""
        return "/var/lib/sssd/sssd_pac.log"

    @property
    def pam(self) -> str:
        """Return path to SSSD pam logs."""
        return "/var/lib/sssd/sssd_pam.log"

    @property
    def ssh(self) -> str:
        """Return path to SSSD ssh logs."""
        return "/var/lib/sssd/sssd_ssh.log"

    @property
    def sudo(self) -> str:
        """Return path to SSSD sudo logs."""
        return "/var/lib/sssd/sssd_sudo.log"

    def domain(self, name: str | None = None) -> str:
        """
        Return path to SSSD domain log for given domain. If the domain name is
        not set then :attr:`SSSDUtils.default_domain` is used.

        :param name: Domain name, defaults to None (=:attr:`SSSDUtils.default_domain`)
        :type name: str | None, optional
        :return: Path to SSSD domain log.
        :rtype: str
        """
        if name is None:
            name = self.__sssd.default_domain

        return f"/var/log/sssd/sssd_{name}.log"


class SSSDCommonConfiguration(object):
    """
    Setup common SSSD configurations.

    This class provides shortcuts to setup SSSD for common scenarios.
    """

    def __init__(self, sssd: SSSDUtils) -> None:
        self.sssd: SSSDUtils = sssd
        """SSSD utils."""

    def local(self) -> None:
        """
        Create ``local`` SSSD domain for local users.

        This is a proxy domain that uses nss_files and PAM system-auth service.
        """
        self.sssd.dom("local").update(
            enabled="true",
            id_provider="proxy",
            proxy_lib_name="files",
            proxy_pam_target="system-auth",
        )

    def krb5_auth(self, kdc: KDC, domain: str | None = None) -> None:
        """
        Configure auth_provider to krb5, using the KDC from the multihost
        configuration.

        #. Merge KDC configuration into the given domain (or default domain)
        #. Generate /etc/krb5.conf from given KDC role

        :param kdc: KDC role object.
        :type kdc: KDC
        :param domain: Existing domain name, defaults to None (= default domain)
        :type domain: str | None, optional
        :raises ValueError: if invalid domain is given.
        """
        if domain is None:
            domain = self.sssd.default_domain

        if domain is None:
            raise ValueError("No domain specified!")

        self.sssd.merge_domain(domain, kdc)
        self.sssd.fs.write("/etc/krb5.conf", kdc.config(), user="root", group="root", mode="0644")

    def kcm(self, kdc: KDC, *, local_domain: bool = True) -> None:
        """
        Configure Kerberos to allow KCM tests.

        #. Generate /etc/krb5.conf from given KDC role
        #. If ``local_domain`` is ``True``, create an SSSD domain ``local`` for local users

        :param kdc: KDC role object.
        :type kdc: KDC
        :param local_domain: Create ``local`` SSSD domain for local users, defaults to ``True``
        :type bool: If ``True`` a ``local`` SSSD domain for local users is created
        """
        self.sssd.fs.write("/etc/krb5.conf", kdc.config(), user="root", group="root", mode="0644")
        if local_domain:
            self.local()

    def sudo(self) -> None:
        """
        Configure SSSD with sudo.

        #. Select authselect sssd profile with 'with-sudo'
        #. Enable sudo responder
        """
        self.sssd.authselect.select("sssd", ["with-sudo"])
        self.sssd.enable_responder("sudo")

    def autofs(self) -> None:
        """
        Configure SSSD with autofs.

        #. Select authselect sssd profile
        #. Enable autofs responder
        """
        self.sssd.authselect.select("sssd")
        self.sssd.enable_responder("autofs")
