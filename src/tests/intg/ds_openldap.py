#
# OpenLDAP directory server instance class
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
# Author: Lukas Slebodnik <lslebodn@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import hashlib
import base64
import time
import ldap
import os
import errno
import signal
import shutil
import subprocess
from util import unindent, first_dir
from ds import DS

try:
    from urllib import quote as url_quote
except ImportError:
    from urllib.parse import quote as url_quote


def hash_password(password):
    """Generate userPassword value for a password."""
    salt = os.urandom(4)
    hash = hashlib.sha1(password.encode('utf-8'))
    hash.update(salt)
    hash_base64 = base64.standard_b64encode(hash.digest() + salt)
    return "{SSHA}" + hash_base64.decode('utf-8')


class DSOpenLDAP(DS):
    """OpenLDAP directory server instance."""

    def __init__(self, dir, port, base_dn, admin_rdn, admin_pw):
        """
            Initialize the instance.

            Arguments:
            dir         Path to the root of the filesystem hierarchy to create
                        the instance under.
            port        TCP port on localhost to bind the server to.
            base_dn     Base DN.
            admin_rdn   Administrator DN, relative to BASE_DN.
            admin_pw    Administrator password.
        """
        DS.__init__(self, dir, port, base_dn, admin_rdn, admin_pw)
        self.run_dir = self.dir + "/var/run/ldap"
        self.pid_path = self.run_dir + "/slapd.pid"
        self.conf_dir = self.dir + "/etc/ldap"
        self.conf_slapd_d_dir = self.conf_dir + "/slapd.d"
        self.data_dir = self.dir + "/var/lib/ldap"

    def _setup_config(self):
        """Setup the instance initial configuration."""
        dist_lib_dir = first_dir("/usr/lib64/openldap",
                                 "/usr/lib/openldap",
                                 "/usr/lib/ldap")
        dist_conf_dir = first_dir("/etc/ldap",
                                  "/etc/openldap")
        args_file = self.run_dir + "/slapd.args"
        admin_pw_hash = hash_password(self.admin_pw)
        uid = os.geteuid()
        gid = os.getegid()

        #
        # Add configuration
        #
        config = unindent("""
            dn: cn=config
            objectClass: olcGlobal
            cn: config
            olcPidFile: {self.pid_path}
            olcArgsFile: {args_file}
            # Read slapd.conf(5) for possible values
            olcLogLevel: none

            # Frontend settings
            dn: olcDatabase={{-1}}frontend,cn=config
            objectClass: olcDatabaseConfig
            objectClass: olcFrontendConfig
            olcDatabase: {{-1}}frontend
            # The maximum number of entries that is returned for
            # a search operation
            olcSizeLimit: 500
            # Allow unlimited access to local connection from the local root
            olcAccess: {{0}}to * by dn.exact=gidNumber={gid}+uidNumber={uid},
             cn=peercred,cn=external,cn=auth manage by * break
            # Allow unauthenticated read access for schema and
            # base DN autodiscovery
            olcAccess: {{1}}to dn.exact="" by * read
            olcAccess: {{2}}to dn.base="cn=Subschema" by * read

            # Config db settings
            dn: olcDatabase=config,cn=config
            objectClass: olcDatabaseConfig
            olcDatabase: config
            # Allow unlimited access to local connection from the local root
            olcAccess: to * by dn.exact=gidNumber={gid}+uidNumber={uid},
             cn=peercred,cn=external,cn=auth manage by * break
            olcRootDN: {self.admin_rdn},cn=config
            olcRootPW: {admin_pw_hash}

            # Load schemas
            dn: cn=schema,cn=config
            objectClass: olcSchemaConfig
            cn: schema

            include: file://{dist_conf_dir}/schema/core.ldif
            include: file://{dist_conf_dir}/schema/cosine.ldif
            include: file://{dist_conf_dir}/schema/nis.ldif
            include: file://{dist_conf_dir}/schema/inetorgperson.ldif

            # Load module
            dn: cn=module{{0}},cn=config
            objectClass: olcModuleList
            cn: module{{0}}
            olcModulePath: {dist_lib_dir}
            olcModuleLoad: back_mdb

            # Set defaults for the backend
            dn: olcBackend=mdb,cn=config
            objectClass: olcBackendConfig
            olcBackend: mdb

            # The database definition.
            dn: olcDatabase=mdb,cn=config
            objectClass: olcDatabaseConfig
            objectClass: olcMdbConfig
            olcDatabase: mdb
            olcDbCheckpoint: 512 30
            olcLastMod: TRUE
            olcSuffix: {self.base_dn}
            olcDbDirectory: {self.data_dir}
            olcRootDN: {self.admin_dn}
            olcRootPW: {admin_pw_hash}
            olcDbIndex: objectClass eq
            olcDbIndex: cn,uid eq
            olcDbIndex: uidNumber,gidNumber eq
            olcDbIndex: member,memberUid eq
            olcAccess: to attrs=userPassword,shadowLastChange
              by self write
              by anonymous auth
              by * none
            olcAccess: to dn.base="" by * read
            olcAccess: to *
              by * read
        """).format(**locals())

        slapadd = subprocess.Popen(
            ["slapadd", "-F", self.conf_slapd_d_dir, "-b", "cn=config"],
            stdin=subprocess.PIPE, close_fds=True
        )
        slapadd.communicate(config.encode('utf-8'))
        if slapadd.returncode != 0:
            raise Exception("Failed to add configuration with slapadd")

        #
        # Add database config (example from distribution)
        #
        db_config = unindent("""
            # One 0.25 GB cache
            set_cachesize 0 268435456 1

            # Transaction Log settings
            set_lg_regionmax 262144
            set_lg_bsize 2097152
        """)
        db_config_file = open(self.data_dir + "/DB_CONFIG", "w")
        db_config_file.write(db_config)
        db_config_file.close()

        # Import ad schema
        subprocess.check_call(
            ["slapadd", "-F", self.conf_slapd_d_dir, "-b", "cn=config",
             "-l", "data/ssh_schema.ldif"],
        )

        # Import sudo schema
        subprocess.check_call(
            ["slapadd", "-F", self.conf_slapd_d_dir, "-b", "cn=config",
             "-l", "data/sudo_schema.ldif"],
        )

        # Import cert schema
        subprocess.check_call(
            ["slapadd", "-F", self.conf_slapd_d_dir, "-b", "cn=config",
             "-l", "data/cert_schema.ldif"],
        )

    def _start_daemon(self):
        """Start the instance."""
        if subprocess.call(["slapd", "-F", self.conf_slapd_d_dir,
                            "-h", self.url_list]) != 0:
            raise Exception("Failed to start slapd")

        #
        # Wait until it is available
        #
        attempt = 0
        while True:
            try:
                ldap_conn = ldap.initialize(self.ldapi_url)
                ldap_conn.simple_bind_s(self.admin_rdn + ",cn=config",
                                        self.admin_pw)
                ldap_conn.unbind_s()
                ldap_conn = ldap.initialize(self.ldap_url)
                ldap_conn.simple_bind_s(self.admin_dn, self.admin_pw)
                ldap_conn.unbind_s()
                break
            except ldap.SERVER_DOWN:
                pass
            attempt = attempt + 1
            if attempt > 30:
                raise Exception("Failed to start slapd")
            time.sleep(1)

    def setup(self):
        """Setup the instance."""
        ldapi_socket = self.run_dir + "/ldapi"
        self.ldapi_url = "ldapi://" + url_quote(ldapi_socket, "")
        self.url_list = self.ldapi_url + " " + self.ldap_url

        os.makedirs(self.conf_slapd_d_dir)
        os.makedirs(self.run_dir)
        os.makedirs(self.data_dir)

        #
        # Setup initial configuration
        #
        self._setup_config()

        self._start_daemon()

        #
        # Relax requirement of member attribute presence in groupOfNames
        #
        modlist = [
            (ldap.MOD_DELETE, "olcObjectClasses",
             b"{7}( 2.5.6.9 NAME 'groupOfNames' "
             b"DESC 'RFC2256: a group of names (DNs)' SUP top "
             b"STRUCTURAL MUST ( member $ cn ) MAY ( businessCategory $ "
             b"seeAlso $ owner $ ou $ o $ description ) )"),
            (ldap.MOD_ADD, "olcObjectClasses",
             b"{7}( 2.5.6.9 NAME 'groupOfNames' "
             b"DESC 'RFC2256: a group of names (DNs)' SUP top "
             b"STRUCTURAL MUST ( cn ) MAY ( member $ businessCategory $ "
             b"seeAlso $ owner $ ou $ o $ description ) )"),
        ]
        ldap_conn = ldap.initialize(self.ldapi_url)
        ldap_conn.simple_bind_s(self.admin_rdn + ",cn=config", self.admin_pw)
        ldap_conn.modify_s("cn={0}core,cn=schema,cn=config", modlist)
        ldap_conn.unbind_s()

        #
        # Add data
        #
        ldap_conn = ldap.initialize(self.ldap_url)
        ldap_conn.simple_bind_s(self.admin_dn, self.admin_pw)
        ldap_conn.add_s(self.base_dn, [
            ("objectClass", [b"dcObject", b"organization"]),
            ("o", b"Example Company"),
        ])
        ldap_conn.add_s("cn=Manager," + self.base_dn, [
            ("objectClass", b"organizationalRole"),
        ])
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies",
                   "Hosts", "Networks"):
            ldap_conn.add_s("ou=" + ou + "," + self.base_dn, [
                ("objectClass", [b"top", b"organizationalUnit"]),
            ])
        ldap_conn.add_s("ou=sudoers," + self.base_dn, [
            ("objectClass", [b"top", b"organizationalUnit"]),
        ])
        ldap_conn.add_s("cn=testrule,ou=sudoers," + self.base_dn, [
            ("objectClass", [b"top", b"sudoRole"]),
            ("sudoUser", [b"tuser"]),
        ])
        ldap_conn.unbind_s()

    def _stop_daemon(self):
        """Stop the instance."""
        # Wait for slapd to stop
        try:
            pid_file = open(self.pid_path, "r")
            try:
                os.kill(int(pid_file.read()), signal.SIGTERM)
            finally:
                pid_file.close()
            attempt = 0
            while os.path.isfile(self.pid_path):
                attempt = attempt + 1
                if attempt > 30:
                    raise Exception("Failed to stop slapd")
                time.sleep(1)
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise

    def teardown(self):
        """Teardown the instance."""
        self._stop_daemon()

        for path in (self.conf_slapd_d_dir, self.run_dir, self.data_dir):
            shutil.rmtree(path, True)


class FakeAD(DSOpenLDAP):
    """Fake Active Directory based on OpenLDAP directory server."""

    def _setup_config(self):
        """Setup the instance initial configuration."""

        # Import ad schema
        subprocess.check_call(
            ["slapadd", "-F", self.conf_slapd_d_dir, "-b", "cn=config",
             "-l", "data/ad_schema.ldif"],
        )

    def setup(self):
        """Setup the instance."""
        ldapi_socket = self.run_dir + "/ldapi"
        self.ldapi_url = "ldapi://" + url_quote(ldapi_socket, "")
        self.url_list = self.ldapi_url + " " + self.ldap_url

        os.makedirs(self.conf_slapd_d_dir)
        os.makedirs(self.run_dir)
        os.makedirs(self.data_dir)

        super(FakeAD, self)._setup_config()
        self._setup_config()

        # Start the daemon
        super(FakeAD, self)._start_daemon()

        # Relax requirement of surname attribute presence in person
        modlist = [
            (ldap.MOD_DELETE, "olcObjectClasses",
             b"{4}( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top "
             b"STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ "
             b"telephoneNumber $ seeAlso $ description ) )"),
            (ldap.MOD_ADD, "olcObjectClasses",
             b"{4}( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top "
             b"STRUCTURAL MUST ( cn ) MAY ( sn $ userPassword $ "
             b"telephoneNumber $ seeAlso $ description ) )"),
        ]
        ldap_conn = ldap.initialize(self.ldapi_url)
        ldap_conn.simple_bind_s(self.admin_rdn + ",cn=config", self.admin_pw)
        ldap_conn.modify_s("cn={0}core,cn=schema,cn=config", modlist)
        ldap_conn.unbind_s()

        # restart daemon for reloading schema
        super(FakeAD, self)._stop_daemon()
        super(FakeAD, self)._start_daemon()

        # Add data
        ldap_conn = ldap.initialize(self.ldap_url)
        ldap_conn.simple_bind_s(self.admin_dn, self.admin_pw)
        ldap_conn.add_s(self.base_dn, [
            ("objectClass", [b"dcObject", b"organization"]),
            ("o", b"Example Company"),
        ])
        ldap_conn.add_s("cn=Manager," + self.base_dn, [
            ("objectClass", b"organizationalRole"),
        ])
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies"):
            ldap_conn.add_s("ou=" + ou + "," + self.base_dn, [
                ("objectClass", [b"top", b"organizationalUnit"]),
            ])
        ldap_conn.unbind_s()

        # import data from real AD
        subprocess.check_call(
            ["ldapadd", "-x", "-w", self.admin_pw, "-D",
             self.admin_dn, "-H", self.ldap_url,
             "-f", "data/ad_data.ldif"],
        )

    def teardown(self):
        """Teardown the instance."""
        super(FakeAD, self).teardown()
