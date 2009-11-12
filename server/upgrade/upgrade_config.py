#!/usr/bin/python
#coding=utf-8

#  SSSD
#
#  upgrade_config.py
#
#  Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import shutil
import traceback
import copy
from ConfigParser import RawConfigParser
from ConfigParser import NoOptionError
from optparse import OptionParser

class SSSDConfigParser(RawConfigParser):
    def raw_set(self, section, option):
        " set without interpolation "
        pass

    def raw_get(self, section, option):
        " get without interpolation "
        return self._sections[section].get(option)

    def _write_section(self, section, fp):
        fp.write("[%s]\n" % section)
        for (key, value) in sorted(self._sections[section].items()):
            if key != "__name__":
                fp.write("%s = %s\n" %
                        (key, str(value).replace('\n', '\n\t')))
        fp.write("\n")

    def write(self, fp):
        """
        SSSD Config file uses a logical order of sections
        ConfigParser does not allow sorting the sections, so
        we hackishly sort them here..
        """
        # Write SSSD first
        if "sssd" in self._sections:
            self._write_section("sssd", fp)
            if (self.has_option('sssd', 'domains')):
                active_domains = [s.strip() for s in self.get('sssd','domains').split(',')]
            else:
                #There were no active domains configured
                active_domains = []
            del self._sections["sssd"]
        # Write the other services
        for service in [ s for s in self._sections if not s.startswith('domain/') ]:
            self._write_section(service, fp)
            del self._sections[service]

        # Write the domains in the order that is specified in domains =
        for dom in active_domains:
            self._write_section('domain/%s' % dom, fp)
            del self._sections['domain/%s' % dom]

        # Write inactive domains
        for section in sorted(self._sections):
            self._write_section(section, fp)

class SSSDConfigFile(object):
    def __init__(self, file_name):
        self.file_name = file_name
        self._config = SSSDConfigParser()
        self._new_config = SSSDConfigParser()
        self._config.read(file_name)

    def get_version(self):
        " Guess if we are looking at v1 config file "
        if not self._config.has_section('sssd'):
            return 1
        if not self._config.has_option('sssd', 'config_file_version'):
            return 1
        return self._config.getint('sssd', 'config_file_version')

    def _backup_file(self):
        " Copy the file we operate on to a backup location "
        shutil.copy(self.file_name, self.file_name+".bak")

        # make sure we don't leak data, force permissions on the backup
        os.chmod(self.file_name+".bak", 0600)

    def _migrate_if_exists(self, to_section, to_option, from_section, from_option):
        """
        Move value of parameter from one section to another, renaming the parameter
        """
        if self._config.has_section(from_section) and \
           self._config.has_option(from_section, from_option):
            self._new_config.set(to_section, to_option,
                                 self._config.get(from_section, from_option))

    def _migrate_kw(self, to_section, from_section, new_old_dict):
        """
        Move value of parameter from one section to another according to
        mapping in ``new_old_dict``
        """
        for new, old in new_old_dict.items():
            self._migrate_if_exists(to_section, new, from_section, old)

    def _migrate_enumerate(self, to_section, from_section):
        " Enumerate was special as it turned into bool from (0,1,2,3) enum "
        if self._config.has_section(from_section) and \
           self._config.has_option(from_section, 'enumerate'):
            enumvalue = self._config.get(from_section, 'enumerate')
            if enumvalue.upper() in ['TRUE', 'FALSE']:
                self._new_config.set(to_section, 'enumerate', enumvalue)
            else:
                try:
                    enumvalue = int(enumvalue)
                except ValueError:
                    raise ValueError('Cannot convert value %s in domain %s' % (enumvalue, from_section))

                if enumvalue == 0:
                    self._new_config.set(to_section, 'enumerate', 'FALSE')
                elif enumvalue > 0:
                    self._new_config.set(to_section, 'enumerate', 'TRUE')
                else:
                    raise ValueError('Cannot convert value %s in domain %s' % (enumvalue, from_section))

    def _migrate_domain(self, domain):
        new_domsec = 'domain/%s' % domain
        old_domsec = 'domains/%s' % domain
        self._new_config.add_section(new_domsec)

        # Generic options - new:old
        generic_kw = { 'min_id' : 'minID',
                       'max_id': 'maxID',
                       'timeout': 'timeout',
                       'magic_private_groups' : 'magicPrivateGroups',
                       'cache_credentials' : 'cache-credentials',
                       'id_provider' : 'provider',
                       'auth_provider' : 'auth-module',
                       'access_provider' : 'access-module',
                       'chpass_provider' : 'chpass-module',
                       'use_fully_qualified_names' : 'useFullyQualifiedNames',
                      }
        # Proxy options
        proxy_kw = { 'proxy_pam_target' : 'pam-target',
                     'proxy_lib_name'   : 'libName',
                   }
        # LDAP options - new:old
        ldap_kw = { 'ldap_uri' : 'ldapUri',
                    'ldap_schema' : 'ldapSchema',
                    'ldap_default_bind_dn' : 'defaultBindDn',
                    'ldap_default_authtok_type' : 'defaultAuthtokType',
                    'ldap_default_authtok' : 'defaultAuthtok',
                    'ldap_user_search_base' : 'userSearchBase',
                    'ldap_user_search_scope' : 'userSearchScope',
                    'ldap_user_search_filter' : 'userSearchFilter',
                    'ldap_user_object_class' : 'userObjectClass',
                    'ldap_user_name' : 'userName',
                    'ldap_user_pwd' : 'userPassword',
                    'ldap_user_uid_number' : 'userUidNumber',
                    'ldap_user_gid_number' : 'userGidNumber',
                    'ldap_user_gecos' : 'userGecos',
                    'ldap_user_home_directory' : 'userHomeDirectory',
                    'ldap_user_shell' : 'userShell',
                    'ldap_user_uuid' : 'userUUID',
                    'ldap_user_principal' : 'userPrincipal',
                    'ldap_force_upper_case_realm' : 'force_upper_case_realm',
                    'ldap_user_fullname' : 'userFullname',
                    'ldap_user_member_of' : 'userMemberOf',
                    'ldap_user_modify_timestamp' : 'modifyTimestamp',
                    'ldap_group_search_base' : 'groupSearchBase',
                    'ldap_group_search_scope' : 'groupSearchScope',
                    'ldap_group_search_filter' : 'groupSearchFilter',
                    'ldap_group_object_class' : 'groupObjectClass',
                    'ldap_group_name' : 'groupName',
                    'ldap_group_pwd' : 'userPassword',
                    'ldap_group_gid_number' : 'groupGidNumber',
                    'ldap_group_member' : 'groupMember',
                    'ldap_group_uuid' : 'groupUUID',
                    'ldap_group_modify_timestamp' : 'modifyTimestamp',
                    'ldap_network_timeout' : 'network_timeout',
                    'ldap_offline_timeout' : 'offline_timeout',
                    'ldap_enumeration_refresh_timeout' : 'enumeration_refresh_timeout',
                    'ldap_stale_time' : 'stale_time',
                    'ldap_opt_timeout' : 'opt_timeout',
                    'ldap_tls_reqcert' : 'tls_reqcert',
                   }
        krb5_kw = { 'krb5_kdcip' : 'krb5KDCIP',
                    'krb5_realm'  : 'krb5REALM',
                    'krb5_try_simple_upn' : 'krb5try_simple_upn',
                    'krb5_changepw_principal' : 'krb5changepw_principle',
                    'krb5_ccachedir' : 'krb5ccache_dir',
                    'krb5_auth_timeout' : 'krb5auth_timeout',
                    'krb5_ccname_template' : 'krb5ccname_template',
                  }
        user_defaults_kw = { 'default_shell' : 'defaultShell',
                             'base_directory' : 'baseDirectory',
                           }

        self._migrate_enumerate(new_domsec, old_domsec)
        self._migrate_kw(new_domsec, old_domsec, generic_kw)
        self._migrate_kw(new_domsec, old_domsec, proxy_kw)
        self._migrate_kw(new_domsec, old_domsec, ldap_kw)
        self._migrate_kw(new_domsec, old_domsec, krb5_kw)

        # configuration files before 0.5.0 did not enforce provider= in local domains
        # it did special-case by domain name (LOCAL)
        try:
            prv = self._new_config.get(new_domsec, 'id_provider')
        except NoOptionError:
            if old_domsec == 'domains/LOCAL':
                prv = 'local'
                self._new_config.set(new_domsec, 'id_provider', prv)

        # if domain was local, update with parameters from [user_defaults]
        if prv == 'local':
            self._migrate_kw(new_domsec, 'user_defaults', user_defaults_kw)

    def _migrate_domains(self):
        for domain in [ s.replace('domains/','') for s in self._config.sections() if s.startswith("domains/") ]:
            domain = domain.strip()
            self._migrate_domain(domain)

    def _remove_dp(self):
        # If data provider is in the list of active services, remove it
        if self._new_config.has_option('sssd', 'services'):
            services = [ srv.strip() for srv in self._new_config.get('sssd', 'services').split(',') ]
            if 'dp' in services:
                services.remove('dp')

        self._new_config.set('sssd', 'services', ", ".join([srv for srv in services]))

        # also remove the [dp] section
        self._new_config.remove_section('dp')

    def _do_v2_changes(self):
        # the changes themselves
        self._remove_dp()

    def v2_changes(self, out_file_name, backup=True):
        """
        Check for needed changes in V2 format and write the result into
        ``out_file_name```.
        """
        # basically a wrapper around _do_v2_changes
        self._new_config = copy.deepcopy(self._config)

        if backup:
            self._backup_file()

        self._do_v2_changes()

        # all done, open the file for writing
        of = open(out_file_name, "wb")

        # make sure it has the right permissions too
        os.chmod(out_file_name, 0600)
        self._new_config.write(of)

    def upgrade_v2(self, out_file_name, backup=True):
        """
        Upgrade the config file to V2 format and write the result into
        ``out_file_name```.
        """
        if backup:
            self._backup_file()

        # [service] - options common to all services, no section as in v1
        service_kw = { 'reconnection_retries' : 'reconnection_retries',
                       'debug_level' : 'debug-level',
                       'debug_timestamps' : 'debug-timestamps',
                       'command' : 'command',
                       'timeout' : 'timeout',
                     }

        # [sssd] - monitor service
        self._new_config.add_section('sssd')
        self._new_config.set('sssd', 'config_file_version', '2')
        self._migrate_if_exists('sssd', 'domains',
                                'domains', 'domains')
        self._migrate_if_exists('sssd', 'services',
                                'services', 'activeServices')
        self._migrate_if_exists('sssd', 'sbus_timeout',
                                 'services/monitor', 'sbusTimeout')
        self._migrate_if_exists('sssd', 're_expression',
                                'names', 're-expression')
        self._migrate_if_exists('sssd', 're_expression',
                                'names', 'full-name-format')
        self._migrate_kw('sssd', 'services', service_kw)
        self._migrate_kw('sssd', 'services/monitor', service_kw)

        # [nss] - Name service
        self._new_config.add_section('nss')
        nss_kw = { 'enum_cache_timeout' : 'EnumCacheTimeout',
                   'entry_cache_timeout' : 'EntryCacheTimeout',
                   'entry_cache_nowait_timeout' : 'EntryCacheNoWaitRefreshTimeout',
                   'entry_negative_timeout ' : 'EntryNegativeTimeout',
                   'filter_users' : 'filterUsers',
                   'filter_groups' : 'filterGroups',
                   'filter_users_in_groups' : 'filterUsersInGroups',
                   }
        nss_kw.update(service_kw)
        self._migrate_kw('nss', 'services', service_kw)
        self._migrate_kw('nss', 'services/nss', nss_kw)

        # [pam] - Authentication service
        self._new_config.add_section('pam')
        pam_kw = {}
        pam_kw.update(service_kw)
        self._migrate_kw('pam', 'services', service_kw)
        self._migrate_kw('pam', 'services/pam', pam_kw)

        # Migrate domains
        self._migrate_domains()

        # Perform neccessary changes
        self._do_v2_changes()

        # all done, open the file for writing
        of = open(out_file_name, "wb")

        # make sure it has the right permissions too
        os.chmod(out_file_name, 0600)

        self._new_config.write(of)

def parse_options():
    parser = OptionParser()
    parser.add_option("-f", "--file",
                      dest="filename", default="/etc/sssd/sssd.conf",
                      help="Set input file to FILE", metavar="FILE")
    parser.add_option("-o", "--outfile",
                      dest="outfile", default=None,
                      help="Set output file to OUTFILE", metavar="OUTFILE")
    parser.add_option("", "--no-backup", action="store_false",
                      dest="backup", default=True,
                      help="""Do not provide backup file after conversion.
The script copies the original file with the suffix .bak
by default""")
    parser.add_option("-v", "--verbose", action="store_true",
                      dest="verbose", default=False,
                      help="Be verbose")
    (options, args) = parser.parse_args()
    if len(args) > 0:
        print >>sys.stderr, "Stray arguments: %s" % ' '.join([a for a in args])
        return None

    # do the conversion in place by default
    if not options.outfile:
        options.outfile = options.filename

    return options

def verbose(msg, verbose):
    if verbose:
        print msg

def main():
    options = parse_options()
    if not options:
        print >>sys.stderr, "Cannot parse options"
        return 1

    try:
        config = SSSDConfigFile(options.filename)
    except SSSDConfigParser.ParsingError:
        print >>sys.stderr, "Cannot parse config file %s" % options.filename
        return 1

    # make sure we keep strict settings when creating new files
    os.umask(0077)

    version = config.get_version()
    if version == 2:
        try:
            config.v2_changes(options.outfile, options.backup)
        except Exception, e:
            print "ERROR: %s" % e
            verbose(traceback.format_exc(), options.verbose)
            return 1
    elif version == 1:
        try:
            config.upgrade_v2(options.outfile, options.backup)
        except Exception, e:
            print "ERROR: %s" % e
            verbose(traceback.format_exc(), options.verbose)
            return 1
    else:
        print >>sys.stderr, "Can only upgrade from v1 to v2, file %s looks like version %d" % (options.filename, config.get_version())
        return 1

    return 0

if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

