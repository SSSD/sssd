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
from __future__ import print_function

import os
import sys
import shutil
import traceback
from optparse import OptionParser

from .ipachangeconf import openLocked
from .ipachangeconf import SSSDChangeConf

class SSSDConfigFile(SSSDChangeConf):
    def __init__(self, filename):
        SSSDChangeConf.__init__(self)
        self.filename = filename

        f = openLocked(self.filename, 0o600, False)
        self.opts = self.parse(f)
        f.close()

    def _backup_file(self, file_name):
        " Copy the file we operate on to a backup location "
        shutil.copy(file_name, file_name + self.backup_suffix)
        # make sure we don't leak data, force permissions on the backup
        os.chmod(file_name + self.backup_suffix, 0o600)

    def get_version(self):
        ver = self.get_option_index('sssd', 'config_file_version')[1]
        if not ver:
            return 1
        try:
            return int(ver['value'])
        except ValueError:
            raise SyntaxError('config_file_version not an integer')

    def rename_opts(self, parent_name, rename_kw, type='option'):
        for new_name, old_name in rename_kw.items():
            index, item = self.get_option_index(parent_name, old_name, type)
            if item:
                item['name'] = new_name

    def _add_dns_domain_name(self, domain):
        id_provider = self.findOpts(domain['value'], 'option', 'id_provider')[1]
        dns_domain_name = { 'type' : 'option',
                            'name' : 'dns_discovery_domain',
                            'value' : domain['name'].lstrip('domain/') }
        if id_provider['value'] == 'ldap':
            server = self.findOpts(domain['value'], 'option', 'ldap_uri')[1]
            if not server or "__srv__" in server['value']:
                domain['value'].insert(0, dns_domain_name)
                return
        elif id_provider['value'] == 'ipa':
            server = self.findOpts(domain['value'], 'option', 'ipa_server')[1]
            if not server or "__srv__" in server['value']:
                domain['value'].insert(0, dns_domain_name)
                return

        auth_provider = self.findOpts(domain['value'], 'option', 'auth_provider')[1]
        if auth_provider and auth_provider['value'] == 'krb5':
            server = self.findOpts(domain['value'], 'option', 'krb5_server')[1]
            if not server or "__srv__" in server['value']:
                domain['value'].insert(0, dns_domain_name)

    def _do_v2_changes(self):
        # remove Data Provider
        srvlist = self.get_option_index('sssd', 'services')[1]
        if srvlist:
            services = [ srv.strip() for srv in srvlist['value'].split(',') ]
            if 'dp' in services:
                services.remove('dp')
            srvlist['value'] = ", ".join([srv for srv in services])
        self.delete_option('section', 'dp')

        for domain in [ s for s in self.sections() if s['name'].startswith("domain/") ]:
            # remove magic_private_groups from all domains
            self.delete_option_subtree(domain['value'], 'option', 'magic_private_groups')
            # check if we need to add dns_domain
            self._add_dns_domain_name(domain)

    def _update_option(self, to_section_name, from_section_name, opts):
        to_section = [ s for s in self.sections() if s['name'].strip() == to_section_name ]
        from_section = [ s for s in self.sections() if s['name'].strip() == from_section_name ]

        if len(to_section) > 0 and len(from_section) > 0:
            vals = to_section[0]['value']
            for o in [one_opt for one_opt in from_section[0]['value'] if one_opt['name'] in opts]:
                updated = False
                for v in vals:
                    if v['type'] == 'empty':
                        continue
                    # if already in list, just update
                    if o['name'] == v['name']:
                        o['value'] = v['value']
                        updated = True
                # not in list, add there
                if not updated:
                    vals.insert(0, { 'name' : o['name'], 'type' : o['type'], 'value' : o['value'] })

    def _migrate_enumerate(self, domain):
        " Enumerate was special as it turned into bool from (0,1,2,3) enum "
        enum = self.findOpts(domain, 'option', 'enumerate')[1]
        if enum:
            if enum['value'].upper() not in ['TRUE', 'FALSE']:
                try:
                    enum['value'] = int(enum['value'])
                except ValueError:
                    raise ValueError('Cannot convert value %s in domain %s' % (enum['value'], domain['name']))

                if enum['value'] == 0:
                    enum['value'] = 'FALSE'
                elif enum['value'] > 0:
                    enum['value'] = 'TRUE'
                else:
                    raise ValueError('Cannot convert value %s in domain %s' % (enum['value'], domain['name']))

    def _migrate_domain(self, domain):
        # rename the section
        domain['name'] = domain['name'].strip().replace('domains', 'domain')

        # Generic options - new:old
        generic_kw = { 'min_id' : 'minId',
                       'max_id': 'maxId',
                       'timeout': 'timeout',
                       'magic_private_groups' : 'magicPrivateGroups',
                       'cache_credentials' : 'cache-credentials',
                       'id_provider' : 'provider',
                       'auth_provider' : 'auth-module',
                       'access_provider' : 'access-module',
                       'chpass_provider' : 'chpass-module',
                       'use_fully_qualified_names' : 'useFullyQualifiedNames',
                       'store_legacy_passwords' : 'store-legacy-passwords',
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
                    'ldap_netgroup_search_base' : 'netgroupSearchBase',
                    'ldap_netgroup_object_class' : 'netgroupObjectClass',
                    'ldap_netgroup_name' : 'netgroupName',
                    'ldap_netgroup_member' : 'netgroupMember',
                    'ldap_netgroup_triple' : 'netgroupTriple',
                    'ldap_netgroup_modify_timestamp' : 'netgroupModifyTimestamp',
                   }
        krb5_kw = { 'krb5_server' : 'krb5KDCIP',
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

        self._migrate_enumerate(domain['value'])
        self.rename_opts(domain['name'], generic_kw)
        self.rename_opts(domain['name'], proxy_kw)
        self.rename_opts(domain['name'], ldap_kw)
        self.rename_opts(domain['name'], krb5_kw)

        # remove obsolete libPath option
        self.delete_option_subtree(domain['value'], 'option', 'libPath')

        # configuration files before 0.5.0 did not enforce provider= in local domains
        # it did special-case by domain name (LOCAL)
        prvindex, prv = self.findOpts(domain['value'], 'option', 'id_provider')
        if not prv and domain['name'] == 'domain/LOCAL':
            prv = { 'type'  : 'option',
                    'name'  : 'id_provider',
                    'value' : 'local',
                  }
            domain['value'].insert(0, prv)

        # if domain was local, update with parameters from [user_defaults]
        if prv['value'] == 'local':
            self._update_option(domain['name'], 'user_defaults', user_defaults_kw.values())
            self.delete_option('section', 'user_defaults')
            self.rename_opts(domain['name'], user_defaults_kw)

        # if domain had provider = files, unroll that into provider=proxy, proxy_lib_name=files
        if prv['value'] == 'files':
            prv['value'] = 'proxy'
            libkw = { 'type'  : 'option',
                      'name'  : 'proxy_lib_name',
                      'value' : 'files',
                    }
            domain['value'].insert(prvindex+1, libkw)

    def _migrate_domains(self):
        for domain in [ s for s in self.sections() if s['name'].startswith("domains/") ]:
            self._migrate_domain(domain)

    def _update_if_exists(self, opt, to_name, from_section, from_name):
        index, item = self.get_option_index(from_section, from_name)
        if item:
            item['name'] = to_name
            opt.append(item)

    def _migrate_services(self):
        # [service] - options common to all services, no section as in v1
        service_kw = { 'reconnection_retries' : 'reconnection_retries',
                       'debug_level' : 'debug-level',
                       'debug_timestamps' : 'debug-timestamps',
                       'command' : 'command',
                       'timeout' : 'timeout',
                     }

        # rename services sections
        names_kw = { 'nss' : 'services/nss',
                     'pam' : 'services/pam',
                     'dp'  : 'services/dp',
                   }
        self.rename_opts(None, names_kw, 'section')

        # [sssd] - monitor service
        sssd_kw = [
                    { 'type'  : 'option',
                      'name'  : 'config_file_version',
                      'value' : '2',
                      'action': 'set',
                    }
                  ]
        self._update_if_exists(sssd_kw, 'domains',
                               'domains', 'domains')
        self._update_if_exists(sssd_kw, 'services',
                               'services', 'activeServices')
        self._update_if_exists(sssd_kw, 'sbus_timeout',
                               'services/monitor', 'sbusTimeout')
        self._update_if_exists(sssd_kw, 're_expression',
                              'names', 're-expression')
        self._update_if_exists(sssd_kw, 're_expression',
                              'names', 'full-name-format')
        self.add_section('sssd', sssd_kw)
        # update from general services section and monitor
        self._update_option('sssd', 'services', service_kw.values())
        self._update_option('sssd', 'services/monitor', service_kw.values())

        # [nss] - Name service
        nss_kw = { 'enum_cache_timeout' : 'EnumCacheTimeout',
                   'entry_cache_timeout' : 'EntryCacheTimeout',
                   'entry_cache_nowait_timeout' : 'EntryCacheNoWaitRefreshTimeout',
                   'entry_negative_timeout ' : 'EntryNegativeTimeout',
                   'filter_users' : 'filterUsers',
                   'filter_groups' : 'filterGroups',
                   'filter_users_in_groups' : 'filterUsersInGroups',
                   }
        nss_kw.update(service_kw)
        self._update_option('nss', 'services', service_kw.values())
        self.rename_opts('nss', nss_kw)

        # [pam] - Authentication service
        pam_kw = {}
        pam_kw.update(service_kw)
        self._update_option('pam', 'services', service_kw.values())
        self.rename_opts('pam', pam_kw)

        # remove obsolete sections
        self.delete_option('section', 'services')
        self.delete_option('section', 'names')
        self.delete_option('section', 'domains')
        self.delete_option('section', 'services/monitor')

    def v2_changes(self, out_file_name, backup=True):
        # read in the old file, make backup if needed
        if backup:
            self._backup_file(self.filename)

        self._do_v2_changes()

        # all done, write the file
        of = open(out_file_name, "wb")
        output = self.dump(self.opts)
        of.write(output)
        of.close()
        # make sure it has the right permissions too
        os.chmod(out_file_name, 0o600)

    def upgrade_v2(self, out_file_name, backup=True):
        # read in the old file, make backup if needed
        if backup:
            self._backup_file(self.filename)

        # do the migration to v2 format
        # do the upgrade
        self._migrate_services()
        self._migrate_domains()
        # also include any changes in the v2 format
        self._do_v2_changes()

        # all done, write the file
        of = open(out_file_name, "wb")
        output = self.dump(self.opts)
        of.write(output)
        of.close()
        # make sure it has the right permissions too
        os.chmod(out_file_name, 0o600)

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
        print(msg)

def main():
    options = parse_options()
    if not options:
        print >>sys.stderr, "Cannot parse options"
        return 1

    try:
        config = SSSDConfigFile(options.filename)
    except SyntaxError:
        verbose(traceback.format_exc(), options.verbose)
        print >>sys.stderr, "Cannot parse config file %s" % options.filename
        return 1
    except Exception as e:
        print("ERROR: %s" % e)
        verbose(traceback.format_exc(), options.verbose)
        return 1

    # make sure we keep strict settings when creating new files
    os.umask(0o077)

    version = config.get_version()
    if version == 2:
        verbose("Looks like v2, only checking changes", options.verbose)
        try:
            config.v2_changes(options.outfile, options.backup)
        except Exception as e:
            print("ERROR: %s" % e)
            verbose(traceback.format_exc(), options.verbose)
            return 1
    elif version == 1:
        verbose("Looks like v1, performing full upgrade", options.verbose)
        try:
            config.upgrade_v2(options.outfile, options.backup)
        except Exception as e:
            print("ERROR: %s" % e)
            verbose(traceback.format_exc(), options.verbose)
            return 1
    else:
        print("Can only upgrade from v1 to v2, file %s looks like version %d" % (options.filename, config.get_version()), file=sys.stderr)
        return 1

    return 0

if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

