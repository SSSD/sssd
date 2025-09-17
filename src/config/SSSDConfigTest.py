#!/usr/bin/env python
#  SSSD
#
#  SSSD Config API tests
#
#  Copyright (C) Red Hat
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
"""
Created on Sep 18, 2009

@author: sgallagh
"""
import unittest
import os
import shutil
import tempfile
from stat import ST_MODE, S_IMODE

import sys

srcdir = os.getenv('srcdir')
if srcdir:
    sys.path.insert(0, "./src/config")
    srcdir = srcdir + "/src/config"
else:
    srcdir = "."
import SSSDConfig  # noqa


def create_temp_dir():
    test_dir = os.environ.get('SSS_TEST_DIR') or "."
    return tempfile.mkdtemp(dir=test_dir)


def striplist(the_list):
    return ([x.strip() for x in the_list])


class SSSDConfigTestValid(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = create_temp_dir()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def testServices(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Validate services
        services = sssdconfig.list_services()
        self.assertTrue('sssd' in services)
        self.assertTrue('nss' in services)
        self.assertTrue('pam' in services)

        # Verify service attributes
        sssd_service = sssdconfig.get_service('sssd')
        service_opts = sssd_service.list_options()

        self.assertTrue('services' in service_opts.keys())
        service_list = sssd_service.get_option('services')
        self.assertTrue('nss' in service_list)
        self.assertTrue('pam' in service_list)

        self.assertTrue('domains' in service_opts)

        del sssdconfig
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.new_config()
        sssdconfig.delete_service('sssd')
        new_sssd_service = sssdconfig.new_service('sssd')
        new_options = new_sssd_service.list_options()

        self.assertTrue('debug_level' in new_options)
        self.assertEqual(new_options['debug_level'][0], int)

        self.assertTrue('command' in new_options)
        self.assertEqual(new_options['command'][0], str)

        self.assertTrue('services' in new_options)
        self.assertEqual(new_options['debug_level'][0], int)

        self.assertTrue('domains' in new_options)
        self.assertEqual(new_options['domains'][0], list)
        self.assertEqual(new_options['domains'][1], str)

        self.assertTrue('re_expression' in new_options)
        self.assertEqual(new_options['re_expression'][0], str)

        self.assertTrue('full_name_format' in new_options)
        self.assertEqual(new_options['full_name_format'][0], str)

        self.assertTrue('default_domain_suffix' in new_options)
        self.assertEqual(new_options['default_domain_suffix'][0], str)

        self.assertTrue('domain_resolution_order' in new_options)
        self.assertEqual(new_options['domain_resolution_order'][0], list)
        self.assertEqual(new_options['domain_resolution_order'][1], str)

        del sssdconfig

    def testDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Validate domain list
        domains = sssdconfig.list_domains()
        self.assertTrue('LDAP' in domains)
        self.assertTrue('PROXY' in domains)
        self.assertTrue('IPA' in domains)

        # Verify domain attributes
        ipa_domain = sssdconfig.get_domain('IPA')
        domain_opts = ipa_domain.list_options()
        self.assertTrue('debug_level' in domain_opts.keys())
        self.assertTrue('id_provider' in domain_opts.keys())
        self.assertTrue('auth_provider' in domain_opts.keys())
        self.assertEqual(ipa_domain.get_option('debug_level'), 0xff0)

        proxy_domain = sssdconfig.get_domain('PROXY')
        self.assertEqual(proxy_domain.get_option('debug_level'), 1)

        # Verify attributes in responders
        pam_responder = sssdconfig.get_service('pam')
        self.assertEqual(pam_responder.get_option('debug_level'), 2)

        sudo_responder = sssdconfig.get_service('sudo')
        self.assertEqual(sudo_responder.get_option('debug_level'), 0xfc10)

        del sssdconfig

    def testListProviders(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        sssdconfig.new_config()
        junk_domain = sssdconfig.new_domain('junk')
        providers = junk_domain.list_providers()
        self.assertTrue('ldap' in providers.keys())

    def testCreateNewLDAPConfig(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        sssdconfig.new_config()

        ldap_domain = sssdconfig.new_domain('LDAP')
        ldap_domain.add_provider('ldap', 'id')
        ldap_domain.set_option('debug_level', 1)
        ldap_domain.set_active(True)
        sssdconfig.save_domain(ldap_domain)

        of = self.tmp_dir + '/testCreateNewLDAPConfig.conf'

        # Ensure the output file doesn't exist
        try:
            os.unlink(of)
        except OSError:
            pass

        # Write out the file
        sssdconfig.write(of)

        # Verify that the output file has the correct permissions
        mode = os.stat(of)[ST_MODE]

        # Output files should not be readable or writable by
        # others, and should not be executable by anyone
        self.assertFalse(S_IMODE(mode) & 0o137)

        # try to import saved configuration file
        config = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                       srcdir + "/etc/sssd.api.d")
        config.import_config(configfile=of)

        # Remove the output file
        os.unlink(of)

    def testModifyExistingConfig(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        ldap_domain = sssdconfig.get_domain('LDAP')
        ldap_domain.set_option('debug_level', 3)

        ldap_domain.remove_provider('auth')
        ldap_domain.add_provider('krb5', 'auth')
        ldap_domain.set_active(True)
        sssdconfig.save_domain(ldap_domain)

        proxy_domain = sssdconfig.get_domain('PROXY')
        proxy_domain.set_option('debug_level', 0x1f10)
        sssdconfig.save_domain(proxy_domain)

        sudo_responder = sssdconfig.get_service('sudo')
        sudo_responder.set_option('debug_level', 0x2210)
        sssdconfig.save_service(sudo_responder)

        pam_responder = sssdconfig.get_service('pam')
        pam_responder.set_option('debug_level', 9)
        sssdconfig.save_service(pam_responder)

        of = self.tmp_dir + '/testModifyExistingConfig.conf'

        # Ensure the output file doesn't exist
        try:
            os.unlink(of)
        except OSError:
            pass

        # Write out the file
        sssdconfig.write(of)

        # Verify that the output file has the correct permissions
        mode = os.stat(of)[ST_MODE]

        # Output files should not be readable or writable by
        # others, and should not be executable by anyone
        self.assertFalse(S_IMODE(mode) & 0o137)

        # try to import saved configuration file
        config = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                       srcdir + "/etc/sssd.api.d")
        config.import_config(configfile=of)

        # test set_option 'debug_level' value

        # check internal state before parsing strings which is done in
        # get_domain or get_service
        debug_option = [x for x in config.options('domain/LDAP')
                        if x['name'] == 'debug_level']
        self.assertEqual(len(debug_option), 1)
        self.assertEqual(debug_option[0]['value'], '3')

        debug_option = [x for x in config.options('domain/PROXY')
                        if x['name'] == 'debug_level']
        self.assertEqual(len(debug_option), 1)
        self.assertEqual(debug_option[0]['value'], '0x1f10')

        debug_option = [x for x in config.options('sudo')
                        if x['name'] == 'debug_level']
        self.assertEqual(len(debug_option), 1)
        self.assertEqual(debug_option[0]['value'], '0x2210')

        debug_option = [x for x in config.options('pam')
                        if x['name'] == 'debug_level']
        self.assertEqual(len(debug_option), 1)
        self.assertEqual(debug_option[0]['value'], '9')

        # Remove the output file
        os.unlink(of)

    def testSpaces(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")
        ldap_domain = sssdconfig.get_domain('LDAP')
        self.assertEqual(ldap_domain.get_option('auth_provider'), 'ldap')
        self.assertEqual(ldap_domain.get_option('id_provider'), 'ldap')


class SSSDConfigTestInvalid(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testBadBool(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-invalid-badbool.conf")
        self.assertRaises(TypeError,
                          sssdconfig.get_domain, 'IPA')


class SSSDConfigTestSSSDService(unittest.TestCase):
    def setUp(self):
        self.schema = SSSDConfig.SSSDConfigSchema(srcdir + "/etc/sssd.api.conf",
                                                  srcdir + "/etc/sssd.api.d")

    def tearDown(self):
        pass

    def testInit(self):
        # Positive test
        SSSDConfig.SSSDService('sssd', self.schema)

        # Type Error test
        # Name is not a string
        self.assertRaises(TypeError, SSSDConfig.SSSDService, 3, self.schema)

        # TypeError test
        # schema is not an SSSDSchema
        self.assertRaises(TypeError, SSSDConfig.SSSDService, '3', self)

        # ServiceNotRecognizedError test
        self.assertRaises(SSSDConfig.ServiceNotRecognizedError,
                          SSSDConfig.SSSDService, 'ssd', self.schema)

    def testListOptions(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        options = service.list_options()
        control_list = [
            'services',
            'domains',
            'timeout',
            're_expression',
            'full_name_format',
            'krb5_rcache_dir',
            'user',
            'default_domain_suffix',
            'debug',
            'debug_level',
            'debug_timestamps',
            'debug_microseconds',
            'debug_backtrace_enabled',
            'command',
            'fd_limit',
            'client_idle_timeout',
            'responder_idle_timeout',
            'cache_first',
            'description',
            'certificate_verification',
            'override_space',
            'disable_netlink',
            'enable_files_domain',
            'domain_resolution_order',
            'try_inotify',
            'monitor_resolv_conf',
            'implicit_pac_responder',
            'core_dumpable',
            'passkey_verification',
        ]

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['services']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['services'][0] == list,
                        "services should require an list. "
                        "list_options is requiring a %s" %
                        options['services'][0])

        self.assertTrue(options['services'][1] == str,
                        "services should require a subtype of str. "
                        "list_options is requiring a %s" %
                        options['services'][1])

    def testListMandatoryOptions(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        options = service.list_mandatory_options()
        control_list = [
            'services',
            'domains']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['services']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['services'][0] == list,
                        "services should require an list. "
                        "list_options is requiring a %s" %
                        options['services'][0])

        self.assertTrue(options['services'][1] == str,
                        "services should require a subtype of str. "
                        "list_options is requiring a %s" %
                        options['services'][1])

    def testSetOption(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test - Exactly right
        service.set_option('debug_level', 2)
        self.assertEqual(service.get_option('debug_level'), 2)

        # Positive test - Allow converting "safe" values
        service.set_option('debug_level', '2')
        self.assertEqual(service.get_option('debug_level'), 2)

        # Positive test - Remove option if value is None
        service.set_option('debug_level', None)
        self.assertTrue('debug_level' not in service.options.keys())

        # Negative test - Nonexistent Option
        self.assertRaises(SSSDConfig.NoOptionError, service.set_option, 'nosuchoption', 1)

        # Negative test - Incorrect type
        self.assertRaises(TypeError, service.set_option, 'debug_level', 'two')

    def testGetOption(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test - List of values
        self.assertEqual(service.get_option('services'), ['nss', 'pam'])

        # Negative Test - Bad Option
        self.assertRaises(SSSDConfig.NoOptionError, service.get_option, 'nosuchoption')

    def testGetAllOptions(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test
        options = service.get_all_options()
        control_list = ['services']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testRemoveOption(self):
        service = SSSDConfig.SSSDService('sssd', self.schema)

        # Positive test - Remove an option that exists
        self.assertEqual(service.get_option('services'), ['nss', 'pam'])
        service.remove_option('services')
        self.assertRaises(SSSDConfig.NoOptionError, service.get_option, 'debug_level')

        # Positive test - Remove an option that doesn't exist
        self.assertRaises(SSSDConfig.NoOptionError, service.get_option, 'nosuchentry')
        service.remove_option('nosuchentry')


class SSSDConfigTestSSSDDomain(unittest.TestCase):
    def setUp(self):
        self.schema = SSSDConfig.SSSDConfigSchema(srcdir + "/etc/sssd.api.conf",
                                                  srcdir + "/etc/sssd.api.d")

    def tearDown(self):
        pass

    def testInit(self):
        # Positive Test
        SSSDConfig.SSSDDomain('mydomain', self.schema)

        # Negative Test - Name not a string
        self.assertRaises(TypeError, SSSDConfig.SSSDDomain, 2, self.schema)

        # Negative Test - Schema is not an SSSDSchema
        self.assertRaises(TypeError, SSSDConfig.SSSDDomain, 'mydomain', self)

    def testGetName(self):
        # Positive Test
        domain = SSSDConfig.SSSDDomain('mydomain', self.schema)

        self.assertEqual(domain.get_name(), 'mydomain')

    def testSetActive(self):
        # Positive Test
        domain = SSSDConfig.SSSDDomain('mydomain', self.schema)

        # Should default to inactive
        self.assertFalse(domain.active)
        domain.set_active(True)
        self.assertTrue(domain.active)
        domain.set_active(False)
        self.assertFalse(domain.active)

    def testListOptions(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # First test default options
        options = domain.list_options()
        control_list = [
            'description',
            'enabled',
            'debug',
            'debug_level',
            'debug_timestamps',
            'domain_type',
            'min_id',
            'max_id',
            'timeout',
            'offline_timeout',
            'offline_timeout_max',
            'offline_timeout_random_offset',
            'command',
            'enumerate',
            'cache_credentials',
            'cache_credentials_minimal_first_factor_length',
            'use_fully_qualified_names',
            'ignore_group_members',
            'filter_users',
            'filter_groups',
            'entry_cache_timeout',
            'entry_cache_user_timeout',
            'entry_cache_group_timeout',
            'entry_cache_netgroup_timeout',
            'entry_cache_service_timeout',
            'entry_cache_autofs_timeout',
            'entry_cache_sudo_timeout',
            'entry_cache_ssh_host_timeout',
            'entry_cache_resolver_timeout',
            'refresh_expired_interval',
            'lookup_family_order',
            'account_cache_expiration',
            'dns_resolver_server_timeout',
            'dns_resolver_op_timeout',
            'dns_resolver_timeout',
            'dns_discovery_domain',
            'failover_primary_timeout',
            'dyndns_update',
            'dyndns_update_per_family',
            'dyndns_ttl',
            'dyndns_iface',
            'dyndns_address',
            'dyndns_refresh_interval',
            'dyndns_refresh_interval_offset',
            'dyndns_update_ptr',
            'dyndns_force_tcp',
            'dyndns_auth',
            'dyndns_server',
            'dyndns_dot_cacert',
            'dyndns_dot_cert',
            'dyndns_dot_key',
            'override_gid',
            'case_sensitive',
            'override_homedir',
            'fallback_homedir',
            'homedir_substring',
            'override_shell',
            'default_shell',
            'pwd_expiration_warning',
            'id_provider',
            'auth_provider',
            'access_provider',
            'chpass_provider',
            'sudo_provider',
            'autofs_provider',
            'hostid_provider',
            'subdomains_provider',
            'selinux_provider',
            'session_provider',
            'resolver_provider',
            'realmd_tags',
            'subdomain_refresh_interval',
            'subdomain_refresh_interval_offset',
            'subdomain_inherit',
            'subdomain_homedir',
            'full_name_format',
            're_expression',
            'cached_auth_timeout',
            'auto_private_groups',
            'pam_gssapi_services',
            'pam_gssapi_check_upn',
            'pam_gssapi_indicators_map',
            'refresh_expired_interval',
            'refresh_expired_interval_offset',
            'local_auth_policy']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['max_id']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['max_id'][0] == int,
                        "max_id should require an int. "
                        "list_options is requiring a %s" %
                        options['max_id'][0])

        self.assertTrue(options['max_id'][1] is None,
                        "max_id should not require a subtype. "
                        "list_options is requiring a %s" %
                        options['max_id'][1])

        # Add a provider that has global options and verify that
        # The new options appear.
        domain.add_provider('krb5', 'auth')

        backup_list = control_list[:]
        control_list.extend(
            ['krb5_server',
             'krb5_backup_server',
             'krb5_realm',
             'krb5_kpasswd',
             'krb5_backup_kpasswd',
             'krb5_ccachedir',
             'krb5_ccname_template',
             'krb5_keytab',
             'krb5_validate',
             'krb5_store_password_if_offline',
             'krb5_auth_timeout',
             'krb5_renewable_lifetime',
             'krb5_lifetime',
             'krb5_renew_interval',
             'krb5_use_fast',
             'krb5_fast_principal',
             'krb5_fast_use_anonymous_pkinit',
             'krb5_canonicalize',
             'krb5_use_enterprise_principal',
             'krb5_use_subdomain_realm',
             'krb5_use_kdcinfo',
             'krb5_map_user'])

        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        control_list.extend(['krb5_kdcip'])

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Remove the auth domain and verify that the options
        # revert to the backup_list
        domain.remove_provider('auth')
        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in backup_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in backup_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testListMandatoryOptions(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # First test default options
        options = domain.list_mandatory_options()
        control_list = ['id_provider']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Add a provider that has global options and verify that
        # The new options appear.
        domain.add_provider('krb5', 'auth')

        backup_list = control_list[:]
        control_list.extend(['krb5_realm'])

        options = domain.list_mandatory_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Remove the auth domain and verify that the options
        # revert to the backup_list
        domain.remove_provider('auth')
        options = domain.list_mandatory_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in backup_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in backup_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testListProviders(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        control_provider_dict = {
            'ipa': ['id', 'auth', 'access', 'chpass', 'sudo', 'autofs',
                    'session', 'hostid', 'subdomains'],
            'ad': ['id', 'auth', 'access', 'chpass', 'sudo', 'autofs',
                   'subdomains', 'resolver'],
            'ldap': ['id', 'auth', 'access', 'chpass', 'sudo', 'autofs',
                     'resolver'],
            'krb5': ['auth', 'access', 'chpass'],
            'proxy': ['id', 'auth', 'chpass'],
            'simple': ['access'],
            'permit': ['access'],
            'deny': ['access']}

        providers = domain.list_providers()

        # Ensure that all of the expected defaults are there
        for provider in control_provider_dict.keys():
            for ptype in control_provider_dict[provider]:
                self.assertTrue(provider in providers)
                self.assertTrue(ptype in providers[provider])

        for provider in providers.keys():
            for ptype in providers[provider]:
                self.assertTrue(provider in control_provider_dict)
                self.assertTrue(ptype in control_provider_dict[provider])

    def testListProviderOptions(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Test looking up a specific provider type
        options = domain.list_provider_options('krb5', 'auth')
        control_list = [
            'krb5_server',
            'krb5_backup_server',
            'krb5_kdcip',
            'krb5_realm',
            'krb5_kpasswd',
            'krb5_backup_kpasswd',
            'krb5_ccachedir',
            'krb5_ccname_template',
            'krb5_keytab',
            'krb5_validate',
            'krb5_store_password_if_offline',
            'krb5_auth_timeout',
            'krb5_renewable_lifetime',
            'krb5_lifetime',
            'krb5_renew_interval',
            'krb5_use_fast',
            'krb5_fast_principal',
            'krb5_fast_use_anonymous_pkinit',
            'krb5_canonicalize',
            'krb5_use_enterprise_principal',
            'krb5_use_subdomain_realm',
            'krb5_use_kdcinfo',
            'krb5_map_user']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Test looking up all provider values
        options = domain.list_provider_options('krb5')
        control_list.extend(['krb5_kpasswd'])

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

    def testAddProvider(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive Test
        domain.add_provider('proxy', 'id')

        # Negative Test - No such backend type
        self.assertRaises(SSSDConfig.NoSuchProviderError,
                          domain.add_provider, 'nosuchbackend', 'auth')

        # Negative Test - No such backend subtype
        self.assertRaises(SSSDConfig.NoSuchProviderSubtypeError,
                          domain.add_provider, 'ldap', 'nosuchsubtype')

        # Negative Test - Try to add a second provider of the same type
        self.assertRaises(SSSDConfig.ProviderSubtypeInUse,
                          domain.add_provider, 'ldap', 'id')

    def testRemoveProvider(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # First test default options
        options = domain.list_options()
        control_list = [
            'description',
            'enabled',
            'debug',
            'debug_level',
            'debug_timestamps',
            'domain_type',
            'min_id',
            'max_id',
            'timeout',
            'offline_timeout',
            'offline_timeout_max',
            'offline_timeout_random_offset',
            'command',
            'enumerate',
            'cache_credentials',
            'cache_credentials_minimal_first_factor_length',
            'use_fully_qualified_names',
            'ignore_group_members',
            'filter_users',
            'filter_groups',
            'entry_cache_timeout',
            'entry_cache_user_timeout',
            'entry_cache_group_timeout',
            'entry_cache_netgroup_timeout',
            'entry_cache_service_timeout',
            'entry_cache_autofs_timeout',
            'entry_cache_sudo_timeout',
            'entry_cache_ssh_host_timeout',
            'entry_cache_resolver_timeout',
            'refresh_expired_interval',
            'account_cache_expiration',
            'lookup_family_order',
            'dns_resolver_server_timeout',
            'dns_resolver_op_timeout',
            'dns_resolver_timeout',
            'dns_discovery_domain',
            'failover_primary_timeout',
            'dyndns_update',
            'dyndns_update_per_family',
            'dyndns_ttl',
            'dyndns_iface',
            'dyndns_address',
            'dyndns_refresh_interval',
            'dyndns_update_ptr',
            'dyndns_force_tcp',
            'dyndns_auth',
            'dyndns_server',
            'dyndns_dot_cacert',
            'dyndns_dot_cert',
            'dyndns_dot_key',
            'override_gid',
            'case_sensitive',
            'override_homedir',
            'fallback_homedir',
            'homedir_substring',
            'override_shell',
            'default_shell',
            'pwd_expiration_warning',
            'id_provider',
            'auth_provider',
            'access_provider',
            'chpass_provider',
            'sudo_provider',
            'autofs_provider',
            'hostid_provider',
            'subdomains_provider',
            'selinux_provider',
            'session_provider',
            'resolver_provider',
            'realmd_tags',
            'subdomain_refresh_interval',
            'subdomain_refresh_interval_offset',
            'subdomain_inherit',
            'subdomain_homedir',
            'full_name_format',
            're_expression',
            'cached_auth_timeout',
            'auto_private_groups',
            'pam_gssapi_services',
            'pam_gssapi_check_upn',
            'pam_gssapi_indicators_map',
            'refresh_expired_interval',
            'refresh_expired_interval_offset',
            'dyndns_refresh_interval',
            'dyndns_refresh_interval_offset',
            'local_auth_policy']

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        self.assertTrue(type(options['max_id']) == tuple,
                        "Option values should be a tuple")

        self.assertTrue(options['max_id'][0] == int,
                        "max_id should require an int. "
                        "list_options is requiring a %s" %
                        options['max_id'][0])

        self.assertTrue(options['max_id'][1] is None,
                        "max_id should not require a subtype. "
                        "list_options is requiring a %s" %
                        options['max_id'][1])

        # Add a provider that has global options and verify that
        # The new options appear.
        domain.add_provider('krb5', 'auth')

        backup_list = control_list[:]
        control_list.extend(
            ['krb5_server',
             'krb5_backup_server',
             'krb5_kdcip',
             'krb5_realm',
             'krb5_kpasswd',
             'krb5_backup_kpasswd',
             'krb5_ccachedir',
             'krb5_ccname_template',
             'krb5_keytab',
             'krb5_validate',
             'krb5_store_password_if_offline',
             'krb5_auth_timeout',
             'krb5_renewable_lifetime',
             'krb5_lifetime',
             'krb5_renew_interval',
             'krb5_use_fast',
             'krb5_fast_principal',
             'krb5_fast_use_anonymous_pkinit',
             'krb5_canonicalize',
             'krb5_use_enterprise_principal',
             'krb5_use_subdomain_realm',
             'krb5_use_kdcinfo',
             'krb5_map_user'])

        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in control_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in control_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Add an LDAP one
        # LDAP ID providers can also use the krb5_realm
        domain.add_provider('ldap', 'id')

        # Set the krb5_realm option and the ldap_uri option
        domain.set_option('krb5_realm', 'EXAMPLE.COM')
        domain.set_option('ldap_uri', 'ldap://ldap.example.com')

        self.assertEqual(domain.get_option('krb5_realm'),
                         'EXAMPLE.COM')
        self.assertEqual(domain.get_option('ldap_uri'),
                         'ldap://ldap.example.com')

        # Remove the LDAP provider and verify that krb5_realm remains
        domain.remove_provider('id')
        self.assertEqual(domain.get_option('krb5_realm'),
                         'EXAMPLE.COM')
        self.assertFalse('ldap_uri' in domain.options)

        # Remove the auth domain and verify that the options
        # revert to the backup_list
        domain.remove_provider('auth')
        self.assertFalse('auth_provider' in domain.options)
        options = domain.list_options()

        self.assertTrue(type(options) == dict,
                        "Options should be a dictionary")

        # Ensure that all of the expected defaults are there
        for option in backup_list:
            self.assertTrue(option in options.keys(),
                            "Option [%s] missing" %
                            option)

        # Ensure that there aren't any unexpected options listed
        for option in options.keys():
            self.assertTrue(option in backup_list,
                            'Option [%s] unexpectedly found' %
                            option)

        # Ensure that the krb5_realm option is now gone
        self.assertFalse('krb5_realm' in domain.options)

        # Test removing nonexistent provider - Real
        domain.remove_provider('id')
        self.assertFalse('id_provider' in domain.options)

        # Test removing nonexistent provider - Bad backend type
        # Should pass without complaint
        domain.remove_provider('id')
        self.assertFalse('id_provider' in domain.options)

        # Test removing nonexistent provider - Bad provider type
        # Should pass without complaint
        domain.remove_provider('nosuchprovider')
        self.assertFalse('nosuchprovider_provider' in domain.options)

    def testGetOption(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Negative Test - Try to get valid option that is not set
        self.assertRaises(SSSDConfig.NoOptionError, domain.get_option, 'max_id')

        # Positive Test - Set the above option and get it
        domain.set_option('max_id', 10000)
        self.assertEqual(domain.get_option('max_id'), 10000)

        # Negative Test - Try yo get invalid option
        self.assertRaises(SSSDConfig.NoOptionError, domain.get_option, 'nosuchoption')

    def testSetOption(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive Test
        domain.set_option('max_id', 10000)
        self.assertEqual(domain.get_option('max_id'), 10000)

        # Positive Test - Remove option if value is None
        domain.set_option('max_id', None)
        self.assertTrue('max_id' not in domain.get_all_options().keys())

        # Negative Test - invalid option
        self.assertRaises(SSSDConfig.NoOptionError, domain.set_option, 'nosuchoption', 1)

        # Negative Test - incorrect type
        self.assertRaises(TypeError, domain.set_option, 'max_id', 'a string')

        # Positive Test - Coax options to appropriate type
        domain.set_option('max_id', '10000')
        self.assertEqual(domain.get_option('max_id'), 10000)

        domain.set_option('max_id', 30.2)
        self.assertEqual(domain.get_option('max_id'), 30)

    def testRemoveOption(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive test - Remove unset but valid option
        self.assertFalse('max_id' in domain.get_all_options().keys())
        domain.remove_option('max_id')
        self.assertFalse('max_id' in domain.get_all_options().keys())

        # Positive test - Remove unset and unknown option
        self.assertFalse('nosuchoption' in domain.get_all_options().keys())
        domain.remove_option('nosuchoption')
        self.assertFalse('nosuchoption' in domain.get_all_options().keys())

    def testSetName(self):
        domain = SSSDConfig.SSSDDomain('sssd', self.schema)

        # Positive test - Change the name once
        domain.set_name('sssd2')
        self.assertEqual(domain.get_name(), 'sssd2')
        self.assertEqual(domain.oldname, 'sssd')

        # Positive test - Change the name a second time
        domain.set_name('sssd3')
        self.assertEqual(domain.get_name(), 'sssd3')
        self.assertEqual(domain.oldname, 'sssd')

        # Negative test - try setting the name to a non-string
        self.assertRaises(TypeError,
                          domain.set_name, 4)


class SSSDConfigTestSSSDConfig(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = create_temp_dir()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def testInit(self):
        # Positive test
        SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                              srcdir + "/etc/sssd.api.d")

        # Negative Test - No Such File
        self.assertRaises(IOError,
                          SSSDConfig.SSSDConfig, "nosuchfile.api.conf", srcdir + "/etc/sssd.api.d")

        # Negative Test - Schema is not parsable
        self.assertRaises(SSSDConfig.ParsingError,
                          SSSDConfig.SSSDConfig, srcdir + "/testconfigs/noparse.api.conf", srcdir + "/etc/sssd.api.d")

    def testImportConfig(self):
        # Positive Test
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Verify that all sections were imported
        control_list = [
            'sssd',
            'nss',
            'pam',
            'sudo',
            'domain/PROXY',
            'domain/IPA',
            'domain/LDAP',
            'domain/INVALIDPROVIDER',
            'domain/INVALIDOPTION',
        ]

        for section in control_list:
            self.assertTrue(sssdconfig.has_section(section),
                            "Section [%s] missing" %
                            section)
        for section in sssdconfig.sections():
            self.assertTrue(section['name'] in control_list)

        # Verify that all options were imported for a section
        control_list = [
            'services',
            'domains',
            'debug_timestamps']

        for option in control_list:
            self.assertTrue(sssdconfig.has_option('sssd', option),
                            "Option [%s] missing from [sssd]" %
                            option)
        for option in sssdconfig.options('sssd'):
            if option['type'] in ('empty', 'comment'):
                continue
            self.assertTrue(option['name'] in control_list,
                            "Option [%s] unexpectedly found" %
                            option)

        # TODO: Check the types and values of the settings

        # Negative Test - Missing config file
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        self.assertRaises(IOError, sssdconfig.import_config, "nosuchfile.conf")

        # Negative Test - Invalid config file
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        self.assertRaises(SSSDConfig.ParsingError, sssdconfig.import_config, srcdir + "/testconfigs/sssd-invalid.conf")

        # Negative Test - Already initialized
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")
        self.assertRaises(SSSDConfig.AlreadyInitializedError,
                          sssdconfig.import_config, srcdir + "/testconfigs/sssd-valid.conf")

    def testImportConfigNoVersion(self):
        # Positive Test
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(
            srcdir + "/testconfigs/sssd-noversion.conf"
        )

        # Validate services
        services = sssdconfig.list_services()
        self.assertTrue('sssd' in services)
        self.assertTrue('nss' in services)
        self.assertTrue('pam' in services)
        self.assertTrue('dp' in services)

        # Verify service attributes
        sssd_service = sssdconfig.get_service('sssd')
        service_opts = sssd_service.list_options()

        self.assertTrue('services' in service_opts.keys())
        service_list = sssd_service.get_option('services')
        self.assertTrue('nss' in service_list)
        self.assertTrue('pam' in service_list)

        # Validate domain list
        domains = sssdconfig.list_domains()
        self.assertTrue('LDAP' in domains)
        self.assertTrue('PROXY' in domains)
        self.assertTrue('IPA' in domains)

        # Verify domain attributes
        ipa_domain = sssdconfig.get_domain('IPA')
        domain_opts = ipa_domain.list_options()
        self.assertTrue('debug_level' in domain_opts.keys())
        self.assertTrue('id_provider' in domain_opts.keys())
        self.assertTrue('auth_provider' in domain_opts.keys())

        # Verify domain attributes
        proxy_domain = sssdconfig.get_domain('PROXY')
        domain_opts = proxy_domain.list_options()
        self.assertTrue('debug_level' in domain_opts.keys())
        self.assertTrue('id_provider' in domain_opts.keys())
        self.assertTrue('auth_provider' in domain_opts.keys())

        # Verify domain attributes
        ldap_domain = sssdconfig.get_domain('LDAP')
        domain_opts = ldap_domain.list_options()
        self.assertTrue('debug_level' in domain_opts.keys())
        self.assertTrue('id_provider' in domain_opts.keys())
        self.assertTrue('auth_provider' in domain_opts.keys())

        domain_control_list = [
            'cache_credentials',
            'id_provider',
            'auth_provider',
            'access_provider',
            'autofs_provider',
            'chpass_provider',
            'sudo_provider',
            'subdomains_provider',
            'resolver_provider',
            'default_shell',
            'fallback_homedir',
            'cache_credentials',
            'use_fully_qualified_names',
        ]

        ad_domain = sssdconfig.get_domain("ad.example.com")

        for option in ad_domain.get_all_options():
            self.assertTrue(option in domain_control_list)

        negative_domain_control_list = [
            'ad_server',
            'ldap_id_mapping',
            'ldap_sasl_authid',
            'selinux_provider',
            'hostid_provider',
            'session_provider',
        ]

        for option in ad_domain.get_all_options():
            self.assertFalse(option in negative_domain_control_list)

    def testNewConfig(self):
        # Positive Test
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.new_config()

        # Check that the defaults were set
        control_list = [
            'sssd',
            'nss',
            'pam',
            'sudo',
            'autofs',
            'ssh',
            'pac',
            'ifp',
            'session_recording']
        for section in control_list:
            self.assertTrue(sssdconfig.has_section(section),
                            "Section [%s] missing" %
                            section)
        for section in sssdconfig.sections():
            self.assertTrue(section['name'] in control_list)

        control_list = ['services']
        for option in control_list:
            self.assertTrue(sssdconfig.has_option('sssd', option),
                            "Option [%s] missing from [sssd]" %
                            option)
        for option in sssdconfig.options('sssd'):
            if option['type'] in ('empty', 'comment'):
                continue
            self.assertTrue(option['name'] in control_list,
                            "Option [%s] unexpectedly found" %
                            option)

        # Negative Test - Already Initialized
        self.assertRaises(SSSDConfig.AlreadyInitializedError, sssdconfig.new_config)

    def testWrite(self):
        # TODO Write tests to compare output files
        pass

    def testListActiveServices(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not Initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.list_active_services)

        # Positive Test
        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        control_list = [
            'nss',
            'pam']
        active_services = sssdconfig.list_active_services()
        self.assertTrue(isinstance(active_services, list))

        for service in control_list:
            self.assertTrue(service in active_services,
                            "Service [%s] missing" %
                            service)
        for service in active_services:
            self.assertTrue(service in control_list,
                            "Service [%s] unexpectedly found" %
                            service)

    def testListInactiveServices(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not Initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.list_inactive_services)

        # Positive Test
        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        control_list = [
            'sssd',
            'sudo']
        inactive_services = sssdconfig.list_inactive_services()

        for service in control_list:
            self.assertTrue(service in inactive_services,
                            "Service [%s] missing" %
                            service)
        for service in inactive_services:
            self.assertTrue(service in control_list,
                            "Service [%s] unexpectedly found" %
                            service)

    def testListServices(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - sssdconfig not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.list_services)

        sssdconfig.new_config()

        control_list = [
            'sssd',
            'pam',
            'nss',
            'sudo',
            'autofs',
            'ssh',
            'pac',
            'ifp',
            'session_recording']
        service_list = sssdconfig.list_services()
        for service in control_list:
            self.assertTrue(service in service_list,
                            "Service [%s] missing" %
                            service)
        for service in service_list:
            self.assertTrue(service in control_list,
                            "Service [%s] unexpectedly found" %
                            service)

    def testGetService(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.get_service, 'sssd')

        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        service = sssdconfig.get_service('sssd')
        self.assertTrue(isinstance(service, SSSDConfig.SSSDService))

        # Verify the contents of this service
        self.assertEqual(type(service.get_option('debug_timestamps')), bool)
        self.assertFalse(service.get_option('debug_timestamps'))

        # Negative Test - No such service
        self.assertRaises(SSSDConfig.NoServiceError, sssdconfig.get_service, 'nosuchservice')

        # Positive test - Service with invalid option loads
        # but ignores the invalid option
        service = sssdconfig.get_service('pam')
        self.assertFalse('nosuchoption' in service.options)

    def testNewService(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.new_service, 'sssd')

        sssdconfig.new_config()

        # Positive Test
        # First need to remove the existing service
        sssdconfig.delete_service('sssd')
        service = sssdconfig.new_service('sssd')
        self.assertTrue(service.get_name() in sssdconfig.list_services())

        # TODO: check that the values of this new service
        # are set to the defaults from the schema

    def testDeleteService(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.delete_service, 'sssd')

        sssdconfig.new_config()

        # Positive Test
        sssdconfig.delete_service('sssd')

    def testSaveService(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        new_service = SSSDConfig.SSSDService('sssd', sssdconfig.schema)

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.save_service, new_service)

        # Positive Test
        sssdconfig.new_config()
        sssdconfig.save_service(new_service)

        # TODO: check that all entries were saved correctly (change a few)

        # Negative Test - Type Error
        self.assertRaises(TypeError, sssdconfig.save_service, self)

    def testActivateService(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        service_name = 'sudo'

        # Negative test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError,
                          sssdconfig.activate_service, service_name)

        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Positive test - Activate an inactive service
        self.assertTrue(service_name in sssdconfig.list_services())
        self.assertFalse(service_name in sssdconfig.list_active_services())
        self.assertTrue(service_name in sssdconfig.list_inactive_services())

        sssdconfig.activate_service(service_name)
        self.assertTrue(service_name in sssdconfig.list_services())
        self.assertTrue(service_name in sssdconfig.list_active_services())
        self.assertFalse(service_name in sssdconfig.list_inactive_services())

        # Positive test - Activate an active service
        # This should succeed
        sssdconfig.activate_service(service_name)
        self.assertTrue(service_name in sssdconfig.list_services())
        self.assertTrue(service_name in sssdconfig.list_active_services())
        self.assertFalse(service_name in sssdconfig.list_inactive_services())

        # Negative test - Invalid service name
        self.assertRaises(SSSDConfig.NoServiceError,
                          sssdconfig.activate_service, 'nosuchservice')

        # Negative test - Invalid service name type
        self.assertRaises(SSSDConfig.NoServiceError,
                          sssdconfig.activate_service, self)

    def testDeactivateService(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        service_name = 'pam'

        # Negative test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError,
                          sssdconfig.activate_service, service_name)

        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Positive test -Deactivate an active service
        self.assertTrue(service_name in sssdconfig.list_services())
        self.assertTrue(service_name in sssdconfig.list_active_services())
        self.assertFalse(service_name in sssdconfig.list_inactive_services())

        sssdconfig.deactivate_service(service_name)
        self.assertTrue(service_name in sssdconfig.list_services())
        self.assertFalse(service_name in sssdconfig.list_active_services())
        self.assertTrue(service_name in sssdconfig.list_inactive_services())

        # Positive test - Deactivate an inactive service
        # This should succeed
        sssdconfig.deactivate_service(service_name)
        self.assertTrue(service_name in sssdconfig.list_services())
        self.assertFalse(service_name in sssdconfig.list_active_services())
        self.assertTrue(service_name in sssdconfig.list_inactive_services())

        # Negative test - Invalid service name
        self.assertRaises(SSSDConfig.NoServiceError,
                          sssdconfig.activate_service, 'nosuchservice')

        # Negative test - Invalid service name type
        self.assertRaises(SSSDConfig.NoServiceError,
                          sssdconfig.activate_service, self)

    def testListActiveDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not Initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.list_active_domains)

        # Positive Test
        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        control_list = [
            'IPA']
        active_domains = sssdconfig.list_active_domains()
        self.assertTrue(isinstance(active_domains, list))

        for domain in control_list:
            self.assertTrue(domain in active_domains,
                            "Domain [%s] missing" %
                            domain)
        for domain in active_domains:
            self.assertTrue(domain in control_list,
                            "Domain [%s] unexpectedly found" %
                            domain)

    def testListInactiveDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not Initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.list_inactive_domains)

        # Positive Test
        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        control_list = [
            'PROXY',
            'LDAP',
            'INVALIDPROVIDER',
            'INVALIDOPTION',
        ]
        inactive_domains = sssdconfig.list_inactive_domains()

        for domain in control_list:
            self.assertTrue(domain in inactive_domains,
                            "Domain [%s] missing" %
                            domain)
        for domain in inactive_domains:
            self.assertTrue(domain in control_list,
                            "Domain [%s] unexpectedly found" %
                            domain)

    def testListDomains(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not Initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.list_domains)

        # Positive Test
        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        control_list = [
            'IPA',
            'PROXY',
            'LDAP',
            'INVALIDPROVIDER',
            'INVALIDOPTION',
        ]
        domains = sssdconfig.list_domains()

        for domain in control_list:
            self.assertTrue(domain in domains,
                            "Domain [%s] missing" %
                            domain)
        for domain in domains:
            self.assertTrue(domain in control_list,
                            "Domain [%s] unexpectedly found" %
                            domain)

    def testListWithInvalidDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not Initialized
        self.assertRaises(SSSDConfig.NotInitializedError,
                          sssdconfig.list_domains)

        # Positive Test
        sssdconfig.import_config(
            srcdir + '/testconfigs/sssd-nonexisting-services-domains.conf'
        )

        domains = sssdconfig.list_active_domains()
        self.assertTrue("active" in domains and len(domains) == 1,
                        "domain 'active' not found among active domains")

        domains = sssdconfig.list_inactive_domains()
        self.assertTrue("inactive" in domains and len(domains) == 1,
                        "domain 'inactive' not found among inactive domains")

        services = sssdconfig.list_active_services()
        self.assertTrue("nss" in services and len(services) == 1,
                        "service 'nss' not found among active services")

        services = sssdconfig.list_inactive_services()
        self.assertTrue(len(services) == 2,
                        "unexpected count of inactive services")
        for service in ("sssd", "pam"):
            self.assertTrue(service in services,
                            "service '%s' not found among inactive services"
                            % service)

    def testGetDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.get_domain, 'sssd')

        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        domain = sssdconfig.get_domain('IPA')
        self.assertTrue(isinstance(domain, SSSDConfig.SSSDDomain))
        self.assertTrue(domain.active)

        domain = sssdconfig.get_domain('LDAP')
        self.assertTrue(isinstance(domain, SSSDConfig.SSSDDomain))
        self.assertFalse(domain.active)

        # TODO verify the contents of this domain
        self.assertTrue(domain.get_option('ldap_id_use_start_tls'))
        self.assertTrue(domain.get_option('ldap_sudo_include_regexp'))
        self.assertTrue(domain.get_option('ldap_autofs_map_master_name'))

        # Negative Test - No such domain
        self.assertRaises(SSSDConfig.NoDomainError, sssdconfig.get_domain, 'nosuchdomain')

        # Positive Test - Domain with unknown provider
        # Expected result: Domain is imported, but does not contain the
        # unknown provider entry
        domain = sssdconfig.get_domain('INVALIDPROVIDER')
        self.assertFalse('chpass_provider' in domain.options)

        # Positive Test - Domain with unknown option
        # Expected result: Domain is imported, but does not contain the
        # unknown option entry
        domain = sssdconfig.get_domain('INVALIDOPTION')
        self.assertFalse('nosuchoption' in domain.options)

    def testNewDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.new_domain, 'example.com')

        sssdconfig.new_config()

        # Positive Test
        domain = sssdconfig.new_domain('example.com')
        self.assertTrue(isinstance(domain, SSSDConfig.SSSDDomain))
        self.assertTrue(domain.get_name() in sssdconfig.list_domains())
        self.assertTrue(domain.get_name() in sssdconfig.list_inactive_domains())

        # TODO: check that the values of this new domain
        # are set to the defaults from the schema

    def testDeleteDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.delete_domain, 'IPA')

        # Positive Test
        sssdconfig.import_config(srcdir + '/testconfigs/sssd-valid.conf')

        self.assertTrue('IPA' in sssdconfig.list_domains())
        self.assertTrue('IPA' in sssdconfig.list_active_domains())
        self.assertTrue(sssdconfig.has_section('domain/IPA'))
        sssdconfig.delete_domain('IPA')
        self.assertFalse('IPA' in sssdconfig.list_domains())
        self.assertFalse('IPA' in sssdconfig.list_active_domains())
        self.assertFalse(sssdconfig.has_section('domain/IPA'))

    def testSaveDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        # Negative Test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError, sssdconfig.save_domain, 'IPA')

        # Positive Test
        sssdconfig.new_config()
        domain = sssdconfig.new_domain('example.com')
        domain.add_provider('ldap', 'id')
        domain.set_option('ldap_uri', 'ldap://ldap.example.com')
        domain.set_active(True)
        sssdconfig.save_domain(domain)

        self.assertTrue('example.com' in sssdconfig.list_domains())
        self.assertTrue('example.com' in sssdconfig.list_active_domains())
        self.assertEqual(sssdconfig.get('domain/example.com', 'ldap_uri'),
                         'ldap://ldap.example.com')

        # Negative Test - Type Error
        self.assertRaises(TypeError, sssdconfig.save_domain, self)

        # Positive test - Change the domain name and save it
        domain.set_name('example.com2')
        self.assertEqual(domain.name, 'example.com2')
        self.assertEqual(domain.oldname, 'example.com')
        sssdconfig.save_domain(domain)

        self.assertTrue('example.com2' in sssdconfig.list_domains())
        self.assertTrue('example.com2' in sssdconfig.list_active_domains())
        self.assertTrue(sssdconfig.has_section('domain/example.com2'))
        self.assertEqual(sssdconfig.get('domain/example.com2',
                                        'ldap_uri'),
                         'ldap://ldap.example.com')
        self.assertFalse('example.com' in sssdconfig.list_domains())
        self.assertFalse('example.com' in sssdconfig.list_active_domains())
        self.assertFalse('example.com' in sssdconfig.list_inactive_domains())
        self.assertFalse(sssdconfig.has_section('domain/example.com'))
        self.assertEqual(domain.oldname, None)

        # Positive test - Set the domain inactive and save it
        activelist = sssdconfig.list_active_domains()
        inactivelist = sssdconfig.list_inactive_domains()

        domain.set_active(False)
        sssdconfig.save_domain(domain)

        self.assertFalse('example.com2' in sssdconfig.list_active_domains())
        self.assertTrue('example.com2' in sssdconfig.list_inactive_domains())

        self.assertEqual(len(sssdconfig.list_active_domains()),
                         len(activelist) - 1)
        self.assertEqual(len(sssdconfig.list_inactive_domains()),
                         len(inactivelist) + 1)

        # Positive test - Set the domain active and save it
        activelist = sssdconfig.list_active_domains()
        inactivelist = sssdconfig.list_inactive_domains()
        domain.set_active(True)
        sssdconfig.save_domain(domain)

        self.assertTrue('example.com2' in sssdconfig.list_active_domains())
        self.assertFalse('example.com2' in sssdconfig.list_inactive_domains())

        self.assertEqual(len(sssdconfig.list_active_domains()),
                         len(activelist) + 1)
        self.assertEqual(len(sssdconfig.list_inactive_domains()),
                         len(inactivelist) - 1)

        # Positive test - Set the domain inactive and save it
        activelist = sssdconfig.list_active_domains()
        inactivelist = sssdconfig.list_inactive_domains()

        sssdconfig.deactivate_domain(domain.get_name())

        self.assertFalse('example.com2' in sssdconfig.list_active_domains())
        self.assertTrue('example.com2' in sssdconfig.list_inactive_domains())

        self.assertEqual(len(sssdconfig.list_active_domains()),
                         len(activelist) - 1)
        self.assertEqual(len(sssdconfig.list_inactive_domains()),
                         len(inactivelist) + 1)

        # Positive test - Set the domain active and save it
        activelist = sssdconfig.list_active_domains()
        inactivelist = sssdconfig.list_inactive_domains()

        sssdconfig.activate_domain(domain.get_name())

        self.assertTrue('example.com2' in sssdconfig.list_active_domains())
        self.assertFalse('example.com2' in sssdconfig.list_inactive_domains())

        self.assertEqual(len(sssdconfig.list_active_domains()),
                         len(activelist) + 1)
        self.assertEqual(len(sssdconfig.list_inactive_domains()),
                         len(inactivelist) - 1)

        # Positive test - Ensure that saved domains retain values
        domain.set_option('ldap_krb5_init_creds', True)
        domain.set_option('ldap_id_use_start_tls', False)
        domain.set_option('ldap_user_search_base',
                          'cn=accounts, dc=example, dc=com')
        self.assertTrue(domain.get_option('ldap_krb5_init_creds'))
        self.assertFalse(domain.get_option('ldap_id_use_start_tls'))
        self.assertEqual(domain.get_option('ldap_user_search_base'),
                         'cn=accounts, dc=example, dc=com')

        sssdconfig.save_domain(domain)

        of = self.tmp_dir + '/testSaveDomain.out'

        # Ensure the output file doesn't exist
        try:
            os.unlink(of)
        except OSError:
            pass

        # Write out the file
        sssdconfig.write(of)

        # Verify that the output file has the correct permissions
        mode = os.stat(of)[ST_MODE]

        # Output files should not be readable or writable by
        # others, and should not be executable by anyone
        self.assertFalse(S_IMODE(mode) & 0o137)

        # Remove the output file
        os.unlink(of)

        domain2 = sssdconfig.get_domain('example.com2')
        self.assertTrue(domain2.get_option('ldap_krb5_init_creds'))
        self.assertFalse(domain2.get_option('ldap_id_use_start_tls'))

    def testActivateDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        domain_name = 'PROXY'

        # Negative test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError,
                          sssdconfig.activate_domain, domain_name)

        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Positive test - Activate an inactive domain
        self.assertTrue(domain_name in sssdconfig.list_domains())
        self.assertFalse(domain_name in sssdconfig.list_active_domains())
        self.assertTrue(domain_name in sssdconfig.list_inactive_domains())

        sssdconfig.activate_domain('PROXY')
        self.assertTrue(domain_name in sssdconfig.list_domains())
        self.assertTrue(domain_name in sssdconfig.list_active_domains())
        self.assertFalse(domain_name in sssdconfig.list_inactive_domains())

        # Positive test - Activate an active domain
        # This should succeed
        sssdconfig.activate_domain('PROXY')
        self.assertTrue(domain_name in sssdconfig.list_domains())
        self.assertTrue(domain_name in sssdconfig.list_active_domains())
        self.assertFalse(domain_name in sssdconfig.list_inactive_domains())

        # Negative test - Invalid domain name
        self.assertRaises(SSSDConfig.NoDomainError,
                          sssdconfig.activate_domain, 'nosuchdomain')

        # Negative test - Invalid domain name type
        self.assertRaises(SSSDConfig.NoDomainError,
                          sssdconfig.activate_domain, self)

    def testDeactivateDomain(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        domain_name = 'IPA'

        # Negative test - Not initialized
        self.assertRaises(SSSDConfig.NotInitializedError,
                          sssdconfig.activate_domain, domain_name)

        sssdconfig.import_config(srcdir + "/testconfigs/sssd-valid.conf")

        # Positive test -Deactivate an active domain
        self.assertTrue(domain_name in sssdconfig.list_domains())
        self.assertTrue(domain_name in sssdconfig.list_active_domains())
        self.assertFalse(domain_name in sssdconfig.list_inactive_domains())

        sssdconfig.deactivate_domain(domain_name)
        self.assertTrue(domain_name in sssdconfig.list_domains())
        self.assertFalse(domain_name in sssdconfig.list_active_domains())
        self.assertTrue(domain_name in sssdconfig.list_inactive_domains())

        # Positive test - Deactivate an inactive domain
        # This should succeed
        sssdconfig.deactivate_domain(domain_name)
        self.assertTrue(domain_name in sssdconfig.list_domains())
        self.assertFalse(domain_name in sssdconfig.list_active_domains())
        self.assertTrue(domain_name in sssdconfig.list_inactive_domains())

        # Negative test - Invalid domain name
        self.assertRaises(SSSDConfig.NoDomainError,
                          sssdconfig.activate_domain, 'nosuchdomain')

        # Negative test - Invalid domain name type
        self.assertRaises(SSSDConfig.NoDomainError,
                          sssdconfig.activate_domain, self)

    def testParse(self):
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")

        with open(srcdir + "/testconfigs/sssd-test-parse.conf", "r") as f:
            data = sssdconfig.parse(f)

        self.assertEqual(len(data), 5)
        self.assertEqual(data[-2], {'type': "section",
                                    'name': "nss",
                                    'value': [{'type': 'option',
                                               'name': 'debug_level',
                                               'value': '1'},
                                              {'type': 'empty',
                                               'name': 'empty'}]})
        self.assertEqual(data[-1], {'type': "section",
                                    'name': "pam",
                                    'value': [{'type': 'empty',
                                               'name': 'empty'}]})


        with open(srcdir + "/testconfigs/sssd-valid.conf", "r") as f:
            data = sssdconfig.parse(f)

        self.assertEqual(len(data), 9)
        self.assertEqual(data[-1], {'name': "sudo",
                                    'type': "section",
                                    'value': [{'type': 'option',
                                               'name': 'debug_level',
                                               'value': '0xfC10'}]})

    def testEnabledOption(self):
        """Test the new enabled option."""
        # Positive Test
        sssdconfig = SSSDConfig.SSSDConfig(srcdir + "/etc/sssd.api.conf",
                                           srcdir + "/etc/sssd.api.d")
        sssdconfig.import_config(srcdir + "/testconfigs/sssd-enabled-option.conf")

        # Verify that all sections were imported
        control_list = [
            'nss',
            'sssd',
            'pam',
            'domain/enabled_1',
            'domain/enabled_2',
            'domain/enabled_3',
            'domain/disabled_1',
            'domain/disabled_2',
            'domain/disabled_3',
        ]

        for section in control_list:
            self.assertTrue(sssdconfig.has_section(section),
                            "Section [%s] missing" %
                            section)
        for section in sssdconfig.sections():
            self.assertTrue(section['name'] in control_list)

        # Verify that all options were imported for [sssd] section
        control_list = [
            'services',
            'domains',
            'debug_timestamps']

        for option in control_list:
            self.assertTrue(sssdconfig.has_option('sssd', option),
                            "Option [%s] missing from [sssd]" %
                            option)
        for option in sssdconfig.options('sssd'):
            if option['type'] in ('empty', 'comment'):
                continue
            self.assertTrue(option['name'] in control_list,
                            "Option [%s] unexpectedly found" %
                            option)

        # Verify enabled domains
        control_list = [
            'enabled_1',
            'enabled_2',
            'enabled_3']

        if (sssdconfig.has_option('sssd', 'domains')):
            sssd_domains = striplist(sssdconfig.get('sssd', 'domains').split(','))
            domain_dict = dict.fromkeys(sssd_domains)
            if '' in domain_dict:
                del domain_dict['']
            sssd_domains = list(domain_dict)
        else:
            sssd_domains = []

        for domain in sssdconfig.list_active_domains():
            self.assertTrue(domain in control_list,
                            "Domain [domain/%s] should be disabled" % domain)
        for domain in control_list:
            self.assertTrue(domain in sssdconfig.list_active_domains(),
                            "Domain [domain/%s] should be enabled" % domain)

        # Verify disabled domains
        control_list = [
            'disabled_1',
            'disabled_2',
            'disabled_3']

        for domain in sssdconfig.list_inactive_domains():
            self.assertTrue(domain in control_list,
                            "Domain [domain/%s] should be enabled" % domain)
        for domain in control_list:
            self.assertTrue(domain in sssdconfig.list_inactive_domains(),
                            "Domain [domain/%s] should be disabled" % domain)


if __name__ == "__main__":
    error = 0

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestSSSDService)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x1

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestSSSDDomain)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x2

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestSSSDConfig)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x4

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestValid)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x8

    suite = unittest.TestLoader().loadTestsFromTestCase(SSSDConfigTestInvalid)
    res = unittest.TextTestRunner().run(suite)
    if not res.wasSuccessful():
        error |= 0x10

    sys.exit(error)
