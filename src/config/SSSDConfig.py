'''
Created on Sep 18, 2009

@author: sgallagh
'''

import os
import gettext
import exceptions
from ipachangeconf import SSSDChangeConf

# Exceptions
class SSSDConfigException(Exception): pass
class ParsingError(Exception): pass
class AlreadyInitializedError(SSSDConfigException): pass
class NotInitializedError(SSSDConfigException): pass
class NoOutputFileError(SSSDConfigException): pass
class NoServiceError(SSSDConfigException): pass
class NoSectionError(SSSDConfigException): pass
class NoOptionError(SSSDConfigException): pass
class ServiceNotRecognizedError(SSSDConfigException): pass
class ServiceAlreadyExists(SSSDConfigException): pass
class NoDomainError(SSSDConfigException): pass
class DomainNotRecognized(SSSDConfigException): pass
class DomainAlreadyExistsError(SSSDConfigException): pass
class NoSuchProviderError(SSSDConfigException): pass
class NoSuchProviderSubtypeError(SSSDConfigException): pass
class ProviderSubtypeInUse(SSSDConfigException): pass

PACKAGE = 'sss_daemon'
LOCALEDIR = '/usr/share/locale'

translation = gettext.translation(PACKAGE, LOCALEDIR, fallback=True)
_ = translation.ugettext

# TODO: This needs to be made external
option_strings = {
    # [service]
    'debug_level' : _('Set the verbosity of the debug logging'),
    'debug_timestamps' : _('Include timestamps in debug logs'),
    'debug_to_files' : _('Write debug messages to logfiles'),
    'timeout' : _('Ping timeout before restarting service'),
    'command' : _('Command to start service'),
    'reconnection_retries' : _('Number of times to attempt connection to Data Providers'),

    # [sssd]
    'services' : _('SSSD Services to start'),
    'domains' : _('SSSD Domains to start'),
    'sbus_timeout' : _('Timeout for messages sent over the SBUS'),
    're_expression' : _('Regex to parse username and domain'),
    'full_name_format' : _('Printf-compatible format for displaying fully-qualified names'),

    # [nss]
    'enum_cache_timeout' : _('Enumeration cache timeout length (seconds)'),
    'entry_cache_no_wait_timeout' : _('Entry cache background update timeout length (seconds)'),
    'entry_negative_timeout' : _('Negative cache timeout length (seconds)'),
    'filter_users' : _('Users that SSSD should explicitly ignore'),
    'filter_groups' : _('Groups that SSSD should explicitly ignore'),
    'filter_users_in_groups' : _('Should filtered users appear in groups'),
    'pwfield' : _('The value of the password field the NSS provider should return'),

    # [pam]
    'offline_credentials_expiration' : _('How long to allow cached logins between online logins (days)'),
    'offline_failed_login_attempts' : _('How many failed logins attempts are allowed when offline'),
    'offline_failed_login_delay' : _('How long (minutes) to deny login after offline_failed_login_attempts has been reached'),

    # [provider]
    'id_provider' : _('Identity provider'),
    'auth_provider' : _('Authentication provider'),
    'access_provider' : _('Access control provider'),
    'chpass_provider' : _('Password change provider'),

    # [domain]
    'min_id' : _('Minimum user ID'),
    'max_id' : _('Maximum user ID'),
    'timeout' : _('Ping timeout before restarting domain'),
    'enumerate' : _('Enable enumerating all users/groups'),
    'cache_credentials' : _('Cache credentials for offline login'),
    'store_legacy_passwords' : _('Store password hashes'),
    'use_fully_qualified_names' : _('Display users/groups in fully-qualified form'),
    'entry_cache_timeout' : _('Entry cache timeout length (seconds)'),
    'lookup_family_order' : _('Restrict or prefer a specific address family when performing DNS lookups'),
    'account_cache_expiration' : _('How long to keep cached entries after last successful login (days)'),
    'dns_resolver_timeout' : _('How long to wait for replies from DNS when resolving servers (seconds)'),
    'dns_discovery_domain' : _('The domain part of service discovery DNS query'),

    # [provider/ipa]
    'ipa_domain' : _('IPA domain'),
    'ipa_server' : _('IPA server address'),
    'ipa_hostname' : _('IPA client hostname'),
    'ipa_dyndns_update' : _("Whether to automatically update the client's DNS entry in FreeIPA"),
    'ipa_dyndns_iface' : _("The interface whose IP should be used for dynamic DNS updates"),

    # [provider/krb5]
    'krb5_kdcip' : _('Kerberos server address'),
    'krb5_realm' : _('Kerberos realm'),
    'krb5_auth_timeout' : _('Authentication timeout'),

    # [provider/krb5/auth]
    'krb5_ccachedir' : _('Directory to store credential caches'),
    'krb5_ccname_template' : _("Location of the user's credential cache"),
    'krb5_keytab' : _("Location of the keytab to validate credentials"),
    'krb5_validate' : _("Enable credential validation"),
    'krb5_store_password_if_offline' : _("Store password if offline for later online authentication"),

    # [provider/krb5/chpass]
    'krb5_kpasswd' : _('Server where the change password service is running if not on the KDC'),

    # [provider/ldap]
    'ldap_uri' : _('ldap_uri, The URI of the LDAP server'),
    'ldap_search_base' : _('The default base DN'),
    'ldap_schema' : _('The Schema Type in use on the LDAP server, rfc2307'),
    'ldap_default_bind_dn' : _('The default bind DN'),
    'ldap_default_authtok_type' : _('The type of the authentication token of the default bind DN'),
    'ldap_default_authtok' : _('The authentication token of the default bind DN'),
    'ldap_network_timeout' : _('Length of time to attempt connection'),
    'ldap_opt_timeout' : _('Length of time to attempt synchronous LDAP operations'),
    'ldap_offline_timeout' : _('Length of time between attempts to reconnect while offline'),
    'ldap_tls_cacert' : _('File that contains CA certificates'),
    'ldap_tls_cacertdir' : _('Path to CA certificate directory'),
    'ldap_tls_reqcert' : _('Require TLS certificate verification'),
    'ldap_sasl_mech' : _('Specify the sasl mechanism to use'),
    'ldap_sasl_authid' : _('Specify the sasl authorization id to use'),
    'krb5_kdcip' : _('Kerberos server address'),
    'krb5_realm' : _('Kerberos realm'),
    'ldap_krb5_keytab' : _('Kerberos service keytab'),
    'ldap_krb5_init_creds' : _('Use Kerberos auth for LDAP connection'),
    'ldap_referrals' : _('Follow LDAP referrals'),
    'ldap_krb5_ticket_lifetime' : _('Lifetime of TGT for LDAP connection'),

    # [provider/ldap/id]
    'ldap_search_timeout' : _('Length of time to wait for a search request'),
    'ldap_enumeration_refresh_timeout' : _('Length of time between enumeration updates'),
    'ldap_id_use_start_tls' : _('Require TLS for ID lookups'),
    'ldap_user_search_base' : _('Base DN for user lookups'),
    'ldap_user_search_scope' : _('Scope of user lookups'),
    'ldap_user_search_filter' : _('Filter for user lookups'),
    'ldap_user_object_class' : _('Objectclass for users'),
    'ldap_user_name' : _('Username attribute'),
    'ldap_user_uid_number' : _('UID attribute'),
    'ldap_user_gid_number' : _('Primary GID attribute'),
    'ldap_user_gecos' : _('GECOS attribute'),
    'ldap_user_homedir' : _('Home directory attribute'),
    'ldap_user_shell' : _('Shell attribute'),
    'ldap_user_uuid' : _('UUID attribute'),
    'ldap_user_principal' : _('User principal attribute (for Kerberos)'),
    'ldap_user_fullname' : _('Full Name'),
    'ldap_user_member_of' : _('memberOf attribute'),
    'ldap_user_modify_timestamp' : _('Modification time attribute'),

    # [provider/ldap/auth]
    'ldap_pwd_policy' : _('Policy to evaluate the password expiration'),

    # [provider/ldap/access]
    'ldap_access_filter' : _('LDAP filter to determine access privileges'),

    # [provider/simple/access]
    'simple_allow_users' : _('Comma separated list of allowed users'),
    'simple_deny_users' : _('Comma separated list of prohibited users'),

    # [provider/local/id]
    'default_shell' : _('Default shell, /bin/bash'),
    'base_directory' : _('Base for home directories'),

    # [provider/proxy/id]
    'proxy_lib_name' : _('The name of the NSS library to use'),

    # [provider/proxy/auth]
    'proxy_pam_target' : _('PAM stack to use')
}

def striplist(l):
    return([x.strip() for x in l])

def options_overlap(options1, options2):
    overlap = []
    for option in options1:
        if option in options2:
            overlap.append(option)
    return overlap

class SSSDConfigSchema(SSSDChangeConf):
    def __init__(self, schemafile, schemaplugindir):
        SSSDChangeConf.__init__(self)
        #TODO: get these from a global setting
        if not schemafile:
            schemafile = '/etc/sssd/sssd.api.conf'
        if not schemaplugindir:
            schemaplugindir = '/etc/sssd/sssd.api.d'

        try:
            #Read the primary config file
            fd = open(schemafile, 'r')
            self.readfp(fd)
            fd.close()
            # Read in the provider files
            for file in os.listdir(schemaplugindir):
                fd = open(schemaplugindir+ "/" + file)
                self.readfp(fd)
                fd.close()
        except IOError:
            raise
        except SyntaxError: # can be raised with readfp
            raise ParsingError

        # Set up lookup table for types
        self.type_lookup = {
            'bool' : bool,
            'int'  : int,
            'long' : long,
            'float': float,
            'str'  : str,
            'list' : list,
            'None' : None
            }

        # Lookup table for acceptable boolean values
        self.bool_lookup = {
            'false' : False,
            'true'  : True,
            }

    def get_options(self, section):
        if not self.has_section(section):
            raise NoSectionError
        options = self.options(section)

        # Indexes
        PRIMARY_TYPE = 0
        SUBTYPE = 1
        MANDATORY = 2
        DEFAULT = 3

        # Parse values
        parsed_options = {}
        for option in self.strip_comments_empty(options):
            unparsed_option = option['value']
            split_option = striplist(unparsed_option.split(','))
            optionlen = len(split_option)

            primarytype = self.type_lookup[split_option[PRIMARY_TYPE]]
            subtype = self.type_lookup[split_option[SUBTYPE]]
            mandatory = self.bool_lookup[split_option[MANDATORY]]

            if option_strings.has_key(option['name']):
                desc = option_strings[option['name']]
            else:
                desc = None

            if optionlen == 3:
                # This option has no defaults
                parsed_options[option['name']] = \
                    (primarytype,
                     subtype,
                     mandatory,
                     desc,
                     None)
            elif optionlen == 4:
                if type(split_option[DEFAULT]) == primarytype:
                    parsed_options[option['name']] = \
                        (primarytype,
                         subtype,
                         mandatory,
                         desc,
                         split_option[DEFAULT])
                elif primarytype == list:
                    if (type(split_option[DEFAULT]) == subtype):
                        parsed_options[option['name']] = \
                            (primarytype,
                             subtype,
                             mandatory,
                             desc,
                             [split_option[DEFAULT]])
                    else:
                        try:
                            if subtype == bool and \
                            type(split_option[DEFAULT]) == str:
                                parsed_options[option['name']] = \
                                    (primarytype,
                                     subtype,
                                     mandatory,
                                     desc,
                                     [self.bool_lookup[split_option[DEFAULT].lower()]])
                            else:
                                parsed_options[option['name']] = \
                                    (primarytype,
                                     subtype,
                                     mandatory,
                                     desc,
                                     [subtype(split_option[DEFAULT])])
                        except ValueError, KeyError:
                            raise ParsingError
                else:
                    try:
                        if primarytype == bool and \
                            type(split_option[DEFAULT]) == str:
                                parsed_options[option['name']] = \
                                    (primarytype,
                                     subtype,
                                     mandatory,
                                     desc,
                                     self.bool_lookup[split_option[DEFAULT].lower()])
                        else:
                            parsed_options[option['name']] = \
                                (primarytype,
                                 subtype,
                                 mandatory,
                                 desc,
                                 primarytype(split_option[DEFAULT]))
                    except ValueError, KeyError:
                        raise ParsingError

            elif optionlen > 4:
                if (primarytype != list):
                    raise ParsingError
                fixed_options = []
                for x in split_option[DEFAULT:]:
                    if type(x) != subtype:
                        try:
                            if (subtype == bool and type(x) == str):
                                newvalue = self.bool_lookup[x.lower()]
                            else:
                                newvalue = subtype(x)
                            fixed_options.extend([newvalue])
                        except ValueError, KeyError:
                            raise ParsingError
                    else:
                        fixed_options.extend([x])
                parsed_options[option['name']] = \
                    (primarytype,
                     subtype,
                     mandatory,
                     desc,
                     fixed_options)
            else:
                # Bad config file
                raise ParsingError

        return parsed_options

    def get_option(self, section, option):
        if not self.has_section(section):
            raise NoSectionError(section)
        if not self.has_option(section, option):
            raise NoOptionError("Section [%s] has no option [%s]" %
                                (section, option))

        return self.get_options(section)[option]

    def get_defaults(self, section):
        if not self.has_section(section):
            raise NoSectionError(section)

        schema_options = self.get_options(section)
        defaults = dict([(x,schema_options[x][4])
                         for x in schema_options.keys()
                         if schema_options[x][4] != None])

        return defaults

    def get_services(self):
        service_list = [x['name'] for x in self.sections()
                        if x['name'] != 'service' and
                        not x['name'].startswith('domain') and
                        not x['name'].startswith('provider')]
        return service_list

    def get_providers(self):
        providers = {}
        for section in self.sections():
            splitsection = section['name'].split('/')
            if (splitsection[0] == 'provider'):
                if(len(splitsection) == 3):
                    if not providers.has_key(splitsection[1]):
                        providers[splitsection[1]] = []
                    providers[splitsection[1]].extend([splitsection[2]])
        for key in providers.keys():
            providers[key] = tuple(providers[key])
        return providers

class SSSDConfigObject(object):
    def __init__(self):
        self.name = None
        self.options = {}

    def get_name(self):
        """
        Return the name of the this object

        === Returns ===
        The domain name

        === Errors ===
        No errors
        """
        return self.name

    def get_option(self, optionname):
        """
        Return the value of an service option

        optionname:
          The option to get.

        === Returns ===
        The value for the requested option.

        === Errors ===
        NoOptionError:
          The specified option was not listed in the service
        """
        if optionname in self.options.keys():
            return self.options[optionname]
        raise NoOptionError(optionname)

    def get_all_options(self):
        """
        Return a dictionary of name/value pairs for this object

        === Returns ===
        A dictionary of name/value pairs currently in use for this object

        === Errors ===
        No errors
        """
        return self.options

    def remove_option(self, optionname):
        """
        Remove an option from the object. If the option does not exist, it is ignored.

        === Returns ===
        No return value.

        === Errors ===
        No errors
        """
        if self.options.has_key(optionname):
            del self.options[optionname]

class SSSDService(SSSDConfigObject):
    '''
    Object to manipulate SSSD service options
    '''

    def __init__(self, servicename, apischema):
        """
        Create a new SSSDService, setting its defaults to those found in the
        schema. This constructor should not be used directly. Use
        SSSDConfig.new_service() instead.

        name:
          The service name
        apischema:
          An SSSDConfigSchema? object created by SSSDConfig.__init__()

        === Returns ===
        The newly-created SSSDService object.

        === Errors ===
        TypeError:
          The API schema passed in was unusable or the name was not a string.
        ServiceNotRecognizedError:
          The service was not listed in the schema
        """
        SSSDConfigObject.__init__(self)

        if not isinstance(apischema, SSSDConfigSchema) or type(servicename) != str:
            raise TypeError

        if not apischema.has_section(servicename):
            raise ServiceNotRecognizedError(servicename)

        self.name = servicename
        self.schema = apischema

        # Set up the service object with any known defaults
        self.options = {}

        # Include a list of hidden options
        self.hidden_options = []

        # Set up default options for all services
        self.options.update(self.schema.get_defaults('service'))

        # Set up default options for this service
        self.options.update(self.schema.get_defaults(self.name))

        # For the [sssd] service, force the config file version
        if servicename == 'sssd':
            self.options['config_file_version'] = 2
            self.hidden_options.append('config_file_version')

    def list_options_with_mandatory(self):
        """
        List options for the service, including the mandatory flag.

        === Returns ===
        A dictionary of configurable options. This dictionary is keyed on the
        option name with a tuple of the variable type, subtype ('None' if the
        type is not  a collection type), whether it is mandatory, the
        translated option description, and the default value (or 'None') as
        the value.

        Example:
        { 'enumerate' :
          (bool, None, False, u'Enable enumerating all users/groups', True) }

        === Errors ===
        No errors
        """
        options = {}

        # Get the list of available options for all services
        schema_options = self.schema.get_options('service')
        options.update(schema_options)

        schema_options = self.schema.get_options(self.name)
        options.update(schema_options)

        return options

    def list_options(self):
        """
        List all options that apply to this service

        === Returns ===
        A dictionary of configurable options. This dictionary is keyed on the
        option name with a tuple of the variable type, subtype ('None' if the
        type is not  a collection type), the translated option description, and
        the default value (or 'None') as the value.

        Example:
        { 'services' :
          (list, str, u'SSSD Services to start', ['nss', 'pam']) }

        === Errors ===
        No Errors
        """
        options = self.list_options_with_mandatory()

        # Filter out the mandatory field to maintain compatibility
        # with older versions of the API
        filtered_options = {}
        for key in options.keys():
            filtered_options[key] = (options[key][0], options[key][1], options[key][3], options[key][4])

        return filtered_options

    def list_mandatory_options(self):
        """
        List all mandatory options that apply to this service

        === Returns ===
        A dictionary of configurable options. This dictionary is keyed on the
        option name with a tuple of the variable type, subtype ('None' if the
        type is not  a collection type), the translated option description, and
        the default value (or 'None') as the value.

        Example:
        { 'services' :
          (list, str, u'SSSD Services to start', ['nss', 'pam']) }

        === Errors ===
        No Errors
        """
        options = self.list_options_with_mandatory()

        # Filter out the mandatory field to maintain compatibility
        # with older versions of the API
        filtered_options = {}
        for key in options.keys():
            if options[key][2]:
                filtered_options[key] = (options[key][0], options[key][1], options[key][3], options[key][4])

        return filtered_options

    def set_option(self, optionname, value):
        """
        Set a service option to the specified value (or values)

        optionname:
          The option to change
        value:
          The value to set. This may be a single value or a list of values. If
          it is set to None, it resets the option to its default.

        === Returns ===
        No return value

        === Errors ===
        NoOptionError:
          The specified option is not listed in the schema
        TypeError:
          The value specified was not of the expected type
        """
        if self.schema.has_option(self.name, optionname):
            option_schema = self.schema.get_option(self.name, optionname)
        elif self.schema.has_option('service', optionname):
            option_schema = self.schema.get_option('service', optionname)
        elif optionname in self.hidden_options:
            # Set this option and do not add it to the list of changeable values
            self.options[optionname] = value
            return
        else:
            raise NoOptionError('Section [%s] has no option [%s]' % (self.name, optionname))

        if value == None:
            self.remove_option(optionname)
            return

        raise_error = False

        # If we were expecting a list and didn't get one,
        # Create a list with a single entry. If it's the
        # wrong subtype, it will fail below
        if option_schema[0] == list and type(value) != list:
            if type(value) == str:
                value = striplist(value.split(','))
            else:
                value = [value]

        if type(value) != option_schema[0]:
            # If it's possible to convert it, do so
            try:
                if option_schema[0] == bool and \
                type(value) == str:
                    value = self.schema.bool_lookup[value.lower()]
                else:
                    value = option_schema[0](value)
            except ValueError:
                raise_error = True
            except KeyError:
                raise_error = True

            if raise_error:
                raise TypeError('Expected %s for %s, received %s' %
                                (option_schema[0], optionname, type(value)))

        if type(value) == list:
            # Iterate through the list an ensure that all members
            # are of the appropriate subtype
            try:
                newvalue = []
                for x in value:
                    if option_schema[1] == bool and \
                    type(x) == str:
                        newvalue.extend([self.schema.bool_lookup[x.lower()]])
                    else:
                        newvalue.extend([option_schema[1](x)])
            except ValueError:
                raise_error = True
            except KeyError:
                raise_error = True

            if raise_error:
                raise TypeError('Expected %s' % option_schema[1])

            value = newvalue

        self.options[optionname] = value

class SSSDDomain(SSSDConfigObject):
    """
    Object to manipulate SSSD domain options
    """
    def __init__(self, domainname, apischema):
        """
        Creates a new, empty SSSDDomain. This domain is inactive by default.
        This constructor should not be used directly. Use
        SSSDConfig.new_domain() instead.

        name:
          The domain name.
        apischema:
          An SSSDConfigSchema object created by SSSDConfig.__init__()

        === Returns ===
        The newly-created SSSDDomain object.

        === Errors ===
        TypeError:
          apischema was not an SSSDConfigSchema object or domainname was not
         a string
        """
        SSSDConfigObject.__init__(self)

        if not isinstance(apischema, SSSDConfigSchema) or type(domainname) != str:
            raise TypeError

        self.name = domainname
        self.schema = apischema
        self.active = False
        self.oldname = None
        self.providers = []

        # Set up the domain object with any known defaults
        self.options = {}

        # Set up default options for all domains
        self.options.update(self.schema.get_defaults('provider'))
        self.options.update(self.schema.get_defaults('domain'))

    def set_active(self, active):
        """
        Enable or disable this domain

        active:
          Boolean value. If True, this domain will be added to the active
          domains list when it is saved. If False, it will be removed from the
          active domains list when it is saved.

        === Returns ===
        No return value

        === Errors ===
        No errors
        """
        self.active = bool(active)

    def list_options_with_mandatory(self):
        """
        List options for the currently-configured providers, including the
        mandatory flag

        === Returns ===
        A dictionary of configurable options. This dictionary is keyed on the
        option name with a tuple of the variable type, subtype ('None' if the
        type is not  a collection type), whether it is mandatory, the
        translated option description, and the default value (or 'None') as
        the value.

        Example:
        { 'enumerate' :
          (bool, None, False, u'Enable enumerating all users/groups', True) }

        === Errors ===
        No errors
        """
        options = {}
        # Get the list of available options for all domains
        options.update(self.schema.get_options('provider'))

        options.update(self.schema.get_options('domain'))

        # Candidate for future optimization: will update primary type
        # for each subtype
        for (provider, providertype) in self.providers:
            schema_options = self.schema.get_options('provider/%s'
                                                     % provider)
            options.update(schema_options)
            schema_options = self.schema.get_options('provider/%s/%s'
                                                     % (provider, providertype))
            options.update(schema_options)
        return options

    def list_options(self):
        """
        List options available for the currently-configured providers.

        === Returns ===
        A dictionary of configurable options. This dictionary is keyed on the
        option name with a tuple of the variable type, subtype ('None' if the
        type is not  a collection type), the translated option description, and
        the default value (or 'None') as the value.

        Example:
        { 'enumerate' :
          (bool, None, u'Enable enumerating all users/groups', True) }

        === Errors ===
        No errors
        """
        options = self.list_options_with_mandatory()

        # Filter out the mandatory field to maintain compatibility
        # with older versions of the API
        filtered_options = {}
        for key in options.keys():
            filtered_options[key] = (options[key][0], options[key][1], options[key][3], options[key][4])

        return filtered_options

    def list_mandatory_options(self):
        """
        List mandatory options for the currently-configured providers.

        === Returns ===
        A dictionary of configurable options. This dictionary is keyed on the
        option name with a tuple of the variable type, subtype ('None' if the
        type is not  a collection type), the translated option description, and
        the default value (or 'None') as the value.

        Example:
        { 'enumerate' :
          (bool, None, u'Enable enumerating all users/groups', True) }

        === Errors ===
        No errors
        """
        options = self.list_options_with_mandatory()

        # Filter out the mandatory field to maintain compatibility
        # with older versions of the API
        filtered_options = {}
        for key in options.keys():
            if options[key][2]:
                filtered_options[key] = (options[key][0], options[key][1], options[key][3], options[key][4])

        return filtered_options

    def list_provider_options(self, provider, provider_type=None):
        """
        If provider_type is specified, list all options applicable to that
        target, otherwise list all possible options available for a provider.

        type:
            Provider backend type. (e.g. local, ldap, krb5, etc.)
        provider_type:
            Subtype of the backend type. (e.g. id, auth, access, chpass)

        === Returns ===

        A dictionary of configurable options for the specified provider type.
        This dictionary is keyed on the option name with a tuple of the
        variable type, subtype ('None' if the type is not  a collection type),
        the translated option description, and the default value (or 'None')
        as the value.

        === Errors ===

        NoSuchProviderError:
            The specified provider is not listed in the schema or plugins
        NoSuchProviderSubtypeError:
            The specified provider subtype is not listed in the schema
        """
        #TODO section checking

        options = self.schema.get_options('provider/%s' % provider)
        if(provider_type):
            options.update(self.schema.get_options('provider/%s/%s' %
                                                   (provider, provider_type)))
        else:
            # Add options from all provider subtypes
            known_providers = self.list_providers()
            for provider_type in known_providers[provider]:
                options.update(self.list_provider_options(provider,
                                                          provider_type))
        return options

    def list_providers(self):
        """
        Return a dictionary of providers.

        === Returns ===
        Returns a dictionary of providers, keyed on the primary type, with the
        value being a tuple of the subtypes it supports.

        Example:
        { 'ldap' : ('id', 'auth', 'chpass') }

        === Errors ===
        No Errors
        """
        return self.schema.get_providers()

    def set_option(self, option, value):
        """
        Set a domain option to the specified value (or values)

        option:
          The option to change.
        value:
          The value to set. This may be a single value or a list of values.
          If it is set to None, it resets the option to its default.

        === Returns ===
        No return value.

        === Errors ===
        NoOptionError:
            The specified option is not listed in the schema
        TypeError:
            The value specified was not of the expected type
        """
        options = self.list_options()
        if (option not in options.keys()):
            raise NoOptionError('Section [%s] has no option [%s]' %
                                (self.name, option))

        if value == None:
            self.remove_option(option)
            return

        option_schema = options[option]
        raise_error = False

        # If we were expecting a list and didn't get one,
        # Create a list with a single entry. If it's the
        # wrong subtype, it will fail below
        if option_schema[0] == list and type(value) != list:
            if type(value) == str:
                value = striplist(value.split(','))
            else:
                value = [value]

        if type(value) != option_schema[0]:
            # If it's possible to convert it, do so
            try:
                if option_schema[0] == bool and \
                type(value) == str:
                    value = self.schema.bool_lookup[value.lower()]
                else:
                    value = option_schema[0](value)
            except ValueError:
                raise_error = True
            except KeyError:
                raise_error = True

            if raise_error:
                raise TypeError('Expected %s for %s, received %s' %
                                (option_schema[0], option, type(value)))

        if type(value) == list:
            # Iterate through the list an ensure that all members
            # are of the appropriate subtype
            try:
                newvalue = []
                for x in value:
                    if option_schema[1] == bool and \
                    type(x) == str:
                        newvalue.extend([self.schema.bool_lookup[x.lower()]])
                    else:
                        newvalue.extend([option_schema[1](x)])
            except ValueError:
                raise_error = True
            except KeyError:
                raise_error = True

            if raise_error:
                raise TypeError('Expected %s' % option_schema[1])
            value = newvalue

        # Check whether we're adding a provider entry.
        is_provider = option.rfind('_provider')
        if (is_provider > 0):
            provider = option[:is_provider]
            try:
                self.add_provider(value, provider)
            except NoSuchProviderError:
                raise NoOptionError
        else:
            self.options[option] = value

    def set_name(self, newname):
        """
        Change the name of the domain

        newname:
          New name for this domain

        === Returns ===
        No return value.

        === Errors ===
        TypeError:
          newname was not a string
        """

        if type(newname) != str:
            raise TypeError

        if not self.oldname:
            # Only set the oldname once
            self.oldname = self.name
        self.name = newname

    def add_provider(self, provider, provider_type):
        """
        Add a new provider type to the domain

        type:
          Provider backend type. (e.g. local, ldap, krb5, etc.)
        subtype:
          Subtype of the backend type. (e.g. id, auth, chpass)

        === Returns ===
        No return value.

        === Errors ===
        ProviderSubtypeInUse:
          Another backend is already providing this subtype
        NoSuchProviderError:
          The specified provider is not listed in the schema or plugins
        NoSuchProviderSubtypeError:
          The specified provider subtype is not listed in the schema
        """
        # Check that provider and provider_type are valid
        configured_providers = self.list_providers()
        if provider in configured_providers.keys():
            if provider_type not in configured_providers[provider]:
                raise NoSuchProviderSubtypeError(provider_type)
        else:
            raise NoSuchProviderError

        # Don't add a provider twice
        with_this_type = [x for x in self.providers if x[1] == provider_type]
        if len(with_this_type) > 1:
            # This should never happen!
            raise ProviderSubtypeInUse
        if len(with_this_type) == 1:
            if with_this_type[0][0] != provider:
                raise ProviderSubtypeInUse(with_this_type[0][0])
        else:
            self.providers.extend([(provider, provider_type)])

        option_name = '%s_provider' % provider_type
        self.options[option_name] = provider

        # Add defaults for this provider
        self.options.update(self.schema.get_defaults('provider/%s' %
                                                     provider))
        self.options.update(self.schema.get_defaults('provider/%s/%s' %
                                                     (provider,
                                                      provider_type)))

    def remove_provider(self, provider_type):
        """
        Remove a provider from the domain. If the provider is not present, it
        is ignored.

        provider_type:
          Subtype of the backend type. (e.g. id, auth, chpass)

        === Returns ===
        No return value.

        === Errors ===
        No Errors
        """

        provider = None
        for (provider, ptype) in self.providers:
            if ptype == provider_type:
                break
            provider = None

        # Check whether the provider_type was found
        if not provider:
            return

        # Remove any unused options when removing the provider.
        options = self.list_provider_options(provider, provider_type)

        # Trim any options that are used by other providers,
        # if that provider is in use
        for (prov, ptype) in self.providers:
            # Ignore the one being removed
            if (prov, ptype) == (provider, provider_type):
                continue

            provider_options = self.list_provider_options(prov, ptype)
            overlap = options_overlap(options.keys(), provider_options.keys())
            for opt in overlap:
                del options[opt]

        # We should now have a list of options used only by this
        # provider. So we remove them.
        for option in options:
            if self.options.has_key(option):
                del self.options[option]

        self.providers.remove((provider, provider_type))

class SSSDConfig(SSSDChangeConf):
    """
    class SSSDConfig
    Primary class for operating on SSSD configurations
    """
    def __init__(self, schemafile=None, schemaplugindir=None):
        """
        Initialize the SSSD config parser/editor. This constructor does not
        open or create a config file. If the schemafile and schemaplugindir
        are not passed, it will use the system defaults.

        schemafile:
          The path to the api schema config file. Usually
          /etc/sssd/sssd.api.conf
        schemaplugindir:
          The path the directory containing the provider schema config files.
          Usually /etc/sssd/sssd.api.d

        === Returns ===
        The newly-created SSSDConfig object.

        === Errors ===
        IOError:
          Exception raised when the schema file could not be opened for
          reading.
        ParsingError:
          The main schema file or one of those in the plugin directory could
          not be parsed.
        """
        SSSDChangeConf.__init__(self)
        self.schema = SSSDConfigSchema(schemafile, schemaplugindir)
        self.configfile = None
        self.initialized = False
        self.API_VERSION = 2

    def import_config(self,configfile=None):
        """
        Read in a config file, populating all of the service and domain
        objects with the read values.

        configfile:
          The path to the SSSD config file. If not specified, use the system
          default, usually /etc/sssd/sssd.conf

        === Returns ===
        No return value

        === Errors ===
        IOError:
          Exception raised when the file could not be opened for reading
        ParsingError:
          Exception raised when errors occur attempting to parse a file.
        AlreadyInitializedError:
          This SSSDConfig object was already initialized by a call to
          import_config() or new_config()
        """
        if self.initialized:
            raise AlreadyInitializedError

        if not configfile:
            #TODO: get this from a global setting
            configfile = '/etc/sssd/sssd.conf'
        # open will raise an IOError if it fails
        fd = open(configfile, 'r')

        try:
            self.readfp(fd)
        except:
            raise ParsingError

        fd.close()
        self.configfile = configfile
        self.initialized = True

        try:
            if int(self.get('sssd', 'config_file_version')) != self.API_VERSION:
                raise ParsingError("Wrong config_file_version")
        except:
            # Either the 'sssd' section or the 'config_file_version' was not
            # present in the config file
            raise ParsingError("File contains no config_file_version")

    def new_config(self):
        """
        Initialize the SSSDConfig object with the defaults from the schema.

        === Returns ===
        No return value

        === Errors ===
        AlreadyInitializedError:
          This SSSDConfig object was already initialized by a call to
          import_config() or new_config()
        """
        if self.initialized:
            raise AlreadyInitializedError

        self.initialized = True

        #Initialize all services
        for servicename in self.schema.get_services():
            service = self.new_service(servicename)

    def write(self, outputfile=None):
        """
        Write out the configuration to a file.

        outputfile:
          The path to write the new config file. If it is not specified, it
          will use the path specified by the import() call.
        === Returns ===
        No return value

        === Errors ===
        IOError:
          Exception raised when the file could not be opened for writing
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        NoOutputFileError:
          No outputfile was specified and this SSSDConfig object was not
          initialized by import()
        """
        if not self.initialized:
            raise NotInitializedError

        if outputfile == None:
            if(self.configfile == None):
                raise NoOutputFileError

            outputfile = self.configfile

        # open() will raise IOError if it fails
        old_umask = os.umask(0177)
        of = open(outputfile, "wb")
        output = self.dump(self.opts)
        of.write(output)
        of.close()
        os.umask(old_umask)

    def list_services(self):
        """
        Retrieve a list of known services.

        === Returns ===
        The list of known services.

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError

        service_list = [x['name'] for x in self.sections()
                        if not x['name'].startswith('domain') ]
        return service_list

    def get_service(self, name):
        """
        Get an SSSDService object to edit a service.

        name:
          The name of the service to return.

        === Returns ===
        An SSSDService instance containing the current state of a service in
        the SSSDConfig

        === Errors ===
        NoServiceError:
          There is no such service with the specified name in the SSSDConfig.
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError
        if not self.has_section(name):
            raise NoServiceError

        service = SSSDService(name, self.schema)
        for opt in self.strip_comments_empty(self.options(name)):
            try:
                service.set_option(opt['name'], opt['value'])
            except NoOptionError:
                # If we come across an option that we don't recognize,
                # we should just ignore it and continue
                pass

        return service

    def new_service(self, name):
        """
        Create a new service from the defaults and return the SSSDService
        object for it. This function will also add this service to the list of
        active services in the [SSSD] section.

        name:
          The name of the service to create and return.

        === Returns ===
        The newly-created SSSDService object

        === Errors ===
        ServiceNotRecognizedError:
          There is no such service in the schema.
        ServiceAlreadyExistsError:
          The service being created already exists in the SSSDConfig object.
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError
        if (self.has_section(name)):
            raise ServiceAlreadyExists(name)

        service = SSSDService(name, self.schema)
        self.save_service(service)
        return service

    def delete_service(self, name):
        """
        Remove a service from the SSSDConfig object. This function will also
        remove this service from the list of active services in the [SSSD]
        section. Has no effect if the service does not exist.

        === Returns ===
        No return value

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError
        self.delete_option('section', name)

    def save_service(self, service):
        """
        Save the changes made to the service object back to the SSSDConfig
        object.

        service_object:
          The SSSDService object to save to the configuration.

        === Returns ===
        No return value
        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        TypeError:
          service_object was not of the type SSSDService
        """
        if not self.initialized:
            raise NotInitializedError
        if not isinstance(service, SSSDService):
            raise TypeError

        name = service.get_name()
        # Ensure that the existing section is removed
        # This way we ensure that we are getting a
        # complete copy of the service.
        # delete_option() is a noop if the section
        # does not exist.
        index = self.delete_option('section', name)

        addkw = []
        for option,value in service.get_all_options().items():
            if (type(value) == list):
                value = ', '.join(value)
            addkw.append( { 'type'  : 'option',
                            'name'  : option,
                            'value' : str(value) } )

        self.add_section(name, addkw, index)

    def list_active_domains(self):
        """
        Return a list of all active domains.

        === Returns ===
        The list of configured, active domains.

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError

        if (self.has_option('sssd', 'domains')):
            active_domains = striplist(self.get('sssd', 'domains').split(','))
            domain_dict = dict.fromkeys(active_domains)
            if domain_dict.has_key(''):
                del domain_dict['']

            # Remove any entries in this list that don't
            # correspond to an active domain, for integrity
            configured_domains = self.list_domains()
            for dom in domain_dict.keys():
                if dom not in configured_domains:
                    del domain_dict[dom]

            active_domains = domain_dict.keys()
        else:
            active_domains = []

        return active_domains

    def list_inactive_domains(self):
        """
        Return a list of all configured, but disabled domains.

        === Returns ===
        The list of configured, inactive domains.

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError

        if (self.has_option('sssd', 'domains')):
            active_domains = striplist(self.get('sssd', 'domains').split(','))
        else:
            active_domains = []

        domains = [x for x in self.list_domains()
                   if x not in active_domains]
        return domains

    def list_domains(self):
        """
        Return a list of all configured domains, including inactive domains.

        === Returns ===
        The list of configured domains, both active and inactive.

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError
        domains = [x['name'][7:] for x in self.sections() if x['name'].startswith('domain/')]
        return domains

    def get_domain(self, name):
        """
        Get an SSSDDomain object to edit a domain.

        name:
          The name of the domain to return.

        === Returns ===
        An SSSDDomain instance containing the current state of a domain in the
        SSSDConfig

        === Errors ===
        NoDomainError:
          There is no such domain with the specified name in the SSSDConfig.
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError
        if not self.has_section('domain/%s' % name):
            raise NoDomainError(name)

        domain = SSSDDomain(name, self.schema)

        # Read in the providers first or we may have type
        # errors trying to read in their options
        providers = [ (x['name'],x['value']) for x in self.strip_comments_empty(self.options('domain/%s' % name))
                     if x['name'].rfind('_provider') > 0]

        for (option, value) in providers:
            try:
                domain.set_option(option, value)
            except NoOptionError:
                # If we come across an option that we don't recognize,
                # we should just ignore it and continue
                pass

        # Read in all the options from the configuration
        for opt in self.strip_comments_empty(self.options('domain/%s' % name)):
            if (opt['name'], opt['value']) not in providers:
                try:
                    domain.set_option(opt['name'], opt['value'])
                except NoOptionError:
                    # If we come across an option that we don't recognize,
                    # we should just ignore it and continue
                    pass

        # Determine if this domain is currently active
        domain.active = self.is_domain_active(name)

        return domain

    def new_domain(self, name):
        """
        Create a new, empty domain and return the SSSDDomain object for it.

        name:
          The name of the domain to create and return.

        === Returns ===
        The newly-created SSSDDomain object

        === Errors ===
        DomainAlreadyExistsError:
          The service being created already exists in the SSSDConfig object.
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError
        if self.has_section('domain/%s' % name):
            raise DomainAlreadyExistsError

        domain = SSSDDomain(name, self.schema)
        self.save_domain(domain)
        return domain

    def is_domain_active(self, name):
        """
        Is a particular domain set active

        name:
          The name of the configured domain to check

        === Returns ===
        True if the domain is active, False if it is inactive

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        NoDomainError:
          No domain by this name is configured
        """

        if not self.initialized:
            raise NotInitializedError

        if name not in self.list_domains():
            raise NoDomainError

        return name in self.list_active_domains()

    def activate_domain(self, name):
        """
        Activate a configured domain

        name:
          The name of the configured domain to activate

        === Returns ===
        No return value

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        NoDomainError:
          No domain by this name is configured
        """

        if not self.initialized:
            raise NotInitializedError

        if name not in self.list_domains():
            raise NoDomainError

        item = self.get_option_index('sssd', 'domains')[1]
        if not item:
            self.set('sssd','domains', name)
            return

        # Turn the items into a set of dictionary keys
        # This guarantees uniqueness and makes it easy
        # to add a new value
        domain_dict = dict.fromkeys(striplist(item['value'].split(',')))
        if domain_dict.has_key(''):
            del domain_dict['']

        # Add a new key for the domain being activated
        domain_dict[name] = None

        # Write out the joined keys
        self.set('sssd','domains', ", ".join(domain_dict.keys()))

    def deactivate_domain(self, name):
        """
        Deactivate a configured domain

        name:
          The name of the configured domain to deactivate

        === Returns ===
        No return value

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        NoDomainError:
          No domain by this name is configured
        """

        if not self.initialized:
            raise NotInitializedError

        if name not in self.list_domains():
            raise NoDomainError
        item = self.get_option_index('sssd', 'domains')[1]
        if not item:
            self.set('sssd','domains', '')
            return

        # Turn the items into a set of dictionary keys
        # This guarantees uniqueness and makes it easy
        # to remove the one unwanted value.
        domain_dict = dict.fromkeys(striplist(item['value'].split(',')))
        if domain_dict.has_key(''):
            del domain_dict['']

        # Remove the unwanted domain from the lest
        if domain_dict.has_key(name):
            del domain_dict[name]

        # Write out the joined keys
        self.set('sssd','domains', ", ".join(domain_dict.keys()))

    def delete_domain(self, name):
        """
        Remove a domain from the SSSDConfig object. This function will also
        remove this domain from the list of active domains in the [SSSD]
        section, if it is there.

        === Returns ===
        No return value

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        """
        if not self.initialized:
            raise NotInitializedError

        # Remove the domain from the active domains list if applicable
        self.deactivate_domain(name)
        self.delete_option('section', 'domain/%s' % name)

    def save_domain(self, domain):
        """
        Save the changes made to the domain object back to the SSSDConfig
        object. If this domain is marked active, ensure it is present in the
        active domain list in the [SSSD] section

        domain_object:
          The SSSDDomain object to save to the configuration.

        === Returns ===
        No return value

        === Errors ===
        NotInitializedError:
          This SSSDConfig object has not had import_config() or new_config()
          run on it yet.
        TypeError:
          domain_object was not of type SSSDDomain
        """
        if not self.initialized:
            raise NotInitializedError
        if not isinstance(domain, SSSDDomain):
            raise TypeError

        name = domain.get_name()

        oldindex = None
        if domain.oldname and domain.oldname != name:
            # We are renaming this domain
            # Remove the old section

            self.deactivate_domain(domain.oldname)
            oldindex = self.delete_option('section', 'domain/%s' %
                                          domain.oldname)

            # Reset the oldname, in case we're not done with
            # this domain object.
            domain.oldname = None;

        sectionname = 'domain/%s' % name
        # Ensure that the existing section is removed
        # This way we ensure that we are getting a
        # complete copy of the service.
        # delete_option() is a noop if the section
        # does not exist.
        index = self.delete_option('section', sectionname)
        addkw = []
        for option,value in domain.get_all_options().items():
            if (type(value) == list):
                value = ', '.join(value)
            addkw.append( { 'type'  : 'option',
                            'name'  : option,
                            'value' : str(value) } )
        if oldindex:
            self.add_section(sectionname, addkw, oldindex)
        else:
            self.add_section(sectionname, addkw, index)

        if domain.active:
            self.activate_domain(name)
        else:
            self.deactivate_domain(name)
