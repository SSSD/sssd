'''
Created on Sep 18, 2009

@author: sgallagh
'''

import os
import exceptions
from ConfigParser import RawConfigParser, NoSectionError

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
class NoSuchProviderError(SSSDConfigException): pass
class NoSuchProviderSubtypeError(SSSDConfigException): pass
class ProviderSubtypeInUse(SSSDConfigException): pass

class SSSDConfigSchema(RawConfigParser):
    def __init__(self, schemafile, schemaplugindir):
        #TODO: get these from a global setting
        if not schemafile:
            schemafile = '/etc/sssd/sssd.api.conf'
        if not schemaplugindir:
            schemaplugindir = '/etc/sssd/sssd.api.d'

        RawConfigParser.__init__(self, None, dict)
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
        except:
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

    def _striplist(self, l):
        return([x.strip() for x in l])

    def get_options(self, section):
        if not self.has_section(section):
            raise NoSectionError
        options = self.options(section)

        # Parse values
        parsed_options = {}
        for option in options:
            unparsed_option = self.get(section, option)
            split_option = self._striplist(unparsed_option.split(','))
            optionlen = len(split_option)

            primarytype = self.type_lookup[split_option[0]]
            subtype = self.type_lookup[split_option[1]]

            if optionlen == 2:
                # This option has no defaults
                parsed_options[option] = \
                    (primarytype,
                     subtype,
                     None)
            elif optionlen == 3:
                if type(split_option[2]) == primarytype:
                    parsed_options[option] = \
                        (primarytype,
                         subtype,
                         split_option[2])
                elif primarytype == list:
                    if (type(split_option[2]) == subtype):
                        parsed_options[option] = \
                            (primarytype,
                             subtype,
                             [split_option[2]])
                    else:
                        try:
                            parsed_options[option] = \
                                (primarytype,
                                 subtype,
                                 [subtype(split_option[2])])
                        except ValueError:
                            raise ParsingError
                else:
                    try:
                        parsed_options[option] = \
                            (primarytype,
                             subtype,
                             primarytype(split_option[2]))
                    except ValueError:
                        raise ParsingError

            elif optionlen > 3:
                if (primarytype != list):
                    raise ParsingError
                fixed_options = []
                for x in split_option[2:]:
                    if type(x) != subtype:
                        try:
                            fixed_options.extend([subtype(x)])
                        except ValueError:
                            raise ParsingError
                    else:
                        fixed_options.extend([x])
                parsed_options[option] = \
                    (primarytype,
                     subtype,
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
        defaults = dict([(x,schema_options[x][2])
                         for x in schema_options.keys()
                         if schema_options[x][2] != None])

        return defaults

    def get_services(self):
        service_list = [x for x in self.sections()
                        if x != 'service' and
                        not x.startswith('domain') and
                        not x.startswith('provider')]
        return service_list

    def get_providers(self):
        providers = {}
        for section in self._sections:
            splitsection = section.split('/')
            if (splitsection[0] == 'provider'):
                if(len(splitsection) == 3):
                    if not providers.has_key(splitsection[1]):
                        providers[splitsection[1]] = []
                    providers[splitsection[1]].extend([splitsection[2]])
        for key in providers.keys():
            providers[key] = tuple(providers[key])
        return providers

class SSSDService:
    '''
    classdocs
    '''

    def __init__(self, servicename, apischema):
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

    def get_name(self):
        return self.name

    def list_options(self):
        options = {}

        # Get the list of available options for all services
        schema_options = self.schema.get_options('service')
        options.update(schema_options)

        schema_options = self.schema.get_options(self.name)
        options.update(schema_options)

        return options

    def _striplist(self, l):
        return([x.strip() for x in l])

    def set_option(self, optionname, value):
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

        # If we were expecting a list and didn't get one,
        # Create a list with a single entry. If it's the
        # wrong subtype, it will fail below
        if option_schema[0] == list and type(value) != list:
            if type(value) == str:
                value = self._striplist(value.split(','))
            else:
                value = [value]

        if type(value) != option_schema[0]:
            # If it's possible to convert it, do so
            try:
                value = option_schema[0](value)
            except ValueError:
                raise TypeError('Expected %s for %s, received %s' %
                            (option_schema[0], optionname, type(value)))

        if type(value) == list:
            # Iterate through the list an ensure that all members
            # are of the appropriate subtype
            try:
                value = [option_schema[1](x)
                         for x in value]
            except ValueError:
                raise TypeError('Expected %s' % option_schema[1])

        self.options[optionname] = value

    def get_option(self, optionname):
        if optionname in self.options.keys():
            return self.options[optionname]
        raise NoOptionError(optionname)

    def get_all_options(self):
        return self.options

    def remove_option(self, optionname):
        if self.options.has_key(optionname):
            del self.options[optionname]

class SSSDDomain:
    def __init__(self, domainname, apischema):
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

    def get_name(self):
        return self.name

    def set_active(self, active):
        self.active = bool(active)

    def list_options(self):
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

    def list_provider_options(self, provider, provider_type=None):
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
        return self.schema.get_providers()

    def set_option(self, option, value):
        options = self.list_options()
        if (option not in options.keys()):
            raise NoOptionError('Section [%s] has no option [%s]' %
                                (self.name, option))

        if value == None:
            self.remove_option(option)
            return

        option_schema = options[option]

        # If we were expecting a list and didn't get one,
        # Create a list with a single entry. If it's the
        # wrong subtype, it will fail below
        if option_schema[0] == list and type(value) != list:
            if type(value) == str:
                value = self._striplist(value.split(','))
            else:
                value = [value]

        if type(value) != option_schema[0]:
            # If it's possible to convert it, do so
            try:
                value = option_schema[0](value)
            except ValueError:
                raise TypeError('Expected %s for %s, received %s' %
                            (option_schema[0], option, type(value)))

        if type(value) == list:
            # Iterate through the list an ensure that all members
            # are of the appropriate subtype
            try:
                value = [option_schema[1](x)
                         for x in value]
            except ValueError:
                raise TypeError('Expected %s' % option_schema[1])

        # Check whether we're adding a provider entry.
        # This requires special handling
        is_provider = option.rfind('_provider')
        if (is_provider > 0):
            provider = option[:is_provider]
            self.add_provider(value, provider)
        else:
            self.options[option] = value

    def get_option(self, optionname):
        if optionname in self.options.keys():
            return self.options[optionname]
        raise NoOptionError(optionname)

    def get_all_options(self):
        return self.options

    def remove_option(self, optionname):
        if optionname in self.options.keys():
            del self.options[optionname]

    def add_provider(self, provider, provider_type):
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
            raise ProviderSubtypeInUser
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


    def remove_provider(self, provider, provider_type):
        if (provider,provider_type) not in self.providers:
            return

        # TODO: safely remove any unused options when removing
        # the provider. This will require modifying the schema
        # to account for multiple providers making use of the
        # same options (such ask krb5_realm)

        self.providers.remove((provider,provider_type))

class SSSDConfig(RawConfigParser):
    def __init__(self, schemafile=None, schemaplugindir=None):
        RawConfigParser.__init__(self, None, dict)
        self.schema = SSSDConfigSchema(schemafile, schemaplugindir)
        self.configfile = None
        self.initialized = False
        self.API_VERSION = 2

    def import_config(self,configfile=None):
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
        if self.initialized:
            raise AlreadyInitializedError

        self.initialized = True

        #Initialize all services
        for servicename in self.schema.get_services():
            service = self.new_service(servicename)

    def write(self, outputfile=None):
        if not self.initialized:
            raise NotInitializedError

        if outputfile == None:
            if(self.configfile == None):
                raise NoOutputFileError

            outputfile = self.configfile

        # open() will raise IOError if it fails
        of = open(outputfile, 'w')
        RawConfigParser.write(self, of)
        of.close()

    def list_services(self):
        if not self.initialized:
            raise NotInitializedError

        service_list = [x for x in self.sections()
                        if not x.startswith('domain')]
        return service_list

    def get_service(self, name):
        if not self.initialized:
            raise NotInitializedError
        if not self.has_section(name):
            raise NoServiceError

        service = SSSDService(name, self.schema)
        [service.set_option(option, value)
         for (option,value) in self.items(name)]

        return service

    def new_service(self, name):
        if not self.initialized:
            raise NotInitializedError
        if (self.has_section(name)):
            raise ServiceAlreadyExists(name)

        service = SSSDService(name, self.schema)
        self.save_service(service)
        return service

    def delete_service(self, name):
        if not self.initialized:
            raise NotInitializedError
        self.remove_section(name)

    def save_service(self, service):
        if not self.initialized:
            raise NotInitializedError
        if not isinstance(service, SSSDService):
            raise TypeError

        name = service.get_name()
        # Ensure that the existing section is removed
        # This way we ensure that we are getting a
        # complete copy of the service.
        # remove_section() is a noop if the section
        # does not exist.
        self.remove_section(name)
        self.add_section(name)
        option_dict = service.get_all_options()
        for option in option_dict.keys():
            value = option_dict[option]
            if (type(value) == list):
                value = ', '.join(value)

            self.set(name, option, value)

    def _striplist(self, l):
        return([x.strip() for x in l])

    def list_active_domains(self):
        if not self.initialized:
            raise NotInitializedError

        if (self.has_option('sssd', 'domains')):
            active_domains = self._striplist(self.get('sssd', 'domains').split(','))
        else:
            active_domains = []

        domains = [x for x in self.list_domains()
                   if x in active_domains]
        return domains

    def list_inactive_domains(self):
        if not self.initialized:
            raise NotInitializedError

        if (self.has_option('sssd', 'domains')):
            active_domains = self._striplist(self.get('sssd', 'domains').split(','))
        else:
            active_domains = []

        domains = [x for x in self.list_domains()
                   if x not in active_domains]
        return domains

    def list_domains(self):
        if not self.initialized:
            raise NotInitializedError
        domains = [x[7:] for x in self.sections() if x.startswith('domain/')]
        return domains

    def get_domain(self, name):
        if not self.initialized:
            raise NotInitializedError
        if not self.has_section('domain/%s' % name):
            raise NoDomainError(name)

        domain = SSSDDomain(name, self.schema)

        # Read in the providers first or we may have type
        # errors trying to read in their options
        providers = [x for x in self.items('domain/%s' % name)
                     if x[0].rfind('_provider') > 0]
        [domain.set_option(option, value)
         for (option, value) in providers]

        [domain.set_option(option, value)
         for (option,value) in self.items('domain/%s' % name)
         if (option,value) not in providers]

        return domain

    def new_domain(self, name):
        if not self.initialized:
            raise NotInitializedError
        if self.has_section('domain/%s' % name):
            raise DomainAlreadyExistsError

        domain = SSSDDomain(name, self.schema)
        self.save_domain(domain);
        return domain

    def delete_domain(self, name):
        if not self.initialized:
            raise NotInitializedError
        self.remove_section('domain/%s' % name)

    def save_domain(self, domain):
        if not self.initialized:
            raise NotInitializedError
        if not isinstance(domain, SSSDDomain):
            raise TypeError

        name = domain.get_name()
        sectionname = 'domain/%s' % name
        # Ensure that the existing section is removed
        # This way we ensure that we are getting a
        # complete copy of the service.
        # remove_section() is a noop if the section
        # does not exist.
        self.remove_section(sectionname)
        self.add_section(sectionname)
        option_dict = domain.get_all_options()
        [self.set(sectionname, option, option_dict[option])
         for option in option_dict.keys()]

        if domain.active:
            if domain.get_name not in self.list_active_domains():
                # Add it to the list of active domains
                if (self.has_option('sssd','domains')):
                    active_domains = self.get('sssd', 'domains')
                    active_domains += ", %s" % domain.get_name()
                else:
                    active_domains = domain.get_name()
                self.set('sssd', 'domains', active_domains)
