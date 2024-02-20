import sys
import gettext

PACKAGE = 'sss_daemon'
LOCALEDIR = '/usr/share/locale'

translation = gettext.translation(PACKAGE, LOCALEDIR, fallback=True)
if sys.version_info[0] > 2:
    _ = translation.gettext
else:
    _ = translation.ugettext


class SSSDOptions(object):
    def __init__(self):
        pass

    option_strings = {
        # [service]
        'debug': _('Set the verbosity of the debug logging'),
        'debug_level': _('Set the verbosity of the debug logging'),
        'debug_timestamps': _('Include timestamps in debug logs'),
        'debug_microseconds': _('Include microseconds in timestamps in debug logs'),
        'debug_backtrace_enabled': _('Enable/disable debug backtrace'),
        'timeout': _('Watchdog timeout before restarting service'),
        'command': _('Command to start service'),
        'reconnection_retries': _('Number of times to attempt connection to Data Providers'),
        'fd_limit': _('The number of file descriptors that may be opened by this responder'),
        'client_idle_timeout': _('Idle time before automatic disconnection of a client'),
        'responder_idle_timeout': _('Idle time before automatic shutdown of the responder'),
        'cache_first': _('Always query all the caches before querying the Data Providers'),
        'offline_timeout': _('When SSSD switches to offline mode the amount of time before it tries to go back online '
                             'will increase based upon the time spent disconnected. This value is in seconds and '
                             'calculated by the following: offline_timeout + random_offset.'),

        # [sssd]
        'services': _('SSSD Services to start'),
        'domains': _('SSSD Domains to start'),
        're_expression': _('Regex to parse username and domain'),
        'full_name_format': _('Printf-compatible format for displaying fully-qualified names'),
        'krb5_rcache_dir': _('Directory on the filesystem where SSSD should store Kerberos replay cache files.'),
        'default_domain_suffix': _('Domain to add to names without a domain component.'),
        'user': _('The user to drop privileges to'),
        'certificate_verification': _('Tune certificate verification'),
        'override_space': _('All spaces in group or user names will be replaced with this character'),
        'disable_netlink': _('Tune sssd to honor or ignore netlink state changes'),
        'enable_files_domain': _('Enable or disable the implicit files domain'),
        'domain_resolution_order': _('A specific order of the domains to be looked up'),
        'monitor_resolv_conf': _('Controls if SSSD should monitor the state of resolv.conf to identify when it needs '
                                 'to update its internal DNS resolver.'),
        'try_inotify': _('SSSD monitors the state of resolv.conf to identify when it needs to update its internal DNS '
                         'resolver. By default, we will attempt to use inotify for this, and will fall back to '
                         'polling resolv.conf every five seconds if inotify cannot be used.'),
        'implicit_pac_responder': _('Run PAC responder automatically for AD and IPA provider'),
        'core_dumpable': _('Enable or disable core dumps for all SSSD processes.'),
        'passkey_verification': _('Tune passkey verification behavior'),

        # [nss]
        'enum_cache_timeout': _('Enumeration cache timeout length (seconds)'),
        'entry_cache_no_wait_timeout': _('Entry cache background update timeout length (seconds)'),
        'entry_negative_timeout': _('Negative cache timeout length (seconds)'),
        'local_negative_timeout': _('Files negative cache timeout length (seconds)'),
        'filter_users': _('Users that SSSD should explicitly ignore'),
        'filter_groups': _('Groups that SSSD should explicitly ignore'),
        'filter_users_in_groups': _('Should filtered users appear in groups'),
        'pwfield': _('The value of the password field the NSS provider should return'),
        'override_homedir': _('Override homedir value from the identity provider with this value'),
        'fallback_homedir': _('Substitute empty homedir value from the identity provider with this value'),
        'override_shell': _('Override shell value from the identity provider with this value'),
        'allowed_shells': _('The list of shells users are allowed to log in with'),
        'vetoed_shells': _('The list of shells that will be vetoed, and replaced with the fallback shell'),
        'shell_fallback': _('If a shell stored in central directory is allowed but not available, use this fallback'),
        'default_shell': _('Shell to use if the provider does not list one'),
        'memcache_timeout': _('How long will be in-memory cache records valid'),
        'memcache_size_passwd': _(
            'Size (in megabytes) of the data table allocated inside fast in-memory cache for passwd requests'),
        'memcache_size_group': _(
            'Size (in megabytes) of the data table allocated inside fast in-memory cache for group requests'),
        'memcache_size_initgroups': _(
            'Size (in megabytes) of the data table allocated inside fast in-memory cache for initgroups requests'),
        'homedir_substring': _('The value of this option will be used in the expansion of the override_homedir option '
                               'if the template contains the format string %H.'),
        'get_domains_timeout': _('Specifies time in seconds for which the list of subdomains will be considered '
                                 'valid.'),
        'entry_cache_nowait_percentage': _('The entry cache can be set to automatically update entries in the '
                                           'background if they are requested beyond a percentage of the '
                                           'entry_cache_timeout value for the domain.'),

        # [pam]
        'offline_credentials_expiration': _('How long to allow cached logins between online logins (days)'),
        'offline_failed_login_attempts': _('How many failed logins attempts are allowed when offline'),
        'offline_failed_login_delay': _(
            'How long (minutes) to deny login after offline_failed_login_attempts has been reached'),
        'pam_verbosity': _('What kind of messages are displayed to the user during authentication'),
        'pam_response_filter': _('Filter PAM responses sent to the pam_sss'),
        'pam_id_timeout': _('How many seconds to keep identity information cached for PAM requests'),
        'pam_pwd_expiration_warning': _('How many days before password expiration a warning should be displayed'),
        'pam_trusted_users': _('List of trusted uids or user\'s name'),
        'pam_public_domains': _('List of domains accessible even for untrusted users.'),
        'pam_account_expired_message': _('Message printed when user account is expired.'),
        'pam_account_locked_message': _('Message printed when user account is locked.'),
        'pam_cert_auth': _('Allow certificate based/Smartcard authentication.'),
        'pam_cert_db_path': _('Path to certificate database with PKCS#11 modules.'),
        'pam_cert_verification': _('Tune certificate verification for PAM authentication.'),
        'p11_child_timeout': _('How many seconds will pam_sss wait for p11_child to finish'),
        'pam_app_services': _('Which PAM services are permitted to contact application domains'),
        'pam_p11_allowed_services': _('Allowed services for using smartcards'),
        'p11_wait_for_card_timeout': _('Additional timeout to wait for a card if requested'),
        'p11_uri': _('PKCS#11 URI to restrict the selection of devices for Smartcard authentication'),
        'pam_initgroups_scheme': _('When shall the PAM responder force an initgroups request'),
        'pam_gssapi_services': _('List of PAM services that are allowed to authenticate with GSSAPI.'),
        'pam_gssapi_check_upn': _('Whether to match authenticated UPN with target user'),
        'pam_gssapi_indicators_map': _('List of pairs <PAM service>:<authentication indicator> that '
                                       'must be enforced for PAM access with GSSAPI authentication'),
        'pam_passkey_auth': _('Allow passkey device authentication.'),
        'passkey_child_timeout': _('How many seconds will pam_sss wait for passkey_child to finish'),
        'passkey_debug_libfido2': _('Enable debugging in the libfido2 library'),
        'pam_json_services': _('Enable JSON protocol for authentication methods selection.'),

        # [sudo]
        'sudo_timed': _('Whether to evaluate the time-based attributes in sudo rules'),
        'sudo_inverse_order': _('If true, SSSD will switch back to lower-wins ordering logic'),
        'sudo_threshold': _('Maximum number of rules that can be refreshed at once. If this is exceeded, full refresh '
                            'is performed.'),

        # [autofs]
        'autofs_negative_timeout': _('Negative cache timeout length (seconds)'),

        # [ssh]
        'ssh_hash_known_hosts': _('Whether to hash host names and addresses in the known_hosts file'),
        'ssh_known_hosts_timeout': _('How many seconds to keep a host in the known_hosts file after its host keys '
                                     'were requested'),
        'ca_db': _('Path to storage of trusted CA certificates'),
        'ssh_use_certificate_keys': _('Allow to generate ssh-keys from certificates'),
        'ssh_use_certificate_matching_rules': _('Use the following matching rules to filter the certificates for '
                                                'ssh-key generation'),

        # [pac]
        'allowed_uids': _('List of UIDs or user names allowed to access the PAC responder'),
        'pac_lifetime': _('How long the PAC data is considered valid'),
        'pac_check': _('Validate the PAC'),

        # [ifp]
        'user_attributes': _('List of user attributes the InfoPipe is allowed to publish'),

        # [session_recording]
        'scope': _('One of the following strings specifying the scope of session recording: none - No users are '
                   'recorded. some - Users/groups specified by users and groups options are recorded. all - All users '
                   'are recorded.'),
        'users': _('A comma-separated list of users which should have session recording enabled. Matches user names '
                   'as returned by NSS. I.e. after the possible space replacement, case changes, etc.'),
        'groups': _('A comma-separated list of groups, members of which should have session recording enabled. '
                    'Matches group names as returned by NSS. I.e. after the possible space replacement, case changes, '
                    'etc.'),
        'exclude_users': _('A comma-separated list of users to be excluded from recording, only when scope=all'),
        'exclude_groups': _('A comma-separated list of groups, members of which should be excluded from recording, '
                            ' only when scope=all. '),

        # [provider]
        'id_provider': _('Identity provider'),
        'auth_provider': _('Authentication provider'),
        'access_provider': _('Access control provider'),
        'chpass_provider': _('Password change provider'),
        'sudo_provider': _('SUDO provider'),
        'autofs_provider': _('Autofs provider'),
        'hostid_provider': _('Host identity provider'),
        'selinux_provider': _('SELinux provider'),
        'session_provider': _('Session management provider'),
        'resolver_provider': _('Resolver provider'),

        # [domain]
        'domain_type': _('Whether the domain is usable by the OS or by applications'),
        'enabled': _('Enable or disable the domain'),
        'min_id': _('Minimum user ID'),
        'max_id': _('Maximum user ID'),
        'enumerate': _('Enable enumerating all users/groups'),
        'cache_credentials': _('Cache credentials for offline login'),
        'use_fully_qualified_names': _('Display users/groups in fully-qualified form'),
        'ignore_group_members': _('Don\'t include group members in group lookups'),
        'entry_cache_timeout': _('Entry cache timeout length (seconds)'),
        'lookup_family_order': _('Restrict or prefer a specific address family when performing DNS lookups'),
        'account_cache_expiration': _('How long to keep cached entries after last successful login (days)'),
        'dns_resolver_server_timeout': _('How long should SSSD talk to single DNS server before trying next server ('
                                         'miliseconds)'),
        'dns_resolver_op_timeout': _('How long should keep trying to resolve single DNS query (seconds)'),
        'dns_resolver_timeout': _('How long to wait for replies from DNS when resolving servers (seconds)'),
        'dns_discovery_domain': _('The domain part of service discovery DNS query'),
        'override_gid': _('Override GID value from the identity provider with this value'),
        'case_sensitive': _('Treat usernames as case sensitive'),
        'entry_cache_user_timeout': _('Entry cache timeout length (seconds)'),
        'entry_cache_group_timeout': _('Entry cache timeout length (seconds)'),
        'entry_cache_netgroup_timeout': _('Entry cache timeout length (seconds)'),
        'entry_cache_service_timeout': _('Entry cache timeout length (seconds)'),
        'entry_cache_autofs_timeout': _('Entry cache timeout length (seconds)'),
        'entry_cache_sudo_timeout': _('Entry cache timeout length (seconds)'),
        'entry_cache_resolver_timeout': _('Entry cache timeout length (seconds)'),
        'refresh_expired_interval': _('How often should expired entries be refreshed in background'),
        'refresh_expired_interval_offset': _("Maximum period deviation when refreshing expired entries in background"),
        'dyndns_update': _("Whether to automatically update the client's DNS entry"),
        'dyndns_ttl': _("The TTL to apply to the client's DNS entry after updating it"),
        'dyndns_iface': _("The interface whose IP should be used for dynamic DNS updates"),
        'dyndns_refresh_interval': _("How often to periodically update the client's DNS entry"),
        'dyndns_refresh_interval_offset': _("Maximum period deviation when updating the client's DNS entry"),
        'dyndns_update_ptr': _("Whether the provider should explicitly update the PTR record as well"),
        'dyndns_force_tcp': _("Whether the nsupdate utility should default to using TCP"),
        'dyndns_auth': _("What kind of authentication should be used to perform the DNS update"),
        'dyndns_server': _("Override the DNS server used to perform the DNS update"),
        'subdomain_enumerate': _('Control enumeration of trusted domains'),
        'subdomain_refresh_interval': _('How often should subdomains list be refreshed'),
        'subdomain_refresh_interval_offset': _('Maximum period deviation when refreshing the subdomain list'),
        'subdomain_inherit': _('List of options that should be inherited into a subdomain'),
        'subdomain_homedir': _('Default subdomain homedir value'),
        'cached_auth_timeout': _('How long can cached credentials be used for cached authentication'),
        'auto_private_groups': _('Whether to automatically create private groups for users'),
        'pwd_expiration_warning': _('Display a warning N days before the password expires.'),
        'realmd_tags': _('Various tags stored by the realmd configuration service for this domain.'),
        'subdomains_provider': _('The provider which should handle fetching of subdomains. This value should be '
                                 'always the same as id_provider.'),
        'entry_cache_ssh_host_timeout': _('How many seconds to keep a host ssh key after refresh. IE how long to '
                                          'cache the host key for.'),
        'cache_credentials_minimal_first_factor_length': _('If 2-Factor-Authentication (2FA) is used and credentials '
                                                           'should be saved this value determines the minimal length '
                                                           'the first authentication factor (long term password) must '
                                                           'have to be saved as SHA512 hash into the cache.'),
        'local_auth_policy': _('Local authentication methods policy '),

        # [provider/ipa]
        'ipa_domain': _('IPA domain'),
        'ipa_server': _('IPA server address'),
        'ipa_backup_server': _('Address of backup IPA server'),
        'ipa_hostname': _('IPA client hostname'),
        'ipa_dyndns_update': _("Whether to automatically update the client's DNS entry in FreeIPA"),
        'ipa_dyndns_ttl': _("The TTL to apply to the client's DNS entry after updating it"),
        'ipa_dyndns_iface': _("The interface whose IP should be used for dynamic DNS updates"),
        'ipa_hbac_search_base': _("Search base for HBAC related objects"),
        'ipa_hbac_refresh': _("The amount of time between lookups of the HBAC rules against the IPA server"),
        'ipa_selinux_refresh': _("The amount of time in seconds between lookups of the SELinux maps against the IPA "
                                 "server"),
        'ipa_hbac_support_srchost': _("If set to false, host argument given by PAM will be ignored"),
        'ipa_automount_location': _("The automounter location this IPA client is using"),
        'ipa_master_domain_search_base': _("Search base for object containing info about IPA domain"),
        'ipa_ranges_search_base': _("Search base for objects containing info about ID ranges"),
        'ipa_enable_dns_sites': _("Enable DNS sites - location based service discovery"),
        'ipa_views_search_base': _("Search base for view containers"),
        'ipa_view_class': _("Objectclass for view containers"),
        'ipa_view_name': _("Attribute with the name of the view"),
        'ipa_override_object_class': _("Objectclass for override objects"),
        'ipa_anchor_uuid': _("Attribute with the reference to the original object"),
        'ipa_user_override_object_class': _("Objectclass for user override objects"),
        'ipa_group_override_object_class': _("Objectclass for group override objects"),
        'ipa_deskprofile_search_base': _("Search base for Desktop Profile related objects"),
        'ipa_deskprofile_refresh': _("The amount of time in seconds between lookups of the Desktop Profile rules "
                                     "against the IPA server"),
        'ipa_deskprofile_request_interval': _("The amount of time in minutes between lookups of Desktop Profiles "
                                              "rules against the IPA server when the last request did not find any "
                                              "rule"),
        'ipa_subid_ranges_search_base': _("Search base for SUBID ranges"),
        'ipa_access_order': _("Which rules should be used to evaluate access control"),
        'ipa_host_fqdn': _('The LDAP attribute that contains FQDN of the host.'),
        'ipa_host_object_class': _('The object class of a host entry in LDAP.'),
        'ipa_host_search_base': _('Use the given string as search base for host objects.'),
        'ipa_host_ssh_public_key': _('The LDAP attribute that contains the host\'s SSH public keys.'),
        'ipa_netgroup_domain': _('The LDAP attribute that contains NIS domain name of the netgroup.'),
        'ipa_netgroup_member': _('The LDAP attribute that contains the names of the netgroup\'s members.'),
        'ipa_netgroup_member_ext_host': _('The LDAP attribute that lists FQDNs of hosts and host groups that are '
                                          'members of the netgroup.'),
        'ipa_netgroup_member_host': _('The LDAP attribute that lists hosts and host groups that are direct members of '
                                      'the netgroup.'),
        'ipa_netgroup_member_of': _('The LDAP attribute that lists netgroup\'s memberships.'),
        'ipa_netgroup_member_user': _('The LDAP attribute that lists system users and groups that are direct members '
                                      'of the netgroup.'),
        'ipa_netgroup_name': _('The LDAP attribute that corresponds to the netgroup name.'),
        'ipa_netgroup_object_class': _('The object class of a netgroup entry in LDAP.'),
        'ipa_netgroup_uuid': _('The LDAP attribute that contains the UUID/GUID of an LDAP netgroup object.'),
        'ipa_selinux_usermap_enabled': _('The LDAP attribute that contains whether or not is user map enabled for '
                                         'usage.'),
        'ipa_selinux_usermap_host_category': _('The LDAP attribute that contains host category such as \'all\'.'),
        'ipa_selinux_usermap_member_host': _('The LDAP attribute that contains all hosts / hostgroups this rule match '
                                             'against.'),
        'ipa_selinux_usermap_member_user': _('The LDAP attribute that contains all users / groups this rule match '
                                             'against.'),
        'ipa_selinux_usermap_name': _('The LDAP attribute that contains the name of SELinux usermap.'),
        'ipa_selinux_usermap_object_class': _('The object class of a host entry in LDAP.'),
        'ipa_selinux_usermap_see_also': _('The LDAP attribute that contains DN of HBAC rule which can be used for '
                                          'matching instead of memberUser and memberHost.'),
        'ipa_selinux_usermap_selinux_user': _('The LDAP attribute that contains SELinux user string itself.'),
        'ipa_selinux_usermap_user_category': _('The LDAP attribute that contains user category such as \'all\'.'),
        'ipa_selinux_usermap_uuid': _('The LDAP attribute that contains unique ID of the user map.'),
        'ipa_server_mode': _('The option denotes that the SSSD is running on IPA server and should perform lookups of '
                             'users and groups from trusted domains differently.'),
        'ipa_subdomains_search_base': _('Use the given string as search base for trusted domains.'),

        # [provider/ad]
        'ad_domain': _('Active Directory domain'),
        'ad_enabled_domains': _('Enabled Active Directory domains'),
        'ad_server': _('Active Directory server address'),
        'ad_backup_server': _('Active Directory backup server address'),
        'ad_hostname': _('Active Directory client hostname'),
        'ad_enable_dns_sites': _('Enable DNS sites - location based service discovery'),
        'ad_access_filter': _('LDAP filter to determine access privileges'),
        'ad_enable_gc': _('Whether to use the Global Catalog for lookups'),
        'ad_gpo_access_control': _('Operation mode for GPO-based access control'),
        'ad_gpo_cache_timeout': _("The amount of time between lookups of the GPO policy files against the AD server"),
        'ad_gpo_map_interactive': _('PAM service names that map to the GPO (Deny)InteractiveLogonRight '
                                    'policy settings'),
        'ad_gpo_map_remote_interactive': _('PAM service names that map to the GPO (Deny)RemoteInteractiveLogonRight '
                                           'policy settings'),
        'ad_gpo_map_network': _('PAM service names that map to the GPO (Deny)NetworkLogonRight policy settings'),
        'ad_gpo_map_batch': _('PAM service names that map to the GPO (Deny)BatchLogonRight policy settings'),
        'ad_gpo_map_service': _('PAM service names that map to the GPO (Deny)ServiceLogonRight policy settings'),
        'ad_gpo_map_permit': _('PAM service names for which GPO-based access is always granted'),
        'ad_gpo_map_deny': _('PAM service names for which GPO-based access is always denied'),
        'ad_gpo_default_right': _('Default logon right (or permit/deny) to use for unmapped PAM service names'),
        'ad_site': _('a particular site to be used by the client'),
        'ad_maximum_machine_account_password_age': _('Maximum age in days before the machine account password should '
                                                     'be renewed'),
        'ad_machine_account_password_renewal_opts': _('Option for tuning the machine account renewal task'),
        'ad_update_samba_machine_account_password': _('Whether to update the machine account password in the Samba '
                                                      'database'),
        'ad_use_ldaps': _('Use LDAPS port for LDAP and Global Catalog requests'),
        'ad_allow_remote_domain_local_groups': _('Do not filter domain local groups from other domains'),

        # [provider/krb5]
        'krb5_kdcip': _('Kerberos server address'),
        'krb5_server': _('Kerberos server address'),
        'krb5_backup_server': _('Kerberos backup server address'),
        'krb5_realm': _('Kerberos realm'),
        'krb5_auth_timeout': _('Authentication timeout'),
        'krb5_use_kdcinfo': _('Whether to create kdcinfo files'),
        'krb5_confd_path': _('Where to drop krb5 config snippets'),

        # [provider/krb5/auth]
        'krb5_ccachedir': _('Directory to store credential caches'),
        'krb5_ccname_template': _("Location of the user's credential cache"),
        'krb5_keytab': _("Location of the keytab to validate credentials"),
        'krb5_validate': _("Enable credential validation"),
        'krb5_store_password_if_offline': _("Store password if offline for later online authentication"),
        'krb5_renewable_lifetime': _("Renewable lifetime of the TGT"),
        'krb5_lifetime': _("Lifetime of the TGT"),
        'krb5_renew_interval': _("Time between two checks for renewal"),
        'krb5_use_fast': _("Enables FAST"),
        'krb5_fast_principal': _("Selects the principal to use for FAST"),
        'krb5_fast_use_anonymous_pkinit': _("Use anonymous PKINIT to request FAST credentials"),
        'krb5_canonicalize': _("Enables principal canonicalization"),
        'krb5_use_enterprise_principal': _("Enables enterprise principals"),
        'krb5_use_subdomain_realm': _("Enables using of subdomains realms for authentication"),
        'krb5_map_user': _('A mapping from user names to Kerberos principal names'),

        # [provider/krb5/chpass]
        'krb5_kpasswd': _('Server where the change password service is running if not on the KDC'),
        'krb5_backup_kpasswd': _('Server where the change password service is running if not on the KDC'),

        # [provider/ldap]
        'ldap_uri': _('ldap_uri, The URI of the LDAP server'),
        'ldap_backup_uri': _('ldap_backup_uri, The URI of the LDAP server'),
        'ldap_search_base': _('The default base DN'),
        'ldap_schema': _('The Schema Type in use on the LDAP server, rfc2307'),
        'ldap_pwmodify_mode': _('Mode used to change user password'),
        'ldap_default_bind_dn': _('The default bind DN'),
        'ldap_default_authtok_type': _('The type of the authentication token of the default bind DN'),
        'ldap_default_authtok': _('The authentication token of the default bind DN'),
        'ldap_network_timeout': _('Length of time to attempt connection'),
        'ldap_opt_timeout': _('Length of time to attempt synchronous LDAP operations'),
        'ldap_offline_timeout': _('Length of time between attempts to reconnect while offline'),
        'ldap_force_upper_case_realm': _('Use only the upper case for realm names'),
        'ldap_tls_cacert': _('File that contains CA certificates'),
        'ldap_tls_cacertdir': _('Path to CA certificate directory'),
        'ldap_tls_cert': _('File that contains the client certificate'),
        'ldap_tls_key': _('File that contains the client key'),
        'ldap_tls_cipher_suite': _('List of possible ciphers suites'),
        'ldap_tls_reqcert': _('Require TLS certificate verification'),
        'ldap_sasl_mech': _('Specify the sasl mechanism to use'),
        'ldap_sasl_authid': _('Specify the sasl authorization id to use'),
        'ldap_sasl_realm': _('Specify the sasl authorization realm to use'),
        'ldap_sasl_minssf': _('Specify the minimal SSF for LDAP sasl authorization'),
        'ldap_sasl_maxssf': _('Specify the maximal SSF for LDAP sasl authorization'),
        'ldap_krb5_keytab': _('Kerberos service keytab'),
        'ldap_krb5_init_creds': _('Use Kerberos auth for LDAP connection'),
        'ldap_referrals': _('Follow LDAP referrals'),
        'ldap_krb5_ticket_lifetime': _('Lifetime of TGT for LDAP connection'),
        'ldap_deref': _('How to dereference aliases'),
        'ldap_dns_service_name': _('Service name for DNS service lookups'),
        'ldap_page_size': _('The number of records to retrieve in a single LDAP query'),
        'ldap_deref_threshold': _('The number of members that must be missing to trigger a full deref'),
        'ldap_ignore_unreadable_references': _('Ignore unreadable LDAP references'),
        'ldap_sasl_canonicalize': _('Whether the LDAP library should perform a reverse lookup to canonicalize the '
                                    'host name during a SASL bind'),
        'ldap_rfc2307_fallback_to_local_users': _('Allows to retain local users as members of an LDAP group for '
                                                  'servers that use the RFC2307 schema.'),

        'ldap_entry_usn': _('entryUSN attribute'),
        'ldap_rootdse_last_usn': _('lastUSN attribute'),

        'ldap_connection_expiration_timeout': _('How long to retain a connection to the LDAP server before '
                                                'disconnecting'),

        'ldap_disable_paging': _('Disable the LDAP paging control'),
        'ldap_disable_range_retrieval': _('Disable Active Directory range retrieval'),
        'ldap_use_ppolicy': _('Use the ppolicy extension'),

        # [provider/ldap/id]
        'ldap_search_timeout': _('Length of time to wait for a search request'),
        'ldap_enumeration_search_timeout': _('Length of time to wait for a enumeration request'),
        'ldap_enumeration_refresh_timeout': _('Length of time between enumeration updates'),
        'ldap_enumeration_refresh_offset': _('Maximum period deviation between enumeration updates'),
        'ldap_purge_cache_timeout': _('Length of time between cache cleanups'),
        'ldap_purge_cache_offset': _('Maximum time deviation between cache cleanups'),
        'ldap_id_use_start_tls': _('Require TLS for ID lookups'),
        'ldap_id_mapping': _('Use ID-mapping of objectSID instead of pre-set IDs'),
        'ldap_user_search_base': _('Base DN for user lookups'),
        'ldap_user_search_scope': _('Scope of user lookups'),
        'ldap_user_search_filter': _('Filter for user lookups'),
        'ldap_user_object_class': _('Objectclass for users'),
        'ldap_user_name': _('Username attribute'),
        'ldap_user_uid_number': _('UID attribute'),
        'ldap_user_gid_number': _('Primary GID attribute'),
        'ldap_user_gecos': _('GECOS attribute'),
        'ldap_user_home_directory': _('Home directory attribute'),
        'ldap_user_shell': _('Shell attribute'),
        'ldap_user_uuid': _('UUID attribute'),
        'ldap_user_objectsid': _("objectSID attribute"),
        'ldap_user_primary_group': _('Active Directory primary group attribute for ID-mapping'),
        'ldap_user_principal': _('User principal attribute (for Kerberos)'),
        'ldap_user_fullname': _('Full Name'),
        'ldap_user_member_of': _('memberOf attribute'),
        'ldap_user_modify_timestamp': _('Modification time attribute'),
        'ldap_user_shadow_last_change': _('shadowLastChange attribute'),
        'ldap_user_shadow_min': _('shadowMin attribute'),
        'ldap_user_shadow_max': _('shadowMax attribute'),
        'ldap_user_shadow_warning': _('shadowWarning attribute'),
        'ldap_user_shadow_inactive': _('shadowInactive attribute'),
        'ldap_user_shadow_expire': _('shadowExpire attribute'),
        'ldap_user_shadow_flag': _('shadowFlag attribute'),
        'ldap_user_authorized_service': _('Attribute listing authorized PAM services'),
        'ldap_user_authorized_host': _('Attribute listing authorized server hosts'),
        'ldap_user_authorized_rhost': _('Attribute listing authorized server rhosts'),
        'ldap_user_krb_last_pwd_change': _('krbLastPwdChange attribute'),
        'ldap_user_krb_password_expiration': _('krbPasswordExpiration attribute'),
        'ldap_pwd_attribute': _('Attribute indicating that server side password policies are active'),
        'ldap_user_ad_account_expires': _('accountExpires attribute of AD'),
        'ldap_user_ad_user_account_control': _('userAccountControl attribute of AD'),
        'ldap_ns_account_lock': _('nsAccountLock attribute'),
        'ldap_user_nds_login_disabled': _('loginDisabled attribute of NDS'),
        'ldap_user_nds_login_expiration_time': _('loginExpirationTime attribute of NDS'),
        'ldap_user_nds_login_allowed_time_map': _('loginAllowedTimeMap attribute of NDS'),
        'ldap_user_ssh_public_key': _('SSH public key attribute'),
        'ldap_user_auth_type': _('attribute listing allowed authentication types for a user'),
        'ldap_user_certificate': _('attribute containing the X509 certificate of the user'),
        'ldap_user_email': _('attribute containing the email address of the user'),
        'ldap_user_passkey': _('attribute containing the passkey mapping data of the user'),
        'ldap_user_extra_attrs': _('A list of extra attributes to download along with the user entry'),

        'ldap_group_search_base': _('Base DN for group lookups'),
        'ldap_group_object_class': _('Objectclass for groups'),
        'ldap_group_name': _('Group name'),
        'ldap_group_pwd': _('Group password'),
        'ldap_group_gid_number': _('GID attribute'),
        'ldap_group_member': _('Group member attribute'),
        'ldap_group_uuid': _('Group UUID attribute'),
        'ldap_group_objectsid': _("objectSID attribute"),
        'ldap_group_modify_timestamp': _('Modification time attribute for groups'),
        'ldap_group_type': _('Type of the group and other flags'),
        'ldap_group_external_member': _('The LDAP group external member attribute'),
        'ldap_group_nesting_level': _('Maximum nesting level SSSD will follow'),
        'ldap_group_search_filter': _('Filter for group lookups'),
        'ldap_group_search_scope': _('Scope of group lookups'),

        'ldap_netgroup_search_base': _('Base DN for netgroup lookups'),
        'ldap_netgroup_object_class': _('Objectclass for netgroups'),
        'ldap_netgroup_name': _('Netgroup name'),
        'ldap_netgroup_member': _('Netgroups members attribute'),
        'ldap_netgroup_triple': _('Netgroup triple attribute'),
        'ldap_netgroup_modify_timestamp': _('Modification time attribute for netgroups'),

        'ldap_service_search_base': _('Base DN for service lookups'),
        'ldap_service_object_class': _('Objectclass for services'),
        'ldap_service_name': _('Service name attribute'),
        'ldap_service_port': _('Service port attribute'),
        'ldap_service_proto': _('Service protocol attribute'),

        'ldap_idmap_range_min': _('Lower bound for ID-mapping'),
        'ldap_idmap_range_max': _('Upper bound for ID-mapping'),
        'ldap_idmap_range_size': _('Number of IDs for each slice when ID-mapping'),
        'ldap_idmap_autorid_compat': _('Use autorid-compatible algorithm for ID-mapping'),
        'ldap_idmap_default_domain': _('Name of the default domain for ID-mapping'),
        'ldap_idmap_default_domain_sid': _('SID of the default domain for ID-mapping'),
        'ldap_idmap_helper_table_size': _('Number of secondary slices'),

        'ldap_use_tokengroups': _('Whether to use Token-Groups'),
        'ldap_min_id': _('Set lower boundary for allowed IDs from the LDAP server'),
        'ldap_max_id': _('Set upper boundary for allowed IDs from the LDAP server'),
        'ldap_pwdlockout_dn': _('DN for ppolicy queries'),
        'wildcard_limit': _('How many maximum entries to fetch during a wildcard request'),
        'ldap_library_debug_level': _('Set libldap debug level'),

        # [provider/ldap/auth]
        'ldap_pwd_policy': _('Policy to evaluate the password expiration'),

        # [provider/ldap/access]
        'ldap_access_filter': _('LDAP filter to determine access privileges'),
        'ldap_account_expire_policy': _('Which attributes shall be used to evaluate if an account is expired'),
        'ldap_access_order': _('Which rules should be used to evaluate access control'),

        # [provider/ldap/chpass]
        'ldap_chpass_uri': _('URI of an LDAP server where password changes are allowed'),
        'ldap_chpass_backup_uri': _('URI of a backup LDAP server where password changes are allowed'),
        'ldap_chpass_dns_service_name': _('DNS service name for LDAP password change server'),
        'ldap_chpass_update_last_change': _('Whether to update the ldap_user_shadow_last_change attribute after a '
                                            'password change'),

        # [provider/ldap/sudo]
        'ldap_sudo_search_base': _('Base DN for sudo rules lookups'),
        'ldap_sudo_full_refresh_interval': _('Automatic full refresh period'),
        'ldap_sudo_smart_refresh_interval': _('Automatic smart refresh period'),
        'ldap_sudo_random_offset': _('Smart and full refresh random offset'),
        'ldap_sudo_use_host_filter': _('Whether to filter rules by hostname, IP addresses and network'),
        'ldap_sudo_hostnames': _('Hostnames and/or fully qualified domain names of this machine to filter sudo rules'),
        'ldap_sudo_ip': _('IPv4 or IPv6 addresses or network of this machine to filter sudo rules'),
        'ldap_sudo_include_netgroups': _('Whether to include rules that contains netgroup in host attribute'),
        'ldap_sudo_include_regexp': _('Whether to include rules that contains regular expression in host attribute'),
        'ldap_sudorule_object_class': _('Object class for sudo rules'),
        'ldap_sudorule_object_class_attr': _('Name of attribute that is used as object class for sudo rules'),
        'ldap_sudorule_name': _('Sudo rule name'),
        'ldap_sudorule_command': _('Sudo rule command attribute'),
        'ldap_sudorule_host': _('Sudo rule host attribute'),
        'ldap_sudorule_user': _('Sudo rule user attribute'),
        'ldap_sudorule_option': _('Sudo rule option attribute'),
        'ldap_sudorule_runas': _('Sudo rule runas attribute'),
        'ldap_sudorule_runasuser': _('Sudo rule runasuser attribute'),
        'ldap_sudorule_runasgroup': _('Sudo rule runasgroup attribute'),
        'ldap_sudorule_notbefore': _('Sudo rule notbefore attribute'),
        'ldap_sudorule_notafter': _('Sudo rule notafter attribute'),
        'ldap_sudorule_order': _('Sudo rule order attribute'),

        # [provider/ldap/autofs]
        'ldap_autofs_map_object_class': _('Object class for automounter maps'),
        'ldap_autofs_map_name': _('Automounter map name attribute'),
        'ldap_autofs_entry_object_class': _('Object class for automounter map entries'),
        'ldap_autofs_entry_key': _('Automounter map entry key attribute'),
        'ldap_autofs_entry_value': _('Automounter map entry value attribute'),
        'ldap_autofs_search_base': _('Base DN for automounter map lookups'),
        'ldap_autofs_map_master_name': _('The name of the automount master map in LDAP.'),

        # [provider/ldap/resolver]
        'ldap_iphost_search_base': _('Base DN for IP hosts lookups'),
        'ldap_iphost_object_class': _('Object class for IP hosts'),
        'ldap_iphost_name': _('IP host name attribute'),
        'ldap_iphost_number': _('IP host number (address) attribute'),
        'ldap_iphost_entry_usn': _('IP host entryUSN attribute'),
        'ldap_ipnetwork_search_base': _('Base DN for IP networks lookups'),
        'ldap_ipnetwork_object_class': _('Object class for IP networks'),
        'ldap_ipnetwork_name': _('IP network name attribute'),
        'ldap_ipnetwork_number': _('IP network number (address) attribute'),
        'ldap_ipnetwork_entry_usn': _('IP network entryUSN attribute'),

        # [provider/simple/access]
        'simple_allow_users': _('Comma separated list of allowed users'),
        'simple_deny_users': _('Comma separated list of prohibited users'),
        'simple_allow_groups': _('Comma separated list of groups that are allowed to log in. This applies only to '
                                 'groups within this SSSD domain. Local groups are not evaluated.'),
        'simple_deny_groups': _('Comma separated list of groups that are explicitly denied access. This applies only '
                                'to groups within this SSSD domain. Local groups are not evaluated.'),

        # [provider/proxy]
        'proxy_max_children': _('The number of preforked proxy children.'),

        # [provider/proxy/id]
        'proxy_lib_name': _('The name of the NSS library to use'),
        'proxy_resolver_lib_name': _('The name of the NSS library to use for hosts and networks lookups'),
        'proxy_fast_alias': _('Whether to look up canonical group name from cache if possible'),

        # [provider/proxy/auth]
        'proxy_pam_target': _('PAM stack to use'),

        # [provider/files]
        'passwd_files': _('Path of passwd file sources.'),
        'group_files': _('Path of group file sources.')
    }
