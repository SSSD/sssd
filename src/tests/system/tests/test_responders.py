"""
SSSD Tests

:requirement:
"""

"""
?:needs review
c:covered
+:todo
-:drop
-> move

bash
====
# domains_pam_option
?:Default behaviour of pam trusted users and pam public domains when domains equal LDAP
?:Set pam trusted users to user and pam public domains to none when domains equal LDAP
?:Set pam trusted users to user and pam public domains to all when domains equal LDAP
?:Set pam trusted users to user and pam public domains to none when domains equal LDAP KRB
?:Set pam public domains to none and authenticate krb5 domain user when domains equal LDAP
?:Set pam public domains to KRB5 when domains equal LDAP KRB
?:Use different pam service and auth against LDAP KRB5 domains
?:Set empty value to option domains in pam file
?:Remove option domains from pam service file
?:Verify KRB domain user password change when domains equal KRB5
?:Verify KRB5 domain user password change when domains equal LDAP
?:Use untrusted user and verify domain user password change
?:Set pam trusted users to Unresolved user and verify sssd service status
?:Set pam trusted users to user ids and verify domain user auth
?:Set pam trusted users to Non existing user ids and verify sssd service status
?:Test case insensitive behaviour of domain names
?:Set domains to PROXY and verify domain user auth and password change
?:Set domains to PROXY and verify domain user auth with untrusted user
?:Use fully qualified names for domain users and verify auth when domains equal PROXY
?:Use fully qualified names for domain users and verify auth with untrusted user
?:Use fully qualified names for domain users and verify password change when domains equal PROXY
?:Test pam open session module with a trusted user
?:Test pam open session module with an untrusted user
?:Test pam close session module with a trusted user
?:Test pam close session module with an untrusted user
?:Test pam acct mgmt module with a trusted user
?:Test pam acct mgmt module with an untrusted user


intg
====
# test_pac_responder.py
?:test_multithreaded_pac_client

# test_pam_responder.py
?:test_preauth_indicator
?:test_password_prompting_config_global
?:test_password_prompting_config_srv
?:test_sc_auth_wrong_pin
?:test_sc_auth
?:test_sc_auth_two
?:test_sc_auth_two_missing_name
?:test_sc_proxy_password_fallback
?:test_sc_proxy_no_password_fallback
?:test_require_sc_auth
?:test_require_sc_auth_no_cert
?:test_try_sc_auth_no_map
?:test_try_sc_auth
?:test_try_sc_auth_root
?:test_sc_auth_missing_name
?:test_sc_auth_missing_name_whitespace
?:test_sc_auth_name_format
?:test_krb5_auth
?:test_krb5_auth_domains

multihost
=========
# test_sssd_nss.py
?:test_avoid_interlocking_among_threads
"""