"""
SSSD Kerberos Provider Tests

These tests cover everything specific to Kerberos provider such as authentication,
principals and access control. The Kerberos Cache Manager (KCM) has a dedicated file,
test_kcm.py.

:requirement: krb
"""

"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

intg
====

multihost
=========
# test_krb5.py
?:test_0001_krb5_not_working_based_on_k5login
?:test_0002_generating_lot_of

# test_krb_access_provider.py
?:test_0001_k5login_empty
?:test_0002_k5login_user3
?:test_0003_k5login_user3_with_user4
?:test_0004_k5login_user4_with_deleted_user3

# test_krb_fast_principal.py
?:test_0001_valid_principal
?:test_0002_invalid_principal
?:test_0003_principal_at_?:test_test
?:test_0004_null_principal
?:test_0005_valid_principal_and_krb5_validate_true
?:test_0006_invalid_principal_and_krb5_validate_true
?:test_0007_principal_at_?:test_?:test_and_krb5_validate_true
?:test_0008_null_principal_and_krb5_validate_true

# test_krb_fips.py
?:test_krb_ptr_hash_crash_1792331
?:test_fips_login
?:test_kcm_not_store_tgt
?:test_child_logs_after_receiving_hup
?:test_sssd_not_check_gss_spengo
?:test_fips_as_req
?:test_fips_as_rep
?:test_login_fips_weak_crypto
?:test_ldap_gssapi
?:test_tgs_nonfips

# test_krb_ldap_connection.py
?:test_0001_timeoutdefault
?:test_0002_timeout100
?:test_0003_timeouttimeoutoutofrange
?:test_0004_timeoutminus100
?:test_0005_timeout0

# test_krb_ldap_connection_gssapi.py
?:test_timeoutkrb
"""