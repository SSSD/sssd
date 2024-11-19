"""
SSSD Multiple Domain Tests.

Tests pertaining SSSD configuration with more than one domain.

:requirement: Multiple Domains
"""

"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

bash
====

# multiple_domains
?:Check config ldb filter users per domain for puser10 in proxy domain
?:Check config ldb filter users per domain for puser10 in ldap domain
?:getent for proxy does not return filterusers perdomain user proxy domain
?:getent for ldap does not return filterusers per domain user ldap domain
?:Mulitple Domain Configuration 1 Proxy LDAP and LOCAL
?:Users in Configured Ranges LDAP Proxy and LOCAL
?:Groups in Configuration Ranges LDAP Proxy and LOCAL
?:Attempt to Modify LDAP Domain User LDAP Proxy and LOCAL
?:Attempt to delete LDAP Domain User LDAP Proxy and LOCAL
?:Attempt to Modify LDAP Domain Group LDAP Proxy and LOCAL
?:Attempt to Delete LDAP Group LDAP Proxy and LOCAL
?:Attempt to Add LOCAL User to LDAP Domain Group LDAP Proxy and LOCAL
?:Multiple Domain Configuration 2 Native LDAP and LOCAL
?:Users in Configuration Ranges Native LDAP and LOCAL
?:Groups in Configured Ranges Native LDAP and LOCAL
?:Attempt to Modify LDAP Domain User Native LDAP and LOCAL
?:Attempt to Delete LDAP User Native LDAP and LOCAL
?:Attempt to Modify LDAP Domain Group Native LDAP and LOCAL
?:Attempt to Delete LDAP Domain Group Native LDAP and LOCAL
?:Attempt to Add LOCAL User to LDAP Domain Group Native LDAP and LOCAL
?:Multiple Domain Configuration 3 Two LOCAL Domains SSSD Should Fail to Start
?:Multiple Domain Configuration 4 Two Native LDAP Domains
?:Enumerate Users Two Native LDAP Domains
?:Enumerate Groups Two Native LDAP Domains
?:Multiple Domain Configuration 5 Two Native LDAP Domains Fully Qualified Names
?:Enumerate Users Two Native LDAP Domains Fully Qualified Names
?:Enumerate Groups Two Native LDAP Domains Fully Qualified Names
?:Invalid memberuid Two Native LDAP Domains Fully Qualified Names
?:User information not updated on login for secondary domains bz678593
"""