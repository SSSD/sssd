"""
SSSD Identity Mapping (idmap) Tests.

:requirement: idmapping
"""

"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

bash
===
# idmap/idmap.sh
?:ldap provider
?:#with ldap provider idmapping is disabled
?:ldap idmap range size option has value more than the maximum minus minimum
?:ldap idmap range min option is negative bz1077695
?:ldap idmap range max or ldap idmap range min is a very large
?:All values are negative
?:ldap idmap range min is zero
?:ldap idmap range max is less than ldap idmap range min
?:ldap idmap default domain sid option is set to junk value
?:ldap idmap default domain sid value does not match AD domain sid
?:ldap idmap default domain sid option matches the AD domain sid correctly
?:ldap idmap autorid compat is set to true and ldap idmap default domain sid is not mentioned
?:ldap idmap autorid compat is set True and ldap idmap default domain sid is not matching the AD domain SID
?:Silence DEBUG messages when dealing with built in SIDs bz874616
"""