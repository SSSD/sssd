"""
SSSD Performance Tests.

Tests pertaining SSSD performance

:requirement: Performance
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

# cache_performance
?:User login time statistics for member of 200 groups
?:User login time statistics for member of 500 groups
?:User login time statistics for member of 1000 groups
?:User login time statistics for member of 1500 groups
?:User login time statistics for member of 2000 groups
?:User login time statistics for member of 3000 groups
?:ID cmd time statistics for member of 200 groups
?:ID cmd time statistics for member of 500 groups
?:ID cmd time statistics for member of 1000 groups
?:ID cmd time statistics for member of 1500 groups
?:ID cmd time statistics for member of 2000 groups
?:ID cmd time statistics for member of 3000 groups
?:Group lookup stats with 200 users in a group
?:Group lookup stats with 500 users in a group
?:Group lookup stats with 1000 users in a group
?:Group lookup stats with 1500 users in a group
?:Group lookup stats with 2000 users in a group
?:Group lookup stats with 3000 users in a group
?:Time statistics for listing files owned by 200 users
?:Time statistics for listing files owned by 500 users
?:Time statistics for listing files owned by 1000 users
?:Time statistics for listing files owned by 1500 users
?:Time statistics for listing files owned by 2000 users
?:Time statistics for listing files owned by 3000 users
?:Verify user login time when 100 users attempt simultaneous login
?:Verify user login time when 200 users attempt simultaneous login
?:Verify user login time when 500 users attempt simultaneous login
?:Verify user login time when 1000 users attempt simultaneous login
?:Verify the existence Of Timestamp Cache
?:Verify ldb cache updates on user lookup
?:Expire user entries in cache and verify the updates
?:Refresh user entries after expiry and verify the cache updates
?:Expire entries in cache and run user auth
?:Set refresh expired interval to 40 and verify user record updates
?:Set use fully qualified names to true and verify cache updates
?:Set case sensitive to false and verify cache updates
?:Verify ldb cache updates on group lookup
?:Expire group record in cache and verify the updates
?:Refresh group record after expiry and verify the cache updates
?:Set refresh expired interval to 40 and verify Group record updates
?:Modify user attribute and verify cache updates
?:Delete an existing user and verify cache updates
"""