"""
SSSD Service/Daemon Tests

All SSSD tests related to the service, init, files and processes.

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
# authorized_services/*
?:Granting SSH service access to user1 bz675284
?:Denying SSH service access to user1
?:Granting user2 to ftp service
?:Granting user2 to ftp service with pam_initgroups_scheme = no_session
?:Granting user2 to ftp service with UserStopDelaySec=0
?:Adding ftp service to user1
?:Deny ftp service to user1
?:Granting access to all services
?:Denying access to all services
?:Granting su access to user1
?:Modifying user1 to deny su access
?:Adding filter to ldap access order and user1 fits in the filter
?:Adding filter to ldap access order and user1 does not fit in the filter
?:Testing with a invalid service name in ldap
?:Set two identical services for same user one allow and one deny
?:Allow all service except su


intg
====

multihost
=========
# test_service.py
?:test_0001_bz1432010:SSSD ships a drop-in configuration snippet in /etc/systemd/system
?:test_0002_1736796:"default_domain_suffix" should not cause files domain entries to be qualified, this can break sudo access
?:test_0003_bz1713368: Add sssd-dbus package as a dependency of sssd-tools
?:test_0004_membership_with_files_provider: SSSD must be able to resolve membership involving root with files provider
?:test_0005_sssd_stops_monitoring: When the passwd or group files are replaced, sssd stops monitoring the file for inotify events, and no updates are triggered
?:test_0006_bz1909755: Suppress log message "[sssd] [service_signal_done] (0x0010): Unable to signal service [2]: No such file or directory" during logrote  -> test_logging.py
?:test_0007_bz971435:Enhance sssd init script so that it would source a configuration
?:test_0008_bz1516266:detailed debug and system-log message if krb5_init_context failed -> test_logging.py
"""