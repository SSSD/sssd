AD Provider Test Suite
======================

This directory contains test automation for SSSD AD Provider.


Fixtures
========


session
*******

* setup_session: This fixtures does the following tasks:


  * Install common required packages like
  * Updated /etc/resolv.conf with Windows IP Address
  * Clear sssd cache
  * Configure system to use sssd authentication


* teardown_session: This is not a fixtures but a teardown of ``setup_session``

  * Restores resolv.conf
  * Stop sssd service
  * remove sssd.conf


class
*****

* multihost: This fixture returns multihost object. Also using builtin request
  fixture we pass ``class_setup`` and ``class_teardown``.  If the test suite defines
  class_setup and class_teardown functions, multihost object will be available
  to execute any remote functions.

* clear_sssd_cache: Stops sssd service. Removes cache files from
  ``/var/lib/sss/db`` and starts sssd service. Sleeps for 10 seconds.

* enable_autofs_schema: Backup sssd.conf and Edit sssd.conf and specify
  ``autofs_provider = ad`` and ``debug_level = 9``

* enable_ad_sudoschema: Enable AD Sudo Schema

* create_ad_sudousers: Create users in Windows Active Directory with username
  from ``sudo_idmuser1`` to ``sudo_idmuser10``.

* sudorules: Create AD sudo rules ``less_user_rule1`` to ``less_user_rule10``::


   # less_user_rule1, Sudoers, juno.test
   dn: CN=less_user_rule1,OU=Sudoers,DC=juno,DC=test
   objectClass: top
   objectClass: sudoRole
   cn: less_user_rule1
   distinguishedName: CN=less_user_rule1,OU=Sudoers,DC=juno,DC=test
   instanceType: 4
   whenCreated: 20190416073735.0Z
   whenChanged: 20190416073736.0Z
   uSNCreated: 1283544
   uSNChanged: 1283547
   name: less_user_rule1
   objectGUID:: wYiyH7dlT0G/5y40LPgHpw==
   objectCategory: CN=sudoRole,CN=Schema,CN=Configuration,DC=juno,DC=test
   dSCorePropagationData: 16010101000000.0Z
   sudoHost: ALL
   sudoUser: sudo_idmuserN
   sudoUser: sudo_idmuserN@JUNO.TEST
   sudoOption: !authenticate
   sudoOption: !requiretty
   sudoCommand: /usr/bin/less

* joinad: Join the system to Windows AD using realm with membercli-software
  being adcli.



function
********

* smbconfig: Configure smb.conf ::

    [global]
    workgroup = <DOMAIN>
    security = ads
    realm = <DOMAIN.COM>
    netbios name = <samba-client-shortname>
    kerberos method = secrets and keytab
    client signing = yes
    client use spnego = yes
    log file = /var/log/samba/log.%m
    max log size = 50
    log level = 9


* create_adgrp: fixture to create AD Groups . Runs ``adgroup.ps1`` powershell
  script. powershell script::

    #Following Powershell script will add the group in AD server
    #and set GroupScope as Global and GroupCtegory as Security and
    #also set MemberOf BuiltIn group as Administrator

    Import-Module ActiveDirectory

    $grname = -join ((65..90) + (97..122) | Get-Random -Count 7 | % {[char]$_})

    Write-Host $grname

    New-ADGroup -Name $grname -GroupScope Global -GroupCategory Security

    Add-ADPrincipalGroupMembership -MemberOf Administrators -Identity $grname



* create_aduser_group: Creates AD user ``testuser<randomnumber>`` and AD Groups
  ``testgroup<randomnumber>``

* add_nisobject:

  * uses Indirect parameterization and takes map name as the parameter from
    test case. (example: ``/export``, ``/project1``)
  * Installs nfs-utils package on nfs server and starts  nfs-server.
  * Add map based on request parameter.


* set_autofs_search_base: Enable autofs search base in sssd.conf

* add_user_in_domain_local_group: Add domain local AD group
  ``ltestgoup<randomnumber>``

* add_principals: Add ``HTTP`` and ``NFS`` service principals in Windows AD
