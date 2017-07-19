# SSSD - System Security Services Daemon

## Introduction
SSSD provides a set of daemons to manage access to remote directories and
authentication mechanisms such as LDAP, Kerberos or FreeIPA. It provides
an NSS and PAM interface toward the system and a pluggable backend system
to connect to multiple different account sources.

More information about SSSD can be found on its project page -
https://pagure.io/SSSD/sssd/

## Downloading SSSD
SSSD is shipped as a binary package by most Linux distributions. If you
want to obtain the latest source files, please navigate to the
[Releases folder on pagure](https://releases.pagure.org/SSSD/sssd/)

## Releases
SSSD maintains two release streams - stable and LTM. Releases designated as
LTM are long-term maintenance releases and will see bugfixes and security
patches for a longer time than other releases.

The list of all releases is maintained together with [SSSD documentation](https://docs.pagure.org/SSSD.sssd/users/releases.html)

## Building and installation from source
Please see the file BUILD.txt for details

## Documentation
The most up-to-date documentation can be found at https://fedorahosted.org/sssd/wiki/Documentation

## Licensing
Please see the file called COPYING.

## Contacts
There are several ways to contact us:

* the sssd-devel mailing list: [Development of the System Security Services Daemon](
  https://lists.fedorahosted.org/archives/list/sssd-devel@lists.fedorahosted.org/)
* the sssd-users mailing list: [End-user discussions about the System Security Services Daemon](
  https://lists.fedorahosted.org/archives/list/sssd-users@lists.fedorahosted.org/)
* the #sssd and #freeipa IRC channels on freenode:
  * irc://irc.freenode.net/sssd
  * irc://irc.freenode.net/freeipa
