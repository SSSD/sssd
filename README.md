[![Coverity Scan](https://img.shields.io/coverity/scan/sssd-sssd?label=master%20::%20coverity)](https://scan.coverity.com/projects/sssd-sssd)

# SSSD - System Security Services Daemon

## Introduction
SSSD provides a set of daemons to manage access to remote directories and
authentication mechanisms such as LDAP, Kerberos or FreeIPA. It provides
an NSS and PAM interface toward the system and a pluggable backend system
to connect to multiple different account sources.

More information about SSSD can be found on its project page -
https://github.com/SSSD/sssd.

## Downloading SSSD
SSSD is shipped as a binary package by most Linux distributions. If you
want to obtain the latest source files, please navigate to the
[Releases folder on GitHub](https://github.com/SSSD/sssd/releases).

We sign release tarballs with our [gpg key (id C13CD07FFB2DB1408E457A3CD3D21B2910CF6759)](./contrib/pubkey.asc)
since April 2022. For convenience, the key is also uploaded to
`keys.openpgp.org` keyserver. You can import the key using:

```
$ curl -o sssd.asc https://raw.githubusercontent.com/SSSD/sssd/master/contrib/pubkey.asc
$ gpg2 --import sssd.asc
```

or

```
$ gpg2 --keyserver keys.openpgp.org --recv-keys C13CD07FFB2DB1408E457A3CD3D21B2910CF6759
```

And verify the signature with:

```
$ version=x.y.z
$ curl -o sssd-$version.tar.gz https://github.com/SSSD/sssd/releases/download/$version/sssd-$version.tar.gz
$ curl -o sssd-$version.tar.gz.asc https://github.com/SSSD/sssd/releases/download/$version/sssd-$version.tar.gz.asc
$ gpg2 --verify sssd-$version.tar.gz.asc sssd-$version.tar.gz
```

## Releases
SSSD maintains two release streams - stable and LTM. Releases designated as
LTM are long-term maintenance releases and will see bugfixes and security
patches for a longer time than other releases.

The list of all releases is maintained together with [SSSD documentation](https://sssd.io/releases.html).

## Building and installation from source
Please see the [our developer documentation](https://sssd.io/contrib/building-sssd.html).

## Documentation
The most up-to-date documentation can be found at https://sssd.io.

Its source code is hosted at https://github.com/SSSD/sssd.io.

## Submitting bugs
Please file an issue in the [SSSD github instance](https://github.com/SSSD/sssd/issues).
Make sure to follow the [guide on reporting SSSD bugs](https://sssd.io/docs/reporting-bugs.html).

## Licensing
Please see the file called [COPYING](COPYING).

## Contacts
There are several ways to contact us:

* the sssd-devel mailing list: [Development of the System Security Services Daemon](
  https://lists.fedorahosted.org/archives/list/sssd-devel@lists.fedorahosted.org/)
* the sssd-users mailing list: [End-user discussions about the System Security Services Daemon](
  https://lists.fedorahosted.org/archives/list/sssd-users@lists.fedorahosted.org/)
* the #sssd and #freeipa IRC channels on libera.chat:
  * irc://irc.libera.chat/sssd
  * irc://irc.libera.chat/freeipa
