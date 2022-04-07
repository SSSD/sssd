Layout
======
* This doc provides layout of sssd pytest framework and test suites directory.


module
-------

* sssd.testlib
        * This is the main top directory under which there are subdirectories
          containing various shared functions required to write tests using
          pytest.

* sssd.testlib/common
        * This directory contains modules related to configuring different
          services like 389-ds, kerberos, samba, Joining to AD, SSH Login,
          creating posix uses on 389-ds, Creating kerberos users in kerberos
          database.

* sssd.testlib/common/ipa
        * This directory contains shared functions related to ipa like setting
          up chrony, adding hbac rules, mapping external groups to posix
          groups.


Test Directories
----------------

* sssd/src/tests/multihost
        * This is the parent directory containing all the pytest test suites.

* sssd/src/tests/multihost/ad
        * This is the directory containing the test suites related to AD like
          automount, cifs, sudo, id mapping etc which require single AD server.

* sssd/src/tests/multihost/admultidomain
        * This is the directory containing test suites for SSSD AD
          Provider Multi-domain and multi-forest tests.

* sssd/src/tests/multihost/adsites
        * This is the directory containing the test suites related to Adsites.

* sssd/src/tests/multihost/alltests
        * This directory contains all the non-ad related test suites primarily
          tests related to ldap provider and kerberos provider.

* sssd/src/tests/multihost/ipa
        * This directory contains all the tests related to IPA, mostly related
          assorted ipa bugs with sssd as component, adtrust, ad HBAC and
          subid ranges tests.

* sssd/src/tests/multihost/data
       * This directory does not contains any tests, but contains assorted
         scripts, schema files, powershell scripts which are copied to AD to
         run on Windows systems.

