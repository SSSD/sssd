AD Multidomain Provider Test Suite
======================

This directory contains automation for SSSD AD Provider
Multi-domain and multi-forest tests.

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

* joinad: Join the system to Windows AD using realm with membercli-software
  being adcli.

* joinad: Join the system to Windows AD using realm with membercli-software
  being adcli.
