Examples of using libkrb5 module from sssd.testlib.common
=========================================================
* sssd-testlib provides module libkrb5 which creates a Kerberos server instance


Design
------
* libkb5 module consists of class krb5Srv

* krb5srv class consists of methods to create a Kerberos server

* below are some of the examples of setting up a Kerberos server on RHEL7

Example-1: Setup a Kerberos instance on a single host
-----------------------------------------------------
* create a multihost config file mhc.yaml as below::

      root_password: 'redhat'
      domains:
      - name: example.test
        type: sssd
        hosts:
        - name: server1
          external_hostname: server1.example.test
          ip: 192.168.122.60
          role: master

* create a conftest.py to specify namespace hook::

     from sssd.testlib.common.qe_class import session_multihost
     from sssd.testlib.common.libkb5 import krb5srv
     import pytest

     def pytest_namespace():
         return {'num_masters': 1, 'num_ad':0, 'num_atomic': 0,
                  'num_replicas': 0, 'num_clients':1, 'num_others': 0}

* add a fixture specified below in conftest.py::

      import subprocess

      @pytest.fixture(scope="class")
      def setup_krb5(session_multihost):
           tools = sssdTools(session_multihost.master[0])
           tools.config_etckrb5('EXAMPLE.TEST')
           krb = krb5srv(session_multihost[0]. 'EXAMPLE.TEST')
           try:
              krb.krb_setup_new()
           except subprocess.CalledProcessError:
              print("fail to setup Kerberos")
              assert False

* session_multihost is the session fixture which gets activated when
  py.test is run with --multihost-config=mhc.yaml parameter. This
  parameter connects to systems mentioned in mhc.yaml using ssh
  and this session of each host is available through roles
  defined in multihost config file. In the above example client[0] is
  the multihost handle for host `server1.example.test`

* importing the krb5srv module we are creating instance of
  krb5srv by passing the multihost session handle of master[0] to
  the krb5srv object

* the fixture created by setup_krb5 is of scope class which can be called in a test file as below::

     class TestCase(object):

           def test1(self, session_multihost, setup_krb5):
               print("This is test1")

           def test2(self, session_multihost):
               pass

           def test3(self, session_multihost):
               pass
