Examples of using Multihost Plugin with Fixture for SSSD
========================================================
* pytest multihost plugin uses OpenSSHTransport to connect to hosts and provides methods to
  run commands and copy files.

Namespace hook
--------------
* With pytest multihost plugin we define the hosts under which the actual commands will be
  running in a YAML/JSON file. This file is then read by multihost plugin. Each of the
  host specified in the YAML file have a role, username/password, IP address.

* pytest multihost provides modules and functions which takes the description of hosts in the
  YAML file, connect to the hosts and provides some common functions to run commands, copy/get
  files etc. The main modules provided by multihost plugin are config, domain, host. To use
  these modules we have to subclass them and change their behaviour to suite our needs.

* For SSSD QE we created subclasses of the config, domain and host functions to suite our needs and
  expanded them. This is available through
  `qe_class.py <https://github.com/SSSD/sssd/blob/master/src/tests/multihost/sssd/testlib/common/qe_class.py>`_.
  You may need to add *<your repo>/src/tests/multihost* to your `PYTHONPATH` environment variable.

* qe_class.py also provides a global fixture called session_multihost which provides a session
  scope fixture. This fixture can read the YAML file and provide a global multihost fixture
  to all the tests. This fixture assumes that the YAML file has hosts defined with any of these roles:

  - master
  - client
  - ad
  - atomic
  - others

*  Hosts in the above roles are read and a list is created for hosts in each role and provided using the generator (yield) feature of python. All this is exported in the pytest namespace and can be accessed in the individual tests using namespace hook

* Below are the examples of using namespace hook:

  - Single host:

      * create a multihost config file mhc.yaml as below::

            root_password: 'redhat'
            domains:
               - name: example.test
                 type: sssd
                 hosts:
                   - name: client1
                     external_hostname: client1.example.test
                     ip: 10.65.223.16
                     role: client

      * since we have 1 host with role client we can create a namespace hook in conftest.py
        to access the host as a list

      * create a conftest.py as below::

            def pytest_namespace():
                return { 'num_masters': 0, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':1,  'num_others': 0}

      * in the actual testcase it can be accessed as below::

            from sssd.testlib.common.qe_class import session_multihost
            class TestCase:
                def test1(self, session_multihost):
                    session_multihost.client[0].<method>

      * client[0] is the handle for the client1 system defined in the mhc.yaml

  - Multiple hosts of same role:

      *  create a multihost config file as below::

            root_password: 'redhat'
            domains:
                - name: example.test
                  type: sssd
                  hosts:
                    - name: client1
                      external_hostname: client1.example.test
                      ip: 10.65.223.16
                      role: client
                    - name: client2
                      external_hostname: client2.example.test
                      ip: 10.65.223.17
                      role: client

      * since we have 2 hosts with role client we can create a namespace hook in conftest.py
        to access the hosts as a list

      * create a conftest.py as below::

            def pytest_namespace():
                return { 'num_masters': 0, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':2,  'num_others': 0}

      * in the actual testcase it can be accessed as below::

            from sssd.testlib.common.qe_class import session_multihost
            class TestCase:
                def test1(self, session_multihost):
                    session_multihost.client[0].<method>
                    session_multihost.client[1].<method>

      * client[0] is the handle for the client1 system defined in mhc.yaml
      * client[1] is the handle for the client2 system defined in mhc.yaml

  - Multiple hosts of different roles:

      * create a multihost config file where we have 2 clients and 1 server::

            root_password: 'redhat'
            domains:
                - name: example.test
                  type: sssd
                  hosts:
                    - name: client1
                      external_hostname: client1.example.test
                      ip: 10.65.223.16
                      role: client
                    - name: client2
                      external_hostname: client2.example.test
                      ip: 10.65.223.17
                      role: client
                    - name: server1
                      external_hostname: master1.example.test
                      ip: 10.65.223.18
                      role: master

      * since we have 2 hosts with role client and 1 host with role master we can create a namespace hook in conftest.py to access the hosts as a list

      * create a conftest.py as below::

            def pytest_namespace():
                return { 'num_masters': 1, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':2,  'num_others': 0}

      * in the actual testcase it can be accessed as below::

            from sssd.testlib.common.qe_class import session_multihost
            class TestCase:
                def test1(session_multihost):
                    session_multihost.client[0].<method>
                    session_multihost.client[1].<method>
                def test2(session_multihost):
                    session_multihost.master[0].<method>

Example-1: Single host tests
----------------------------
* create a multihost config file mhc.yaml with 1 host as below::

    root_password: 'redhat'
    domains:
      - name: example.test
        type: sssd
        hosts:
          - name: client1
            external_hostname: client1.example.test
            ip: 10.65.223.16
            role: client

* create a file called conftest.py with below contents::

            def pytest_namespace():
                return { 'num_masters': 0, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':1, 'num_others':0 }

* create file called test1.py which contains testcases::

            from sssd.testlib.common.qe_class import session_multihost
            class TestCase:
                def test1(self, session_multihost):
                    session_multihost.client[0].run_command(['ls', '-l'])

* running the test::

            $ py.test --multihost-config=mhc.yaml test1.py -s -v

Example-2: Multiple hosts tests
-------------------------------
* create a multihost config file mhc.yaml with 2 hosts with roles master and client::

    root_password: 'redhat'
    domains:
      - name: example.test
        type: sssd
        hosts:
          - name: client1
            external_hostname: client1.example.test
            ip: 10.65.223.16
            role: client
          - name: master1
            external_hostname: master1.example.test
            ip: 10.65.223.35
            role: master

* create a file called conftest.py with below contents::

            def pytest_namespace():
                return { 'num_masters': 1, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':1, 'num_others':0 }

* create file called test1.py which contains testcases::

            from sssd.testlib.common.qe_class import session_multihost
            class TestCase:
                def test1(self, session_multihost):
                    session_multihost.client[0].run_command(['ls', '-l'])

                def test2(self, session_multihost):
                    session_multihost.master[0].run_command(['ls', '-l'])

* running the test::

            $ py.test --multihost-config=mhc.yaml test1.py -s -v

Example-3: Multiple hosts test with setup and teardown
------------------------------------------------------
* create a multihost config file mhc.yaml with 2 hosts with roles master and client::

    root_password: 'redhat'
    domains:
      - name: example.test
        type: sssd
        hosts:
          - name: client1
            external_hostname: client1.example.test
            ip: 10.65.223.16
            role: client
          - name: master1
            external_hostname: master1.example.test
            ip: 10.65.223.35
            role: master

* create a file called conftest.py with below contents::

            from sssd.testlib.common.qe_class import session_multihost
            def pytest_namespace():
                return { 'num_masters': 1, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':1, 'num_others':0 }

            @pytest.fixture(scope="class")
            def multihost(session_multihost, request):
                if hasattr(request.cls(), 'class_setup'):
                   request.cls().class_setup(session_multihost)
                   request.addfinalizer(lambda: request.cls().class_teardown(session_multihost))
                return session_multihost

* create file called test1.py which contains testcases::

            class TestCase:
                def class_setup(self, session_multihost):
                    cmd = session_multihost.client[0].run_command(['useradd', 'foobar'])
                    assert cmd.returncode == 0

                def test1(self, session_multihost):
                    session_multihost.client[0].run_command(['id', 'foobar'])

                def class_teardown(self, session_multihost):
                    session_multihost.master[0].run_command(['userdel', 'foobar'])

* running the test::

            $ py.test --multihost-config=mhc.yaml test1.py -s -v

Example-4: Copying files to hosts using multihost plugin
--------------------------------------------------------
* scenario: Create an sssd.conf file with specific configuration parameters. We create a local file on the
  system from which we are running py.test command (jslave/laptop/testsystem) and copy it
  to the actual hosts using transport.put_file method

* create test1.py with below contents::

            import ConfigParser

            class TestCase:
                def class_setup(self, session_multihost):
                    sssdconfig = ConfigParser.RawConfigParser()
                    sssdconfig.optionxform = str
                    sssdconfig.add_section('sssd')
                    sssdconfig.set("sssd", "config_file_version", '2')
                    sssdconfig.set("sssd", "domains", 'example.com')
                    sssdconfig.set("sssd", "services", "nss, pam")
                    domain_section = '%s/%s' % ('domain', 'example.com')
                    sssdconfig.add_section(domain_section)
                    sssdconfig.set(domain_section, "id_provider", "ad")
                    sssdconfig.set(domain_section, "auth_provider", "ad")
                    sssdconfig.set(domain_section, "access_provider", "ad")
                    sssdconfig.set(domain_section, "fallback_homedir", "/home/%d/%u")
                    sssdconfig.set(domain_section, "use_fully_qualified_names", "True")
                    sssdconfig.set(domain_section, "ad_maximum_machine_account_password_age", "1")
                    sssdconfig.set(domain_section, "ad_machine_account_password_renewal_opts", "300:15")
                    sssdconfig.set(domain_section, "debug_level", "9")
                    sssdconfig.set(domain_section, "enumerate", "True")
                    temp_file = '/tmp/sssd.conf'
                    with open(temp_file, 'wb') as fd:
                        sssdconfig.write(fd)
                    session_multihost.client[0].transport.put_file(temp_file, '/etc/sssd/sssd.conf')
                    session_multihost.client[0].run_command(['chmod', '600', '/etc/sssd/sssd.conf'],
                                                            set_env=False, raiseonerr=False)

Example-5: Creating a fixture and calling a fixture
---------------------------------------------------
* scenario: We want to configure sssd.conf before our test runs. we can create a
  function which configures sssd.conf and we call this function before our test runs

* create a file called conftest.py with below contents::

            from sssd.testlib.common.qe_class import session_multihost
            import ConfigParser
            def pytest_namespace():
                return { 'num_masters': 1, 'num_ad':0, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':1, 'num_others':0 }

            @pytest.fixture(scope="class")
            def multihost(session_multihost, request):
                if hasattr(request.cls(), 'class_setup'):
                   request.cls().class_setup(session_multihost)
                   request.addfinalizer(lambda: request.cls().class_teardown(session_multihost))
                return session_multihost

            @pytest.fixture(scope="class")
            def config_sssd(session_multihost, request):
                sssdconfig = ConfigParser.RawConfigParser()
                sssdconfig.optionxform = str
                sssdconfig.add_section('sssd')
                sssdconfig.set("sssd", "config_file_version", '2')
                sssdconfig.set("sssd", "domains", 'example.com')
                sssdconfig.set("sssd", "services", "nss, pam")
                domain_section = '%s/%s' % ('domain', 'example.com')
                sssdconfig.add_section(domain_section)
                sssdconfig.set(domain_section, "id_provider", "ad")
                sssdconfig.set(domain_section, "auth_provider", "ad")
                sssdconfig.set(domain_section, "fallback_homedir", "/home/%d/%u")
                sssdconfig.set(domain_section, "use_fully_qualified_names", "True")
                sssdconfig.set(domain_section, "debug_level", "9")
                sssdconfig.set(domain_section, "enumerate", "True")
                temp_file = '/tmp/sssd.conf'
                with open(temp_file, 'wb') as fd:
                    sssdconfig.write(fd)
                session_multihost.client[0].transport.put_file(temp_file, '/etc/sssd/sssd.conf')

* create a file test1.py with below contents::

           class Testcase:
                def class_setup(self, multihost, config_sssd):
                    cmd = session_multihost.client[0].run_command(['service', 'sssd', 'restart'])
                    assert cmd.returncode == 0

                def test1(self, multihost):
                    print("I am in test1")

                def class_teardown(self, multihost):
                    cmd = session_multihost.client[0].run_command(['service', 'sssd', 'stop'])
                    assert cmd.returncode == 0

Example-6: Connecting to Windows system and running AD specific commands
------------------------------------------------------------------------
* scenario: If the test requirement requires running any specific native commands on
  windows which cannot be fulfilled by adcli.

  Note: Connecting to Windows using multihost plugin requires ssh be running on Windows system.
  For this multihost plugin has been tested only with OpenSSH provided using CYGWIN. So before
  using multihost plugin please install CYGWIN and OpenSSH package. Configure OpenSSH on Windows
  and make sure its firewall is allowing ssh port.

* create a multihost config file mhc.yaml with 2 hosts with roles master and client::

    root_password: 'redhat'
    domains:
      - name: example.test
        type: sssd
        hosts:
          - name: client1
            external_hostname: client1.example.test
            ip: 10.65.223.16
            role: client
          - name: srv1
            external_hostname: srv1.example.test
            ip: 10.65.223.35
            role: ad
            username: Administrator
            password: Secret123

* create a file called conftest.py with below contents::

            def pytest_namespace():
                return { 'num_masters': 0, 'num_ad':1, 'num_atomic': 0, 'num_replicas': 0, 'num_clients':1, 'num_others':0 }

* create file called test1.py which contains testcases::

            from sssd.testlib.common.qe_class import session_multihost
            class TestCase:
                def test1(self, session_multihost):
                    session_multihost.client[0].run_command(['ls', '-l'])

                def test2(self, session_multihost):
                    session_multihost.ad[0].run_command(['date'])

* Running the test::

            $ py.test --multihost-config=mhc.yaml test1.py -s -v
