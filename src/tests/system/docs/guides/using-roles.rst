Using multihost roles
#####################

Multihost role is the main object that gives you access to the remote host. Role
represents a service that runs on the host and the role object provides
interface to manipulate the service or the host -- for example creating a user
on the IPA server or changing configuration on the client.

.. note::

    Role objects are created at the start of each test and destroyed when the
    test is finished. **They create a backup of the current state of the remote
    host and restore modified state back to the original when the test ends.**

    **Therefore as long as you use only the role object, you can be assure that
    everything you change through the role's API is restored to its original
    state automatically.** For example if you add a new user, it is deleted. If
    you create a new file, it is deleted. If you modify existing file, its
    content is restored.

.. warning::

    All services supports full backup and restore except Active Directory where
    this functionality is limited. Active Directory does not provide reasonably
    fast backup mechanism therefore the framework only supports partial backup.
    It will work as expected as long as you only touch newly created objects and
    do not modify any existing object.

Available roles
***************

There are multiple roles available.

* ``ad`` -- Active Directory Domain Controller
* ``ipa`` -- IPA server
* ``ldap`` -- 389ds server
* ``samba`` -- Samba Domain Controller
* ``client`` -- SSSD client

Each role is accessible through pytest fixture.

Using provider roles
********************

Provider roles, that is those that represents identity management service (ad,
samba, ipa, ldap), provide interface to manipulate the service. For example
managing users and groups. These roles implements a generic interface
:class:`~lib.sssd.roles.generic.GenericProvider` and further extends this
interface with service specifics.
:class:`~lib.sssd.roles.generic.GenericProvider` can be used when writing
tests that can run against multiple providers (see
:ref:`topology-parametrization`).

.. note::

   Samba and AD roles also implements
   :class:`~lib.sssd.roles.generic.GenericADProvider` which extends
   :class:`~lib.sssd.roles.generic.GenericProvider` with Samba and Active
   Directory features. This can be used to write single test that can run on
   both Samba and Active Directory but can not run with other provider.

Example: Adding users and groups
================================

User management is done through a user object which can be returned directly
from the role. This object provides ``add``, ``modify``, ``delete`` and ``get``
methods that implements the :class:`~lib.sssd.roles.generic.GenericUser`
interface. Each identity management service can extend this interface with
service specific behavior (for example ldap allows to use the ``rfc2307bis``
schema and organize users into different containers). Group management works in
the same way but :class:`~lib.sssd.roles.generic.GenericGroup` is
implemented.

.. code-block:: python

    @pytest.mark.topology(KnownTopology.IPA)
    def test_ipa(ipa: IPA):
        # Create user
        user = ipa.user('user-1').add(password='Secret123')

        # Create group
        group = ipa.group('group-1').add()

        # Add user to the group
        group.add_member(user)

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_ldap(ldap: LDAP):
        # Create user
        user = ldap.user('user-1', basedn='cn=users').add(uid=10001, gid=10001, password='Secret123')

        # Create user primary group
        ldap.group('user-1', basedn='cn=groups', rfc2307bis=True).add(gid=10001)

        # Create group
        group = ldap.group('group-1', basedn='cn=groups', rfc2307bis=True).add(gid=20001)

        # Add user to the group
        group.add_member(user)

    @pytest.mark.topology(KnownTopology.AD)
    @pytest.mark.topology(KnownTopology.IPA)
    @pytest.mark.topology(KnownTopology.LDAP)
    @pytest.mark.topology(KnownTopology.Samba)
    def test_generic(provider: GenericProvider):
       # Create user
       user = provider.user('user-1').add()

       # Create group
       group = provider.group('group-1').add()

       # Add user to the group
       group.add_member(user)

.. seealso::

    See the following role objects:
    :class:`~lib.sssd.roles.ad.AD`,
    :class:`~lib.sssd.roles.ipa.IPA`,
    :class:`~lib.sssd.roles.ldap.LDAP`,
    :class:`~lib.sssd.roles.samba.Samba`

Using the client role
*********************

The client role is the heart of any multihost test as it allows you to manage
and test SSSD. You can see the whole API here:
:class:`~lib.sssd.roles.client.Client`.

.. note::

    Client role, as well as all other roles, contains multihost utility objects.
    These objects implements some share features like:

    * creating directories and files: :class:`pytest_mh.utils.fs.LinuxFileSystem`
    * starting and stopping systemd services: :class:`pytest_mh.utils.services.SystemdServices`
    * working with SSSD: :class:`lib.sssd.utils.sssd.SSSDUtils`
    * running standard tools such as ``id`` or ``getent``: :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. code-block:: python
        :caption: Example: Working with files and directories

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_files(client: Client):
            # Read file
            nsswitch = client.fs.read('/etc/nsswitch.conf')

            # Write file
            client.fs.write('/etc/krb5.conf', '''
                [logging]
                default = FILE:/var/log/krb5libs.log

                [libdefaults]
                ticket_lifetime = 24h
                renew_lifetime = 7d
                forwardable = true
                rdns = false
            ''')

            # Create directory
            client.fs.mkdir('/tmp/newdir', mode='0600')

    .. code-block:: python
        :caption: Example: Managing services

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_service(ldap: LDAP):
            # Stop directory server
            ldap.svc.stop('dirsrv.target')

Managing SSSD
=============

SSSD on the host is stopped and its cache and logs are cleared automatically
when we entry a test to ensure that each test starts with a fresh state. You can
access the :class:`~lib.sssd.utils.sssd.SSSDUtils` through ``client.sssd``
attribute.

:class:`~lib.sssd.utils.sssd.SSSDUtils` allows you to start, stop and
restart SSSD as well as change configuration.

Configuring SSSD
----------------

Configuration object can be accessed directly through ``client.sssd.config``.

.. code-block:: python

        @pytest.mark.topology(KnownTopology.Client)
        def test_client(client: Client):
            # client.sssd.config[section] = dict[option, value as string]
            client.sssd.config['nss'] = {
                'entry_cache_timeout': 'true',
                'override_homedir': '%U',
                ...
            }

            # client.sssd.config[section][option] = value as string
            client.sssd.config['domain/test']['use_fully_qualified_names'] = 'true'

You can also access each section directly by using a shortcut:

.. code-block:: python

        @pytest.mark.topology(KnownTopology.Client)
        def test_client(client: Client):
            # there is shortcut for each responder
            client.sssd.nss = {
                'entry_cache_timeout': 'true',
                'override_homedir': '%U',
                ...
            }

            # also for domain and subdomain
            client.sssd.dom('test')['use_fully_qualified_names'] = 'true'
            client.sssd.subdom('test', 'subdomname')['use_fully_qualified_names'] = 'false'

It is possible to further simplify access to a selected domain.

.. code-block:: python
    :emphasize-lines: 9

        @pytest.mark.topology(KnownTopology.Client)
        def test_client(client: Client):
            # select a default domain (this does not affect sssd.conf)
            client.sssd.default_domain = 'test'

            # these three are equivalent
            client.sssd.config['domain/test']['use_fully_qualified_names'] = 'true'
            client.sssd.dom('test')['use_fully_qualified_names'] = 'true'
            client.sssd.domain['use_fully_qualified_names'] = 'true'

.. _importing-domain:

Importing SSSD domain from provider role
----------------------------------------

Each multihost configuration may require slightly different SSSD config -- for
example it needs to specify correct domain, hostname and keytab location.
Therefore each host in multihost configuration may specify additional options
for SSSD:

.. code-block:: yaml
    :emphasize-lines: 14

    root_password: 'Secret123'
    domains:
    - name: test
      type: sssd
      hosts:
      - hostname: client.test
        role: client

      - hostname: master.ldap.test
        role: ldap
        config:
          binddn: cn=Directory Manager
          bindpw: Secret123
          client:
            ldap_tls_reqcert: demand
            ldap_tls_cacert: /data/certs/ca.crt
            dns_discovery_domain: ldap.test

Each host also has default values for server uri, id provider and other options.
These value can be imported using
:meth:`~lib.sssd.utils.sssd.SSSDUtils.import_domain`. The first imported
domain is set as the default domain and its configuration can be accessed by
``client.sssd.domain``.

.. code-block:: python
    :emphasize-lines: 3

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_client(client: Client, ldap: LDAP):
            client.sssd.import_domain('test', ldap)
            client.sssd.domain['use_fully_qualified_names'] = 'true'

            conf = client.sssd.config_dumps()
            print(conf)

        # Outputs:
        #
        # [sssd]
        # config_file_version = 2
        # services = nss, pam
        # domains = test
        #
        # [domain/test]
        # ldap_tls_reqcert = demand
        # ldap_tls_cacert = /data/certs/ca.crt
        # dns_discovery_domain = ldap.test
        # id_provider = ldap
        # ldap_uri = ldap://master.ldap.test
        # use_fully_qualified_names = true

Each topology from :class:`lib.sssd.topology.KnownTopology` already contains a
default SSSD domain named ``test``, therefore you do not need to import the
domain manually.

.. code-block:: python
    :emphasize-lines: 3

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_client(client: Client, ldap: LDAP):
            # the domain is already imported
            # client.sssd.import_domain('test', ldap)
            client.sssd.domain['use_fully_qualified_names'] = 'true'

            conf = client.sssd.config_dumps()
            print(conf)

        # Outputs:
        #
        # [sssd]
        # config_file_version = 2
        # services = nss, pam
        # domains = test
        #
        # [domain/test]
        # ldap_tls_reqcert = demand
        # ldap_tls_cacert = /data/certs/ca.crt
        # dns_discovery_domain = ldap.test
        # id_provider = ldap
        # ldap_uri = ldap://master.ldap.test
        # use_fully_qualified_names = true

Starting SSSD
-------------

You can start, stop and restart SSSD. If the operation fails, the reason is
visible in the multihost logs. By default, current SSSD configuration is
automatically written to the host and checked with ``sssctl config-check`` when
calling :meth:`~lib.sssd.utils.sssd.SSSDUtils.start` and
:meth:`~lib.sssd.utils.sssd.SSSDUtils.restart`.

.. code-block:: python

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_client(client: Client, ldap: LDAP):
            client.sssd.domain['use_fully_qualified_names'] = 'true'

            # write sssd.conf, check for typos and start sssd
            client.sssd.start()

            client.sssd.domain['use_fully_qualified_names'] = 'false'

            # avoid changing sssd.conf and config check and restart sssd
            client.sssd.restart(apply_config=False, check_config=False)

            # stop sssd and clear cache and start (config is applied)
            client.sssd.stop()
            client.sssd.clear()
            client.sssd.start()

Asserting properties
====================

:class:`~lib.sssd.utils.tools.LinuxToolsUtils` can be accessed through
``client.tools``. This gives you access to standard Linux commands such as
``id`` and ``getent``. Output of these commands is fully parsed to allow simple
assertions.

.. code-block:: python

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_ldap_id(client: Client, ldap: LDAP):
        # Create organizational units
        ou_users = ldap.ou('users').add()
        ou_groups = ldap.ou('groups').add()

        # Create user
        user = ldap.user('user-1', basedn=ou_users).add(uid=10001, gid=10001, password='Secret123')

        # Create group
        group = ldap.group('group-1', basedn=ou_groups, rfc2307bis=True).add(gid=20001)
        group.add_member(user)

        # Set schema and start SSSD
        client.sssd.domain['ldap_schema'] = 'rfc2307bis'
        client.sssd.start()

        # Assert the user
        result = client.tools.id('user-1')
        assert result is not None
        assert result.user.name == 'user-1'
        assert result.user.id == 10001
        assert result.group.id == 10001
        assert result.group.name is None  # The primary group does not exist
        assert result.memberof('group-1')

        client.sssd.domain['use_fully_qualified_names'] = 'true'
        client.sssd.restart()

        # User can not be accessed by shortname
        result = client.tools.id('user-1')
        assert result is None

        # Find the user with fully qualified name
        result = client.tools.id('user-1@test')
        assert result is not None
        assert result.user.name == 'user-1@test'
        assert result.user.id == 10001
        assert result.group.id == 10001
        assert result.group.name is None   # The primary group does not exist
        assert result.memberof('group-1@test')


Topology parametrization
************************

All tools that are described in this document allows us to write tests for any
topology and we can even write tests that can be run on multiple topologies
without changing the code.


.. code-block:: python

    @pytest.mark.topology(KnownTopology.AD)
    @pytest.mark.topology(KnownTopology.IPA)
    @pytest.mark.topology(KnownTopology.LDAP)
    @pytest.mark.topology(KnownTopology.Samba)
    def test_generic_id(client: Client, provider: GenericProvider):
        # Create user
        user = provider.user('user-1').add(uid=10001, gid=10001)

        # Create group
        group = provider.group('group-1').add(gid=20001)
        group.add_member(user)

        client.sssd.start()

        result = client.tools.id('user-1')
        assert result is not None
        assert result.user.name == 'user-1'
        assert result.user.id == 10001
        assert result.group.id == 10001
        assert result.memberof('group-1')

        client.sssd.domain['use_fully_qualified_names'] = 'true'
        client.sssd.restart()

        result = client.tools.id('user-1')
        assert result is None

        result = client.tools.id('user-1@test')
        assert result is not None
        assert result.user.name == 'user-1@test'
        assert result.user.id == 10001
        assert result.group.id == 10001
        assert result.memberof('group-1@test')

Low level access to remote host
*******************************

If you are missing some functionality, you probably want to extend any existing
role or utility class and implement support for your requirements. However, if
needed, you can also run commands on the host directly:

.. code-block:: python

        @pytest.mark.topology(KnownTopology.AD)
        def test_client(client: Client, ad: AD):
            # Commands are executed in bash on Linux systems
            client.host.ssh.run('echo "test"')

            # And in Powershell on Windows
            ad.host.ssh.run('Write-Output "test"')

.. seealso::

    You can read the API reference for:

    * roles: :mod:`lib.sssd.roles`
    * utils: :mod:`lib.sssd.utils`
    * hosts: :mod:`lib.sssd.hosts`
