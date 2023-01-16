Testing authentication and sudo
###############################

Class :class:`lib.sssd.utils.authentication.AuthenticationUtils` provides access
to su, ssh and sudo commands which can be used to test user authentication via
various channels. The class can be accessed from the ``client`` fixture as
``client.auth``.

.. code-block:: python
    :caption: Test authentication via su

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_su(client: Client, ldap: LDAP):
        ldap.user('test').add(password="Secret123")
        client.sssd.start()

        assert client.auth.su.password('test', 'Secret123')

.. code-block:: python
    :caption: Test authentication via ssh

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_ssh(client: Client, ldap: LDAP):
        ldap.user('test').add(password="Secret123")
        client.sssd.start()

        assert client.auth.ssh.password('test', 'Secret123')

.. note::

    Since su and ssh shares the same interface, it is also possible to write a
    parametrized test for both authentication methods.

    .. code-block:: python

        @pytest.mark.topology(KnownTopology.LDAP)
        @pytest.mark.parametrize('method', ['su', 'ssh'])
        def test_auth(client: Client, ldap: LDAP, method: str):
            ldap.user('test').add(password="Secret123")

            client.sssd.start()
            assert client.auth.parametrize(method).password('test', 'Secret123')

.. code-block:: python
    :caption: Test sudo -l

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_sudo_list(client: Client, ldap: LDAP):
        u = ldap.user('test').add(password="Secret123")
        ldap.sudorule('testrule').add(user=u, host='ALL', command='/bin/ls')

        client.sssd.common.sudo()
        client.sssd.start()

        # Test that user can run sudo
        assert client.auth.sudo.list(u.name, 'Secret123')

        # Test that user can run particular commands
        assert client.auth.sudo.list(u.name, 'Secret123', expected=['(root) /bin/ls'])

.. code-block:: python
    :caption: Test sudo run without password

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_sudo_list(client: Client, ldap: LDAP):
        u = ldap.user('test').add(password="Secret123")
        ldap.sudorule('testrule').add(user=u, host='ALL', command='/bin/ls', nopasswd=True)

        client.sssd.common.sudo()
        client.sssd.start()

        # Test that user can run /bin/ls without additional authentication
        assert client.auth.sudo.run('test', command='/bin/ls')
