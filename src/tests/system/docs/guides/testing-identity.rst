Testing identity
################

Class :class:`lib.sssd.utils.tools.LinuxToolsUtils` provides access to common
system tools, especially the ``id`` and ``getent`` commands which can be used to
assert identity information returned from SSSD. The class can be accessed from
the ``client`` fixture as ``client.tools``.

.. code-block:: python
    :caption: id command example

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_id(client: Client, ldap: LDAP):
        # Create user
        user = ldap.user('user-1').add(uid=10001, gid=10001, password='Secret123')

        # Create group
        group = ldap.group('group-1').add(gid=20001)
        group.add_member(user)

        # Start SSSD
        client.sssd.start()

        # Call `id user-1` and assert the result
        result = client.tools.id('user-1')
        assert result is not None
        assert result.user.name == 'user-1'
        assert result.user.id == 10001
        assert result.group.id == 10001  # primary group
        assert result.group.name is None
        assert result.memberof('group-1')

.. code-block:: python
    :caption: getent command example

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_getent(client: Client, ldap: LDAP):
        # Create user
        user = ldap.user('user-1').add(uid=10001, gid=10001, password='Secret123', shell='/bin/sh')

        # Create group
        group = ldap.group('group-1').add(gid=20001)
        group.add_member(user)

        # Start SSSD
        client.sssd.start()

        # Call `getent passwd user-1` and assert the result
        result = client.tools.getent.passwd('user-1')
        assert result is not None
        assert result.name == 'user-1'
        assert result.uid == 10001
        assert result.gid == 10001
        assert result.home == '/home/user-1'
        assert result.shell == '/bin/sh'
        assert result.gecos is None

        # Call `getent group group-1` and assert the result
        result = client.tools.getent.group('group-1')
        assert result is not None
        assert result.name == 'group-1'
        assert result.gid == 20001
        assert result.members == ['user-1']
