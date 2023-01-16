Local users and groups
######################

Class :class:`lib.sssd.utils.local_users.LocalUsersUtils` provides API to
manage local users and groups. It shares the same generic API that is used
across provider roles such as LDAP or IPA, so it can be used in the same way. It
is available from the client role as
:attr:`lib.sssd.roles.client.Client.local`.

All users and groups that are created during the test are automatically deleted.

.. code-block:: python
    :caption: Examples

    @pytest.mark.topology(KnownTopology.Client)
    def test_local_users(client: Client):
        u = client.local.user('tuser').add()
        g = client.local.group('tgroup').add()
        g.add_member(u)

        result = client.tools.id('tuser')
        assert result is not None
        assert result.user.name == 'tuser'
        assert result.memberof('tgroup')
