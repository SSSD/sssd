Testing LDAP with Kerberos
##########################

SSSD's LDAP provider can be configured to use Kerberos as the authentication
provider. The framework provides tools to automatically configure the LDAP
domain with ``auth_provider = krb5``, using the Kerberos configuration from
given KDC role object. It also provides means to run Kerberos tools such as
``kinit``, ``klist`` and ``kdestroy``.

.. seealso::

    * :class:`lib.sssd.roles.kdc.KDC`
    * :class:`lib.sssd.utils.authentication.KerberosAuthenticationUtils`
    * :attr:`lib.sssd.utils.authentication.AuthenticationUtils.kerberos`

.. note::

    To access the KDC role, you need to add additional hostname to the
    ``mhc.yaml`` multihost configuration. For example:

    .. code-block:: yaml

        - hostname: kdc.test
          role: kdc
          config:
            realm: TEST
            domain: test
            client:
              krb5_server: kdc.test
              krb5_kpasswd: kdc.test
              krb5_realm: TEST


.. code-block:: python
    :caption: LDAP with Kerberos authentication example

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_kdc(client: Client, ldap: LDAP, kdc: KDC):
        ldap.user('tuser').add()
        kdc.principal('tuser').add()

        client.sssd.common.krb5_auth(kdc)
        client.sssd.start()

        with client.ssh('tuser', 'Secret123') as ssh:
            with client.auth.kerberos(ssh) as krb:
                result = krb.klist()
                assert f'krbtgt/{kdc.realm}@{kdc.realm}' in result.stdout
