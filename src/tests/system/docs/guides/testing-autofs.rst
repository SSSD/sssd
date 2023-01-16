Testing autofs / automount
##########################

Class :class:`lib.sssd.utils.automount.AutomountUtils` provides API that can be
used to test autofs / automount functionality. It can test that the mount point
works correctly and also that all defined maps where correctly read.

You can use ``nfs`` role (:class:`lib.sssd.roles.nfs.NFS`) in order to test
automount correctly. This role allows you to export directories over NFS.
Additionally, all provider roles provides generic API to the automount through
their ``automount`` field:

* :attr:`lib.sssd.roles.ldap.LDAP.automount`
* :attr:`lib.sssd.roles.ipa.IPA.automount`
* :attr:`lib.sssd.roles.samba.Samba.automount`
* :attr:`lib.sssd.roles.ad.AD.automount`

.. note::

    To access the nfs role, you need to add additional hostname to the
    ``mhc.yaml`` multihost configuration. For example:

    .. code-block:: yaml

          - hostname: nfs.test
            role: nfs
            config:
              exports_dir: /dev/shm/exports

    ``exports_dir`` is the location where all directories exported through
    :meth:`lib.sssd.roles.nfs.NFS.export` will be created.

.. code-block:: python
    :caption: automount test example

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_automount(client: Client, provider: GenericProvider, nfs: NFS):
        nfs_export1 = nfs.export('export1').add()
        nfs_export2 = nfs.export('export2').add()
        nfs_export3 = nfs.export('sub/export3').add()

        # Create automount maps
        auto_master = provider.automount.map('auto.master').add()
        auto_home = provider.automount.map('auto.home').add()
        auto_sub = provider.automount.map('auto.sub').add()

        # Create mount points
        auto_master.key('/ehome').add(info=auto_home)
        auto_master.key('/esub/sub1/sub2').add(info=auto_sub)

        # Create mount keys
        key1 = auto_home.key('export1').add(info=nfs_export1)
        key2 = auto_home.key('export2').add(info=nfs_export2)
        key3 = auto_sub.key('export3').add(info=nfs_export3)

        # Start SSSD
        client.sssd.common.autofs()
        client.sssd.start()

        # Reload automounter in order fetch updated maps
        client.automount.reload()

        # Check that we can mount all directories on correct locations
        assert client.automount.mount('/ehome/export1', nfs_export1)
        assert client.automount.mount('/ehome/export2', nfs_export2)
        assert client.automount.mount('/esub/sub1/sub2/export3', nfs_export3)

        # Check that the maps are correctly fetched
        assert client.automount.dumpmaps() == {
            '/ehome': {
                'map': 'auto.home',
                'keys': [str(key1), str(key2)]
            },
            '/esub/sub1/sub2': {
                'map': 'auto.sub',
                'keys': [str(key3)]
            },
        }

.. code-block:: python
    :caption: Testing IPA autofs locations

    @pytest.mark.topology(KnownTopology.IPA)
    def test_ipa_autofs_location(client: Client, ipa: IPA, nfs: NFS):
        nfs_export1 = nfs.export('export1').add()
        nfs_export2 = nfs.export('export2').add()

        # Create new automount location
        boston = ipa.automount.location('boston').add()

        # Create automount maps
        auto_master = boston.map('auto.master').add()
        auto_home = boston.map('auto.home').add()

        # Create mount points
        auto_master.key('/ehome').add(info=auto_home)

        # Create mount keys
        key1 = auto_home.key('export1').add(info=nfs_export1)
        key2 = auto_home.key('export2').add(info=nfs_export2)

        # Start SSSD
        client.sssd.common.autofs()
        client.sssd.domain['ipa_automount_location'] = 'boston'
        client.sssd.start()

        # Reload automounter in order fetch updated maps
        client.automount.reload()

        # Check that we can mount all directories on correct locations
        assert client.automount.mount('/ehome/export1', nfs_export1)
        assert client.automount.mount('/ehome/export2', nfs_export2)

        # Check that the maps are correctly fetched
        assert client.automount.dumpmaps() == {
            '/ehome': {
                'map': 'auto.home',
                'keys': [str(key1), str(key2)]
            },
        }
