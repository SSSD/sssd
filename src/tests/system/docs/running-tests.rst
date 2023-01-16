Running tests
#############

Installing requirements
***********************

The tests are written in Python using the `pytest`_ framework and additional
Python packages. The list of all required packages is stored in
`requirements.txt`_. It is recommended to install the requirements inside Python
virtual environment.

.. code-block:: text

    # Install python-ldap dependencies
    sudo dnf install -y gcc python3-devel openldap-devel

    # Install test dependencies
    python3 -m venv .venv
    source .venv/bin/activate
    pip3 install -r ./requirements.txt

Important pytest plugins
========================

The tests requires several pytest plugins that are very important and worth
mentioning here.

* `pytest-mh`_: Adds support for multihost testing. This is the core plugin that
  is fundamental for writing and running the tests.
* `pytest-ticket`_: Adds ``@pytest.mark.ticket(...)`` and ``--ticket`` command
  line option. It is used to run only tests related to particular tickets.
* `pytest-tier`_: Adds ``@pytest.mark.tier(...)`` and ``--tier`` command line
  option. It is used to run only tests from given tier.

Setting up multihost environment
********************************

Even though our tests are run locally with ``pytest``, they actually run
commands on remote machines to make the setup more flexible and avoid changing
anything on your host. The SSSD upstream tests use `sssd-ci-containers`_ project
that provides set of needed containers (client, LDAP, IPA, Samba, NFS, KDC, ...)
and Active Directory vagrant box and this documentation uses this project in all
listed examples.

.. _sssd-ci-containers: https://github.com/SSSD/sssd-ci-containers

.. note::

  You can also provide set of your own hosts. However, you will need to modify
  the `multihost configuration`_.

Starting up the containers
==========================

#. Clone the `sssd-ci-containers`_ repository
#. Switch to the directory
#. Start the containers
#. Start the Active Directory vagrant box

.. code-block:: text

    git clone https://github.com/SSSD/sssd-ci-containers.git
    cd sssd-ci-containers

Start the containers
--------------------

This code snippet will install required dependencies (podman and docker-compose
bridge for podman), installs certificates, setup dns and start the containers.

.. code-block:: bash

    sudo dnf install -y podman podman-docker docker-compose
    sudo systemctl enable --now podman.socket
    sudo setsebool -P container_manage_cgroup true

    cp env.example .env
    sudo make trust-ca
    sudo make setup-dns
    sudo make up

.. warning::

    ``make setup-dns`` disables systemd-resolved and configures NetworkManager
    to resolve related domains through dnsmasq and a DNS server running in one
    of the containers. See the `script`_ and `dnsmasq`_ configuration for more
    details.

    If you see ``Could not determine IP address`` error when running tests, it
    means that the DNS server is not reachable. Make sure that the DNS server is
    running by starting the container with ``sudo make up`` and then run ``sudo
    make setup-dns`` again.

    If you don't want to modify your system so extensively, you can run ``sudo
    make setup-dns-files`` instead. This will only append records to your
    ``/etc/hosts`` file to make the host names resolvable. SRV or PTR lookups
    will not work, but that is not required to run the tests.

Start Active directory vagrant box
----------------------------------

The `sssd-ci-containers`_ project also provides an Active Directory virtual
machine (`vagrant`_ box), because it can not be put in a container. A Samba
container can be used to mimic Active Directory for most test cases, but you
need to start the virtual machine in order to test SSSD against real Active
Directory.

.. _script: https://github.com/SSSD/sssd-ci-containers/blob/master/src/tools/setup-dns.sh
.. _dnsmasq: https://github.com/SSSD/sssd-ci-containers/blob/master/data/configs/dnsmasq.conf
.. _vagrant: https://www.vagrantup.com

It is recommended (but not necessary) to use vagrant from
``quay.io/sssd/vagrant:latest`` container to avoid issues with vagrant plugin
installation.

.. code-block:: text

    # Install dependencies
    sudo dnf remove -y vagrant
    sudo dnf install -y libvirt qemu-kvm
    sudo systemctl start libvirtd

    # Add the following to ~/.bashrc and ‘source ~/.bashrc’
    function vagrant {
    dir="${VAGRANT_HOME:-$HOME/.vagrant.d}"
    mkdir -p "$dir/"{boxes,data,tmp}

    podman run -it --rm \
        -e LIBVIRT_DEFAULT_URI \
        -v /var/run/libvirt/:/var/run/libvirt/ \
        -v "$dir/boxes:/vagrant/boxes" \
        -v "$dir/data:/vagrant/data" \
        -v "$dir/tmp:/vagrant/tmp" \
        -v $(realpath "${PWD}"):${PWD} \
        -w $(realpath "${PWD}") \
        --network host \
        --security-opt label=disable \
        quay.io/sssd/vagrant:latest \
        vagrant $@
    }

    # Start and provision Active Directory virtual machine
    cd sssd-ci-containers/src
    vagrant up ad

    # Enroll client into the Active Directory domain
    sudo podman exec client bash -c "echo vagrant | realm join ad.test"
    sudo podman exec client cp /etc/krb5.keytab /enrollment/ad.keytab
    sudo podman exec client rm /etc/krb5.keytab

.. note::

    It is not required to have the Active Directory machine running in order to
    run the tests. If you run the tests with ``--mh-lazy-ssh`` (as shown in the
    example below) and the AD host is not running, pytest will simply skip the
    tests that requires Active Directory.

Multihost configuration
=======================

Multihost configuration defines the domains and hosts that will be used for
testing SSSD. It describes what ``domains`` are available. Each domain defines
how many ``hosts`` are in the domain and each host provides or implements a
given ``role``.

The `multihost configuration`_ bundled within the SSSD source code is designed
to work with the `sssd-ci-containers`_ project out of the box. If you chose to
create your own hosts, you need to alter the configuration to make it work with
your environment.

.. seealso::

    More information about the multihost configuration can be found in
    :doc:`config`.

Running tests
*************

Now, if you have setup the environment, you can run the tests with ``pytest``.

.. code-block:: text

    cd src/tests/system
    pytest --mh-config=mhc.yaml --mh-lazy-ssh -v

.. note::

  You can use ``-k`` parameter to `filter tests
  <https://docs.pytest.org/en/latest/example/markers.html#using-k-expr-to-select-tests-based-on-their-name>`__.

.. seealso::

  The `pytest-mh`_ plugin also provides several additional command line options
  for pytest, see its documentation for more information.

  You will find at least ``--mh-log-path`` and ``--mh-topology`` very useful.

  * ``--mh-log-path=mh.log``: Logs multihost messages into ``mh.log`` file
  * ``--mh-log-path=/dev/stderr``: Logs multihost messages to standard error output
  * ``--mh-topology=ldap``: Only run ldap tests (you can also use ``ipa``,
    ``ad``, ``samba``, ``client``)

.. _pytest: https://pytest.org=
.. _requirements.txt: https://github.com/SSSD/sssd/blob/master/src/tests/system/requirements.txt
.. _multihost configuration: https://github.com/SSSD/sssd/blob/master/src/tests/system/mhc.yaml
.. _pytest-mh: https://pytest-mh.readthedocs.io
.. _pytest-ticket: https://github.com/next-actions/pytest-ticket
.. _pytest-tier: https://github.com/next-actions/pytest-tier
