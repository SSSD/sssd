Additional markers and metadata
###############################

Additional test metadata
************************

The following metadata are **required** to be present in docstring of each test.
These metadata are used to organize test in Polarion to provide evidency and
traceability for enterprise releases.

.. code-block:: python
    :caption: Required metadata

    def test_example():
        """
        :title: Human readable test title
        :setup:
            1. Setup step
            ...
            N. Setup step
        :steps:
            1. Assert step
            ...
            N. Assert step
        :expectedresults:
            1. Expected result of assert step 1
            ...
            N. Expected result of assert step N
        :teardown:
            1. Teardown step
            ...
            N. Teardown step
        :customerscenario: False|True
        """

* **title**: Simple test case description.
* **setup**: All steps required to setup the environment before assertions (e.g.
  what users are created).
* **steps**: Individual test or assertion steps.
* **expectedresults**: Expected result of each step.
* **teardown** (optional): All steps required to teardown environment. This
  field is usually omitted. But it can be used to document some very specific
  teardown steps if required.
* **customerscenario**: Is this test related to a Red Hat Customer Case?

.. code-block:: python
    :caption: Metadata example

    @pytest.mark.topology(KnownTopology.Client)
    def test_kcm__tgt_renewal(client: Client, kdc: KDC):
        """
        :title: Automatic ticket-granting ticket renewal.
        :setup:
            1. Add Kerberos principal "tuser" to KDC
            2. Add local user "tuser"
            3. Enable TGT renewal in KCM
            4. Start SSSD
        :steps:
            1. Authenticate as "tuser" over SSH
            2. Kinit as "tuser" and request renewable ticket
            3. Wait until automatic renewal is triggered and check that is was renewed
        :expectedresults:
            1. User is logged into the host
            2. TGT is available
            3. TGT was renewed
        :customerscenario: False
        """

Additional markers
******************

Besides the ``topology`` mark, that is required and that defines which hosts
from the multihost configuration are relevant for the test, there are also other
marks that you can use to enhance the testing experience.

@pytest.mark.ticket
===================

The `ticket mark <https://github.com/next-actions/pytest-ticket>`__ can
associate a test with Github issues and Bugzilla or JIRA tickets.

The ``@pytest.mark.ticket`` takes one or more keyword arguments that represents
the tracker tool and the ticket identifier. The value may be single ticket or
list of tickets.

.. code-block:: python
    :caption: Examples

    @pytest.mark.ticket(gh=3433)
    def test_gh()
        pass

    @pytest.mark.ticket(bz=5003433)
    def test_bz()
        pass

    @pytest.mark.ticket(jira="SSSD-3433")
    def test_jira()
        pass

    @pytest.mark.ticket(gh=3433, bz=5003433, jira="SSSD-3433")
    def test_all()
        pass

    @pytest.mark.ticket(gh=3433, bz=[5003433, 5003434], jira="SSSD-3433")
    def test_multi()
        pass

You can then run tests that are relevant only to the selected ticket:

.. code-block:: text

    cd src/tests/system
    pytest --mh-config=mhc.yaml --mh-lazy-ssh -v --ticket=gh#3433

@pytest.mark.tier
=================

The `tier mark <https://github.com/next-actions/pytest-tier>`__ can
associate a test with a specific tier.

The ``@pytest.mark.tier`` takes single number as an argument.

.. code-block:: python
    :caption: Examples

    @pytest.mark.tier(0)
    def test_tier0()
        pass

    @pytest.mark.tier(1)
    def test_tier1()
        pass

You can then run tests that are relevant only to the selected ticket:

.. code-block:: text

    cd src/tests/system
    pytest --mh-config=mhc.yaml --mh-lazy-ssh -v --tier=1

Tier definition
===============

.. list-table:: Tier definition
    :align: center
    :widths: 10 90
    :header-rows: 1
    :stub-columns: 1

    * - Tier
      - Description
    * - @TODO
      -
