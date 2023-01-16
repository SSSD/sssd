Crash Course
############

This is a crash course for SSSD's test framework. The course consists of
multiple task that show the fundamental features and API. First, try to find
the solution for the task by yourself using the information present in the
documentation and inside the hints. Then display the task's solution and compare
it with yours.

Prepare the environment
***********************

See :doc:`../running-tests` to se how to prepare the environment and run the tests.

Is everything working?
======================

You should be ready to execute the tests, if you setup the environment
correctly. Go to the system tests directory (``src/tests/system``) of SSSD
repository and run the tests from this course with:

.. code-blocK:: text

    $ pytest --mh-config=./mhc.yaml --mh-log-path=./log -v ./docs/course/test_course.py

Take the Course
***************

You can begin by creating a file inside the ``tests`` directory, for example
``tests/test_course.py`` and include the following imports:

.. code-block:: python

    import pytest

    from lib.sssd.topology import KnownTopology, KnownTopologyGroup
    from lib.sssd.roles.ad import AD
    from lib.sssd.roles.client import Client
    from lib.sssd.roles.generic import GenericADProvider, GenericProvider
    from lib.sssd.roles.ipa import IPA
    from lib.sssd.roles.ldap import LDAP
    from lib.sssd.roles.samba import Samba

Now try to run the file with ``pytest``:

.. code-block:: console

    pytest --mh-config=./mhc.yaml --mh-log-path=./log -v ./tests/test_course.py

Does it work? Good. Now, you can continue with the following tasks.

* Tasks 1 to 14 will teach you how to write some basic tests for LDAP.
* Tasks 15 - 26 requires you to write the same tests but for IPA. You will see
  that it is pretty much the same except some differences in primary group - IPA
  creates primary groups automatically.
* Tasks 26 - 31 are about topology parametrization - writing single test for
  multiple backends.

.. dropdown:: Task 1
    :color: secondary
    :icon: checklist

    Write your first test for the LDAP topology. The test does not have to do
    anything, just define it and make sure you can run it successfully.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :class:`lib.sssd.topology.KnownTopology`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_01
            :end-before: end:task_01

.. dropdown:: Task 2
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_02
            :end-before: end:task_02

.. dropdown:: Task 3
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid, gid.
    #. Also check that the primary group of the user does not exist.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology``
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_03
            :end-before: end:task_03

.. dropdown:: Task 4
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_04
            :end-before: end:task_04

.. dropdown:: Task 5
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``.
    #. Add new LDAP group named ``users`` with gid set to ``20001``.
    #. Add user ``tuser`` as a member of group ``users``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of ``users``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_05
            :end-before: end:task_05

        .. seealso::

            The memberof method allows you to use multiple input types. Including
            group name (string), group id (int) and list of names or ids.

.. dropdown:: Task 6
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``.
    #. Add two LDAP groups named ``users`` and ``admins`` without any gid set.
    #. Add user ``tuser`` as a member of groups ``users`` and ``admins``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of both ``users`` and ``admins``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_06
            :end-before: end:task_06

        .. note::

            If you omit uid or gid attribute on user or group then the id is
            automatically generated by the framework. This is useful for cases where
            the id is not important.

.. dropdown:: Task 7
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_07
            :end-before: end:task_07

        .. note::

            The password parameter defaults to ``Secret123`` so it can be omitted.
            However, it is a good practice to set it explicitly when you test
            authentication to help understand the test case.

.. dropdown:: Task 8
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``ssh`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_08
            :end-before: end:task_08

.. dropdown:: Task 9
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Parametrize a test case argument with two values: ``su`` and ``ssh``
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` and ``ssh`` with the password,
       use the parametrized value to determine which method should be used.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `@pytest.mark.parametrize <https://docs.pytest.org/en/latest/how-to/parametrize.html>`__
        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_09
            :end-before: end:task_09

        .. note::

            This produces two test runs: one for ``su`` authentication and one for
            ``ssh``. It is better to parametrize the test instead of calling both
            ``su`` and ``ssh`` in one test run so you can test only one thing at a
            time if you ever need to debug failure.

.. dropdown:: Task 10
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with password set to ``Secret123``.
    #. Add new sudo rule to LDAP that allows the user to run ``/bin/ls`` on ``ALL``
       hosts.
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser``.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :meth:`lib.sssd.utils.sssd.SSSDCommonConfiguration.sudo`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`
        * :class:`lib.sssd.utils.authselect.AuthselectUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_10
            :end-before: end:task_10

        .. note::

            You need to enable ``with-sudo`` using authselect so sudo can read rules
            from SSSD. You can use :meth:`lib.sssd.utils.sssd.SSSDCommonConfiguration.sudo`
            as a shortcut for selecting authselect profile and enabling the sudo responder.

.. dropdown:: Task 11
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Add new sudo rule to LDAP that allows the user to run ``/bin/ls`` on ``ALL``
       hosts but without requiring authentication (nopasswd).
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command without a password and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser`` without a password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :meth:`lib.sssd.utils.sssd.SSSDCommonConfiguration.sudo`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`
        * :class:`lib.sssd.utils.authselect.AuthselectUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_11
            :end-before: end:task_11

.. dropdown:: Task 12
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Set ``use_fully_qualified_names`` to ``true`` on the client.
    #. Start SSSD on the client.
    #. Check that ``tuser`` does not exist.
    #. Check that ``tuser@test`` exists.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_12
            :end-before: end:task_12

        .. note::

            Changes to the configuration are automatically applied when calling
            ``client.sssd.start()``. You can override this behavior by calling
            ``client.sssd.start(apply_config=False)``.

.. dropdown:: Task 13
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser``.
    #. Set ``use_fully_qualified_name`` to ``true`` on the client (intentionally
       create a typo in the option name).
    #. Start SSSD on the client.
    #. Assert that an ``Exception`` was risen

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `pytest.raises <https://docs.pytest.org/en/7.1.x/how-to/assert.html#assertions-about-expected-exceptions>`__
        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_13
            :end-before: end:task_13

        .. note::

            Starting SSSD with ``client.sssd.start()`` automatically validates
            configuration with ``sssctl config-check``. If the validation fails, it
            raises an exception. You can override this behavior by calling
            ``client.sssd.start(check_config=False)``.

.. dropdown:: Task 14
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP topology.
    #. Add new LDAP user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new LDAP group named ``tuser`` with gid set to ``10001``, use rfc2307bis schema.
    #. Add two LDAP groups named ``users`` and ``admins`` without any gid set, use rfc2307bis schema.
    #. Add user ``tuser`` as a member of groups ``users`` and ``admins``
    #. Set ``ldap_schema`` to ``rfc2307bis`` on the client
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of both ``users`` and ``admins``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_14
            :end-before: end:task_14

.. dropdown:: Task 15
    :color: secondary
    :icon: checklist

    Write your first test for the IPA topology. The test does not have to do
    anything, just define it and make sure you can run it successfully.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :class:`lib.sssd.topology.KnownTopology`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_15
            :end-before: end:task_15

.. dropdown:: Task 16
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_16
            :end-before: end:task_16

.. dropdown:: Task 17
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with uid and gid set to ``10001``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_17
            :end-before: end:task_17

        .. note::

            Unlike LDAP, IPA creates the primary group automatically therefore we do
            not have to add it ourselves.

.. dropdown:: Task 18
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new IPA group named ``users`` with gid set to ``20001``.
    #. Add user ``tuser`` as a member of group ``users``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of ``users``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_18
            :end-before: end:task_18

.. dropdown:: Task 19
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with uid and gid set to ``10001``.
    #. Add new IPA group named ``users`` without any gid set.
    #. Create a group object for IPA group ``admins`` that already exist (it is created by IPA installation)
    #. Add user ``tuser`` as a member of groups ``users`` and ``admins``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.
    #. Check that the user is member of both ``users`` and ``admins``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_19
            :end-before: end:task_19

.. dropdown:: Task 20
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_20
            :end-before: end:task_20

.. dropdown:: Task 21
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``ssh`` with the password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_21
            :end-before: end:task_21

.. dropdown:: Task 22
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Parametrize a test case argument with two values: ``su`` and ``ssh``
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` and ``ssh`` with the password,
       use the parametrized value to determine which method should be used.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `@pytest.mark.parametrize <https://docs.pytest.org/en/latest/how-to/parametrize.html>`__
        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_22
            :end-before: end:task_22

.. dropdown:: Task 23
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser`` with password set to ``Secret123``.
    #. Add new sudo rule to IPA that allows the user to run ``/bin/ls`` on ``ALL``
       hosts.
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser``.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :meth:`lib.sssd.utils.sssd.SSSDCommonConfiguration.sudo`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_23
            :end-before: end:task_23

.. dropdown:: Task 24
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Add new sudo rule to IPA that allows the user to run ``/bin/ls`` on ``ALL``
       hosts but without requiring authentication (nopasswd).
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run only ``/bin/ls`` command without a password and only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser`` without a password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :meth:`lib.sssd.utils.sssd.SSSDCommonConfiguration.sudo`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. code-block:: python

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_24
            :end-before: end:task_24

.. dropdown:: Task 25
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Set ``use_fully_qualified_names`` to ``true`` on the client.
    #. Start SSSD on the client.
    #. Check that ``tuser`` does not exist.
    #. Check that ``tuser@test`` exists.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ipa.IPA`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_25
            :end-before: end:task_25

.. dropdown:: Task 26
    :color: secondary
    :icon: checklist

    #. Create a new test for IPA topology.
    #. Add new IPA user named ``tuser``.
    #. Set ``use_fully_qualified_name`` to ``true`` on the client (intentionally
       create a typo in the option name).
    #. Start SSSD on the client.
    #. Assert that an ``Exception`` was risen

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopology`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.ldap.LDAP`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_26
            :end-before: end:task_26

.. dropdown:: Task 27
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for LDAP, IPA, Samba and AD topology.
    #. Add new user named ``tuser``.
    #. Add new groups ``tgroup_1`` and ``tgroup_2``
    #. Add the user ``tuser`` as a member of ``tgroup_1`` and ``tgroup_2``
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.
    #. Check that the user is member of ``tgroup_1`` and ``tgroup_2``

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopologyGroup`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.generic.GenericProvider`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_27
            :end-before: end:task_27

        .. note::

            We can write single test that can be run on multiple topologies. This is
            achieved by using well-defined API that is implemented by all providers.
            However, there are some distinctions that you need to be aware of - for
            example LDAP does not create primary group automatically, IPA creates it
            automatically and Samba and AD uses ``Domain Users`` as the primary
            group.

.. dropdown:: Task 28
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for Samba and AD topology.
    #. Add new user named ``tuser``.
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name.
    #. Check that the user is member of ``domain users`` (Active Directory built-in group)

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopologyGroup`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.generic.GenericADProvider`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_28
            :end-before: end:task_28

.. dropdown:: Task 29
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for LDAP and IPA topology.
    #. Add new user named ``tuser`` with uid and gid set to ``10001``.
    #. Create user's primary group object only if the topology is LDAP
    #. Start SSSD on the client.
    #. Run ``id`` command on the client
    #. Check ``id`` result: check that the user exist and has correct name, uid,
       primary group name and gid.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-identity`
        * :class:`lib.sssd.topology.KnownTopologyGroup`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.generic.GenericProvider`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.tools.LinuxToolsUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_29
            :end-before: end:task_29

.. dropdown:: Task 30
    :color: secondary
    :icon: checklist

    #. Create a new test for LDAP, IPA, Samba and AD topology.
    #. Add new user named ``tuser``.
    #. Add new sudo rule ``defaults`` and set ``!authenticate`` option
    #. Add new sudo rule to that ``ALL`` users on ``ALL`` hosts run ``ALL`` commands.
    #. Select ``sssd`` authselect profile with ``with-sudo`` enabled.
    #. Enable sudo responder in SSSD.
    #. Start SSSD on the client.
    #. Check that ``tuser`` can run ``ALL`` commands without a password but only as ``root``.
    #. Check that running ``/bin/ls`` through ``sudo`` actually works for ``tuser`` without a password.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopologyGroup`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.generic.GenericProvider`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :meth:`lib.sssd.utils.sssd.SSSDCommonConfiguration.sudo`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_30
            :end-before: end:task_30

.. dropdown:: Task 31
    :color: secondary
    :icon: checklist

    #. Create a new parametrized test for LDAP, IPA, Samba and AD topology.
    #. Parametrize a test case argument with two values: ``su`` and ``ssh``
    #. Add new user named ``tuser`` with password set to ``Secret123``.
    #. Start SSSD on the client.
    #. Test that the user can authenticate via ``su`` and ``ssh`` with the password,
       use the parametrized value to determine which method should be used.

    .. dropdown:: Display hints
        :color: info
        :icon: light-bulb

        * `@pytest.mark.parametrize <https://docs.pytest.org/en/latest/how-to/parametrize.html>`__
        * :doc:`../writing-tests`
        * :doc:`../guides/testing-authentication`
        * :class:`lib.sssd.topology.KnownTopologyGroup`
        * :class:`lib.sssd.roles.base.BaseLinuxRole`
        * :class:`lib.sssd.roles.generic.GenericProvider`
        * :class:`lib.sssd.roles.client.Client`
        * :class:`lib.sssd.utils.sssd.SSSDUtils`
        * :class:`lib.sssd.utils.authentication.AuthenticationUtils`

    .. dropdown:: Display solution
        :color: success
        :icon: check-circle

        .. literalinclude:: ./test_course.py
            :language: python
            :start-after: start:task_31
            :end-before: end:task_31
