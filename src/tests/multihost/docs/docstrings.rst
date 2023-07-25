Docstrings for Test Cases
=================================
We use docstrings to document the intent of the test code, its steps and its expected results. It is a very useful way to describe the test, especially when the test executes on multiple hosts and the code is long and complex. `Python docstrings`_ provides more details on docstrings.

.. _Python docstrings:  https://www.geeksforgeeks.org/python-docstrings

| Besides, these benefits it is also used to automatically add/modify the test cases in an internal test case management system. We use `Betelgeuse`_ for this purpose.

.. _Betelgeuse:  https://betelgeuse.readthedocs.io/en/stable

=========================
Docstrings in SSSD tests
=========================
Format explained below is only for the actual test cases written in pytest framework. This format is standardized for better readability and to enable `Betelgeuse`_ scripts to add/modify the tests into the internal test case management system

New pytest test file
--------------------
| The first line of the test file should be short description of the tests covered and next line should be left blank
eg. `test_kcm.py <../alltests/test_kcm.py#L1>`__

Docstring fields
----------------
Many fields have common values for all the tests contained in the file. Such fields can be mentioned in the start of the file (below the blank line - refer to the same example given above) and would apply to each test when the tests are added to the test case management system. If the value of a field for a test is different, we can override it by adding it in the respective test case.

Common Fixed Fields and Values
******************************
These fields with their respective values should always be part of test files

**:upstream: yes** This means that the code is being added in github SSSD project

**:casecomponent: sssd** The component package to be tested

**:status: approved** The status of all the tests in the module is set to 'approved' in polarion

**:subsystemteam: sst_idm_sssd** A custom field to categorize the test for a specific team. (internal purpose)

Exception
^^^^^^^^^
**:requirement:** A requirement is a feature or function of the product, based on which the test cases are defined. It enables testers to test and check if the requirement has been adequately met.

This can be mentioned at the start of the file to apply to each test case in the file. If a test being added to the test file belongs to another requirement, then it can be added in the docstrings of that test. The value of the requirement would differ for each test file, hence it is not a fixed value field.

Test cases are linked automatically to the requirement by the internal betelgeuse scripts when they are being added into the system.

Test Case Fields
****************
| **:title:** A friendly name or a short summary of the test case. If name is long (exceeds 119 characters on the line), it can continue on the next line, but should be indented to start after the first colon or align with start of the previous line
eg.
::
    :title: first line of the test case name exceeding 119 characters
     should start from under 't' of title

| Or
eg.
::
    :title: first line of the test case name exceeding 119 characters
            should align with the start of previous line

**:description:** An optional field to add more details about the test

**:id:** A unique "id" for each test case to avoid duplication in the test case management system. It can be created by running the python command on your terminal

.. code-block:: python3

    python3 -c 'import uuid; print (uuid.uuid4())'

**:bugzilla:** Link to a bugzilla if the test code is testing and verifying a known bugzilla fix

**:customerscenario: true** The test code is testing and verifying a known bugzilla fix affecting a customer. This field can be skipped if this condition is not met, it will default to ``false``

**:steps:** Clearly written test steps. The number of steps should match the number of ``expectedresults``. Betelgeuse creates a table of steps and corresponding expected result in the test case management system

**:expectedresults:** Clearly written expected results. For each step there should be a corresponding expected result.

| If a 'step' or 'expected result' is long, it should be indented to align with the start of the previous line. It will be picked up as a single step into the system and avoid failures.
eg. step 3 of steps
::
    :steps:
      1. Configure SSSD with sudo
      2. Leave ou=sudoers empty - do not define any rules
      3. See that smart refresh does not contain
         'modifyTimestamp' in the filter

Some old tests do not have ``steps`` and ``expectedresult`` included in the docstrings because this process was not standardized in the past. It is now mandatory for all the new tests.

Default Test Case Fields
************************
There are some important fields that should be added as part of the test case docstring, but they have default values already set as documented under 'Test Case Fields' in `Default Configuration`_ section. These can be added in case that particular field should have a different value. Some of the fields with default values can be seen in the example.
eg.
::

    :caselevel: Component
    :caseautomation: Automated
    :caseimportance: Medium
    :testtype: Functional
    :caseposneg: Positive

.. _Default Configuration: https://betelgeuse.readthedocs.io/en/stable/config.html#default-configuration
