Core concepts and coding style
##############################

The code must be fully typed and follow the black coding style. All code must be
validated using the following tools:

* Check PEP8 compliance with `flake8 <https://flake8.pycqa.org>`__ and
  `pycodestyle <https://pycodestyle.pycqa.org>`__: ``flake8 . && pycodestyle .``
* Sort imports with `isort <https://pycqa.github.io/isort/>`__: ``isort .``
* Convert to `black <https://black.readthedocs.io>`__ style: ``black .``
* Check types with `mypy <https://mypy.readthedocs.io>`__: ``mypy .``

Core concepts
*************

* Each test starts fresh

  * Everything that is changed by the test is reverted when the test is finished

  * Execution of one test must not affect execution of some other test

* Read and understand

  * What a test does and what data and setup does it requires must be clearly
    visible from the test itself without jumping to other places in the code

  * Avoid using fixtures unless you have a very good reason to do so

* Extend the API

  * If you miss some functionality, extend :doc:`lib.sssd <api>` with a
    new, clear, documented and reusable API

  * Avoid calling commands on remote hosts directly from the tests, this belongs
    to :mod:`lib.sssd.roles`

  * If you need to call a command, it most likely means that you want to extend
    :mod:`lib.sssd.roles` module

* Use topology parametrization whenever possible

  * This rapidly increases the code coverage

Naming tests
************

Name your tests as ``test_feature__case``. For example:

.. code-block:: python

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_id__shortname():
        pass

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_id__fqn():
        pass

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_id__name_with_space():
        pass

About using fixtures
********************

`Fixtures <https://docs.pytest.org/en/latest/explanation/fixtures.html>`__ are a
great pytest tool to provide and share initial setup and prepare data for a
test. However, they can also be a great enemy if you overuse them or if you nest
them into multiple levels (using fixture inside a fixture).

Overusing fixtures makes it quite difficult to understand what a test does and
what data and setup does it require. This is because the information is not
present directly in the test itself but on different place or places in the
code. Therefore you have to jump back and forth in the code in order to
understand what the test does. This is especially bad in testing projects like
SSSD that has so many components.

Another big downside of using fixtures is that they do not allow slight
modifications of the setup. Most of the time, you need to write multiple tests
for single functionality. And even though it seems logical that these tests
share the same setup, it is most often not the case as each test usually
requires slight modification of the overall setup. If the setup is done with
fixtures and you need to add a new test case that requires slight modification
you either end up duplicating the fixture code, creating more fixtures or
refactoring the fixture and every single related test. This of course makes the
tests harder to understand and extend and it diminishes the benefit of using
fixtures.

The SSSD test framework :doc:`lib.sssd <api>` makes the SSSD related setups quite
easy, with just a few lines of code where everything is clear out of the box
even without reading any documentation. Therefore there is no need to use
fixtures.

.. warning::

    The general recommendation is: **Avoid using fixtures** *unless you have a
    very good reason to use it.*

Organizing test cases
*********************

Pytest allows you to write tests inside a class (starts with `Test`) or directly
inside a module (a function starting with `test_`). Even though it might be
logical to organize tests inside a class, it does not give you any benefit over
plain function and it create just one more level of organization that must be
correctly kept and maintained.

.. warning::

    **Avoid organizing tests into classes** *unless there is a food reason to
    use them* (for example when you need to use a class-scoped fixture, however
    this break "Each test starts fresh" principle so it is reserved for very
    special cases).
