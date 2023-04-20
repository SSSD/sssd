This directory contains tests data.

The directory hierarchy is as follows:

* `data/`
  * files shared for all test modules
  * `test_module/` (directory for `test_module.py`)
    * files shared for all tests within the module `test_module.py`
      * `test_module__xyz/` (directory for single test from the module)
        * files relevant only for the test `test_module__xyz`

Use the following fixtures to get the path to the test data:
* `datadir` -> `data/`
* `moduledatadir` -> `data/test_module` for current module
* `testdatadir` -> `data/test_module/test_case` for current module and test case

For example:

```python
@pytest.mark.topology(KnownTopology.Client)
def test_datadir(client: Client, datadir: str):
    with open(f"{datadir}/global_shared_data") as f:
        contents = f.read()

    pass

@pytest.mark.topology(KnownTopology.Client)
def test_moduledatadir(client: Client, moduledatadir: str):
    with open(f"{moduledatadir}/module_specific_data") as f:
        contents = f.read()

    pass

@pytest.mark.topology(KnownTopology.Client)
def test_testdatadir(client: Client, testdatadir: str):
    with open(f"{testdatadir}/test_specific_data") as f:
        contents = f.read()

    pass
```
