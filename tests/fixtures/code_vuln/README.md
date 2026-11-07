Deliberately vulnerable fake project for tests/test_code_audit.py. Never deploy it. The test copies it to a
temporary folder, renames `*.fixture` files (so dependency scanners ignore the old versions here) and adds the fake
secret files at runtime, so none are stored in the repository.
