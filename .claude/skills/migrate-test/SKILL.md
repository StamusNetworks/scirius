---
name: migrate-test
description: Migrate a unittest/TestCase test file to modern pytest style, catching false-green tests along the way.
argument-hint: "<test-file-path>"
user-invocable: true
---

# Migrate Test

Convert a Django `TestCase`/`APITestCase` test file (`test_*.py`) to modern pytest style (`pytest_*.py`). This project is actively migrating from unittest to pytest. `$ARGUMENTS` should be the path to the test file to migrate.

## Context

- Old-style tests: `test_*.py` files using `class TestFoo(TestCase)` or `class TestFoo(RestAPITestBase, APITestCase)`
- New-style tests: `pytest_*.py` files using plain `def test_foo()` functions with fixtures
- The shared `RestAPITestBase` mixin (in `rules/tests/test_misc.py`) provides `http_get`, `http_post`, etc. — these should be replaced with direct DRF `APIClient` usage via the `drf` fixture from `conftest.py`
- Existing conftest fixtures: `default_profile` (creates test user), `drf` (authenticated API client), `clean_cache`, `prepare_test_environment`

## Process

1. **Read the source file** specified in `$ARGUMENTS`. If no argument given, ask which file to migrate.

2. **Read the app's conftest.py** (if it exists) and the root `conftest.py` to understand available fixtures.

3. **Analyze every test method** for correctness issues BEFORE migrating. For each test, check:
   - **Assertions that test nothing useful**: `assertEqual(response.status_code, 200)` without checking response data
   - **Missing assertions entirely**: test methods that call endpoints but never assert anything meaningful
   - **Wrong status code expectations**: POST/DELETE returning 200 instead of 201/204
   - **Assertions on the wrong thing**: asserting the request payload instead of the response
   - **setUp creating state that masks bugs**: objects created in setUp that make tests pass even if the view is broken
   - **Tests that only test Django/DRF framework behavior**, not application logic
   - **Mocking that disconnects the test from reality**: mocking the thing being tested

4. **Report findings** before writing any code:
   - List each test method with a status: `OK`, `SUSPECT` (likely false-green), or `BROKEN` (definitely wrong)
   - For `SUSPECT`/`BROKEN` tests, explain what's wrong and propose a fix
   - Ask the user to confirm before proceeding

5. **Create the new pytest file** (`pytest_*.py` in the same directory):
   - Convert `setUp`/`tearDown` to `@pytest.fixture` (prefer function-scoped)
   - Replace `self.assertEqual`/`self.assertTrue` with plain `assert`
   - Replace `self.assertRaises` with `pytest.raises`
   - Replace `self.client` usage with the `drf` fixture (from root conftest)
   - Use `@pytest.mark.django_db` or the `db` fixture as needed
   - Preserve test logic and intent, but fix any `SUSPECT`/`BROKEN` tests
   - Group related fixtures in the file, not in a class
   - Use `@pytest.fixture` with `yield` for teardown instead of `tearDown`
   - Keep test names descriptive: `test_create_ruleset_with_invalid_name` not `test_003`

6. **Run the new tests** to verify they pass:
   ```bash
   DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv --no-cov <new-file>
   ```

7. **Report**: Show what was migrated, what was fixed, and what was intentionally changed.

## Rules

- NEVER silently drop a test — every old test must have a corresponding new test (or an explicit note that it was removed and why)
- NEVER keep a false-green test as-is — fix it or flag it
- Prefer fixtures over class-based setUp/tearDown
- Use `pytest.param` and `@pytest.mark.parametrize` to reduce duplication when multiple tests differ only in input
- Do NOT add `@pytest.mark.django_db` if the test doesn't touch the database
- The new file should be `pytest_<descriptive_name>.py`, not `pytest_test_<old_name>.py`
