---
name: refactor-service:test
description: "Step 5/5: Write tests for the new service/repo layer and verify the full suite passes."
argument-hint: "<viewset-file-or-class>"
user-invocable: true
---

# Refactor Test (Step 5/5)

Write tests for the newly extracted service and repository, and verify the full test suite passes. `$ARGUMENTS` is the ViewSet file or class name.

This is step 5 of the `/refactor-service` pipeline (`/refactor-service:test`). **Requires completed steps 3 and 4.**

## Process

1. **Read the service and repository** created in steps 3-4.

2. **Write service unit tests** (`<app>/tests/pytest_<name>_service.py`):
   - Use mocked repositories (no DB needed)
   - Test each service method independently
   - Test business logic, validation, edge cases
   - Test that audit logging is called correctly
   - Use pytest style: plain functions + fixtures, no TestCase classes

   ```python
   import pytest
   from unittest.mock import MagicMock

   @pytest.fixture
   def ruleset_repo():
       return MagicMock(spec=RulesetRepository)

   @pytest.fixture
   def service(ruleset_repo):
       return RulesetService(ruleset_repo=ruleset_repo, audit=MagicMock())

   def test_create_ruleset_calls_repo(service, ruleset_repo):
       service.create_ruleset(name="test")
       ruleset_repo.create.assert_called_once_with(name="test")
   ```

3. **Write repository tests** (if repo was created) (`<app>/tests/pytest_<name>_repo.py`):
   - Thin integration tests that hit the DB
   - Use `@pytest.mark.django_db`
   - Test queryset building, filtering, edge cases

4. **Verify existing ViewSet/API tests still pass** (they should — the API contract didn't change):
   ```bash
   DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv --no-cov <app>/tests/
   ```

5. **Run the full suite** for confidence:
   ```bash
   DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv --no-cov
   ```

6. **Run lint**:
   ```bash
   ruff check <new-test-files>
   ```

7. **Present results**: Show new test files, test output, and any issues found.

## Rules

- Service tests must be fast — no DB, no network, mock all external dependencies
- Repository tests should be minimal — just verify the ORM calls work
- Do NOT rewrite existing ViewSet tests — they validate the API contract is preserved
- Use pytest style exclusively: plain functions, fixtures, `assert`, `pytest.raises`
- Follow the `pytest_*.py` naming convention
- If any existing test fails, investigate: is it a real regression from the refactor, or a pre-existing issue?
