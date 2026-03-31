---
name: write-functest
description: Write async functional API tests (httpx) to replace Cypress/RF E2E tests.
argument-hint: "<endpoint-or-cypress-file>"
user-invocable: true
---

# Write Functional Test

Generate async functional API tests using httpx against a live server. These tests replace Cypress browser tests by testing the same user flows at the API level. `$ARGUMENTS` can be a Cypress test file to port, an API endpoint path, or a feature name.

## Context

- Functional tests live in `tests/functional/`
- They use `httpx.AsyncClient` with `pytest-asyncio` (auto mode, session-scoped event loop)
- They run against a live Scirius instance (`SCIRIUS_URL` env var)
- Auth via `SCIRIUS_AUTH_TOKEN` env var (Token-based)
- The `api` fixture (in `tests/functional/conftest.py`) provides an authenticated async client
- The `client` fixture provides an unauthenticated client
- Helper modules exist in `tests/functional/helpers/` (currently stubs — populate as needed)
- Tests are organized by feature: `test_<feature>.py`

## Process

1. **Determine what to test**:
   - If `$ARGUMENTS` is a Cypress file: read it and extract the user flows being tested. Map UI actions to their underlying API calls.
   - If `$ARGUMENTS` is an endpoint: read the corresponding ViewSet/API code to understand all operations.
   - If `$ARGUMENTS` is a feature name: find the relevant API endpoints and Cypress tests.

2. **Read existing functional tests** to match the established style (`tests/functional/test_startup.py` is the reference).

3. **Read the API source code** to understand:
   - Request/response schemas (from serializers)
   - Required permissions (`REQUIRED_GROUPS`)
   - Side effects (UserAction audit logs, signals, etc.)
   - Error responses and edge cases

4. **Design the test plan** covering:
   - **Happy path CRUD**: Create, Read, List, Update, Delete
   - **Validation errors**: Missing required fields, invalid values
   - **Permission checks**: Unauthenticated access, insufficient permissions
   - **Filtering/search**: If the endpoint supports query params
   - **Side effects**: Verify audit logs, related objects, etc.
   - **Concurrency** (if relevant): Parallel requests, race conditions

5. **Write the tests** following these patterns:

   ```python
   import pytest
   from httpx import AsyncClient

   pytestmark = pytest.mark.asyncio


   async def test_list_rulesets(api: AsyncClient):
       resp = await api.get("/rest/rules/ruleset/")
       assert resp.status_code == 200
       data = resp.json()
       assert "results" in data


   async def test_create_ruleset_requires_auth(client: AsyncClient):
       resp = await client.post("/rest/rules/ruleset/", json={"name": "test"})
       assert resp.status_code == 401
   ```

6. **Handle test data lifecycle**:
   - Tests must clean up after themselves (delete created objects)
   - Use fixtures with `yield` for setup/teardown
   - Never depend on pre-existing data beyond what the server starts with
   - Use unique names/identifiers to avoid conflicts with parallel runs

7. **Run the tests** if a local server is available:
   ```bash
   cd tests/functional && SCIRIUS_URL=http://localhost:8000 SCIRIUS_AUTH_TOKEN=<token> pytest -vv <new-file>
   ```

8. **If porting from Cypress**: note which Cypress tests are now covered so they can be tracked for removal.

## Rules

- All test functions must be `async def`
- Use `api` fixture for authenticated requests, `client` for unauthenticated
- Never hardcode URLs — use the path patterns from the router
- Test the API contract, not implementation details
- Each test should be independent — no ordering dependencies
- Use descriptive test names that read as specifications: `test_delete_ruleset_returns_404_when_not_found`
- Add `pytest.mark.slow` for tests that take more than a few seconds
- Add `pytest.mark.requires_es` for tests that need Elasticsearch
