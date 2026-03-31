---
name: refactor-service:slim
description: "Step 4/5: Modify the ViewSet to delegate to the service layer."
argument-hint: "<viewset-file-or-class>"
user-invocable: true
---

# Refactor Slim (Step 4/5)

Modify the ViewSet to use the new service, removing business logic from the controller. `$ARGUMENTS` is the ViewSet file or class name.

This is step 4 of the `/refactor-service` pipeline (`/refactor-service:slim`). **Requires approved service from step 3.**

## Process

1. **Read the current ViewSet** and the service created in step 3.

2. **Modify the ViewSet**:

   - Add service instantiation:
     ```python
     def __init__(self, **kwargs):
         super().__init__(**kwargs)
         self._service = RulesetService(
             ruleset_repo=RulesetRepository(),
             audit=AuditService(),
         )
     ```

   - For each method that was extracted to the service:
     - Keep: request parsing, serializer validation, permission checks, response building
     - Replace: business logic calls with `self._service.<method>(...)`
     - Remove: direct ORM calls that are now in the service/repo
     - Keep: `REQUIRED_GROUPS` — permissions stay on the ViewSet

   - Preserve the exact same HTTP behavior: same status codes, same response format, same error handling

3. **Run validation**:
   ```bash
   ruff check <modified-viewset>
   ```

4. **Run existing tests** to verify nothing broke:
   ```bash
   DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv --no-cov <app>/tests/
   ```

5. **Present the diff** to the user:
   - Show what was removed from the ViewSet
   - Show what service calls replaced it
   - Show test results

## Rules

- The public API must NOT change — same URLs, same request/response format, same status codes
- Keep `REQUIRED_GROUPS` on the ViewSet
- Do NOT move permission checks to the service
- If a test fails, investigate whether it's a real regression or a test that was already fragile
- Show the diff clearly so the user can verify the refactor is behavior-preserving
