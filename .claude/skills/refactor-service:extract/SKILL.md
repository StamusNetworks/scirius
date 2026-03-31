---
name: refactor-service:extract
description: "Step 3/5: Create the service and repository files (without modifying the ViewSet)."
argument-hint: "<viewset-file-or-class>"
user-invocable: true
---

# Refactor Extract (Step 3/5)

Create the service and repository files based on the approved plan. `$ARGUMENTS` is the ViewSet file or class name.

This is step 3 of the `/refactor-service` pipeline (`/refactor-service:extract`). **Requires an approved plan from step 2.**

## Process

1. **Review the plan** from step 2. If no plan exists, tell the user to run `/refactor-service:plan` first.

2. **Create directory structure** if it doesn't exist:
   ```
   <app>/services/__init__.py
   <app>/repositories/__init__.py  (if repo is planned)
   ```

3. **Write the service file** (`<app>/services/<name>.py`):
   - Follow the method signatures from the plan exactly
   - Use dependency injection: all external dependencies come through `__init__`
   - Move business logic from the ViewSet methods (copy, don't cut — ViewSet stays untouched)
   - Move `UserAction` audit logging to service methods
   - Add type hints on all methods
   - Keep methods focused: one responsibility per method

   ```python
   from __future__ import annotations

   class RulesetService:
       def __init__(self, ruleset_repo: RulesetRepository, audit: AuditService) -> None:
           self._ruleset_repo = ruleset_repo
           self._audit = audit

       def create_ruleset(self, *, name: str, ...) -> Ruleset:
           ...
   ```

4. **Write the repository file** (if planned) (`<app>/repositories/<name>.py`):
   - Pure data access — no business logic
   - Thin wrappers around ORM calls
   - Only create if there's non-trivial queryset logic worth isolating

5. **Run validation**:
   ```bash
   ruff check <new-files>
   mypy <new-files>
   ```
   Fix any issues before presenting to the user.

6. **Present the new files** to the user for review.

## Rules

- Do NOT modify the ViewSet in this step — that's step 4
- Do NOT modify existing tests — that's step 5
- The service must be importable and functional on its own (even though nothing calls it yet)
- Services must NOT import `request`, `Response`, or any DRF/HTTP objects
- Repositories must NOT contain business logic
- Use `from __future__ import annotations` for forward references
- Add `__all__` to `__init__.py` files
