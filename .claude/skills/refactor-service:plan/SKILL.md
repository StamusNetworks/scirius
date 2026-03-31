---
name: refactor-service:plan
description: "Step 2/5: Produce a detailed refactoring plan for service extraction from a ViewSet."
argument-hint: "<viewset-file-or-class>"
user-invocable: true
---

# Refactor Plan (Step 2/5)

Produce a detailed, actionable refactoring plan based on the analysis from step 1. `$ARGUMENTS` is the ViewSet file or class name.

This is step 2 of the `/refactor-service` pipeline, but can also be invoked standalone as `/refactor-service:plan` (will run analysis first if needed).

## Process

1. **If no analysis exists yet**, run the `/refactor-analyze` process first.

2. **Decide what moves where**:
   - Methods with business logic → Service
   - Non-trivial queryset building, filtering, aggregation → Repository
   - HTTP concerns (request parsing, response building, permissions) → Stay in ViewSet
   - Simple CRUD with no extra logic → Stay in ViewSet (no service needed)

3. **Design the service interface**:

   ```
   ## Service: <Name>Service

   ### Constructor
   __init__(self, <repo>: <Repo>, <other_service>: <OtherService>, ...)

   ### Methods
   - create_<thing>(*, field1: type, field2: type) -> Model
     Extracted from: ViewSet.create()
     Logic: <what it does>

   - delete_<thing>(pk: int) -> None
     Extracted from: ViewSet.destroy()
     Logic: <what it does, including pre-checks>
   ```

4. **Design the repository interface** (only if needed):

   ```
   ## Repository: <Name>Repository

   ### Methods
   - get_by_id(pk: int) -> Model
   - list_filtered(**kwargs) -> QuerySet
   - create(**kwargs) -> Model
   ```

5. **Plan the file changes**:

   ```
   ## File Changes

   ### New files
   - <app>/services/__init__.py
   - <app>/services/<name>.py — <Name>Service class
   - <app>/repositories/__init__.py (if needed)
   - <app>/repositories/<name>.py (if needed)

   ### Modified files
   - <app>/api/<file>.py — Slim down <ViewSet> to use service

   ### Test files
   - <app>/tests/pytest_<name>_service.py — New service unit tests
   - <app>/tests/pytest_<name>_repo.py — New repo tests (if repo created)
   - <app>/tests/<existing_test>.py — Should still pass unchanged
   ```

6. **Define the execution order**:
   1. Create service (+ repo) files
   2. Verify service compiles and lint passes
   3. Modify ViewSet to use service
   4. Verify existing tests still pass
   5. Add service-level tests

7. **Output the plan** for user review.

## Rules

- Do NOT write any code — this step produces a plan only
- Be explicit about method signatures, including type hints
- If some methods are too simple for a service, say so — don't force the pattern
- Flag any breaking changes or migration risks
- Consider backwards compatibility: the API contract must not change
