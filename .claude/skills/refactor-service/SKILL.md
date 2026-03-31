---
name: refactor-service
description: "Pipeline: extract business logic from a ViewSet into controller/service/repo (runs step-by-step with human approval at each stage)."
argument-hint: "<viewset-file-or-class>"
user-invocable: true
---

# Refactor to Service — Pipeline Orchestrator

This is a multi-step refactoring pipeline. Each step runs as a subagent, produces a deliverable, and **pauses for your approval** before the next step begins. `$ARGUMENTS` should be a ViewSet file path or class name.

## Target Architecture

```
ViewSet (controller)    — HTTP concerns only: parse request, validate, call service, return response
    ↓
Service                 — Business logic: orchestrate operations, enforce rules, emit events
    ↓
Repository (optional)   — Data access: queryset building, filtering, aggregation
```

**Dependency injection**: Services receive dependencies (repositories, other services) via constructor, not imports.

## Pipeline Steps

Run these steps sequentially. After each step, **present the output to the user and wait for approval** before proceeding.

### Step 1: Analyze (`/refactor-service:analyze`)

Launch a **read-only Explore agent** to research the ViewSet and its dependencies. The agent should:
- Read the ViewSet, its serializers, models, URL config, and existing tests
- Map every method: what it does, what business logic it contains, what side effects it has
- Identify dependencies (other models, external APIs, Celery tasks, file I/O)
- List all `UserAction` audit log calls
- Check for existing service/repo patterns elsewhere in the codebase to follow

**Output**: A structured analysis report. Present it to the user.

**Human checkpoint**: User reviews the analysis, may correct understanding or add context.

### Step 2: Plan (`/refactor-service:plan`)

Based on the analysis (and any user corrections), produce a detailed refactoring plan:
- Which methods move to the service, which stay in the ViewSet
- Whether a repository is needed (only if non-trivial queryset logic exists)
- File paths for new files (`<app>/services/<name>.py`, `<app>/repositories/<name>.py`)
- Constructor signature for the service (what gets injected)
- Method signatures for each service method (inputs, return types)
- Which tests need updating and how
- Ordering: what to do first, what depends on what

**Output**: The refactoring plan as a structured document. Present it to the user.

**Human checkpoint**: User approves the plan, may request changes to scope or approach.

### Step 3: Extract service & repository (`/refactor-service:extract`)

Create the new files:
- `<app>/services/<name>.py` — Service class with DI constructor and business methods
- `<app>/repositories/<name>.py` — Repository class (only if planned)
- Add `__init__.py` to new directories if needed

Do NOT modify the ViewSet yet. The service should be a standalone module that can be tested independently.

Run `ruff check` and `mypy` on new files.

**Output**: Show the created files. Present to user.

**Human checkpoint**: User reviews the service/repo code before the ViewSet is touched.

### Step 4: Slim the ViewSet (`/refactor-service:slim`)

Now modify the ViewSet to use the service:
- Import and instantiate the service in `__init__` or as a class attribute
- Replace business logic in each method with a service call
- Keep HTTP concerns: request parsing, serializer validation, response building, permissions
- Keep `REQUIRED_GROUPS` on the ViewSet
- Move `UserAction` logging to the service

Run `ruff check` on the modified ViewSet.

**Output**: Show the diff of the ViewSet changes. Present to user.

**Human checkpoint**: User reviews the ViewSet changes before tests are touched.

### Step 5: Update tests (`/refactor-service:test`)

Write or update tests for the new structure:
- **Service tests** (`pytest_<name>_service.py`): Unit tests with mocked repos, no DB needed
- **Repository tests** (if repo was created): Thin DB integration tests
- **ViewSet tests**: Keep existing API-level tests, they should still pass unchanged

Run the full test suite for the app:
```bash
DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv --no-cov <app>/tests/
```

**Output**: Test results and any new test files. Present to user.

**Human checkpoint**: User verifies all tests pass and coverage is adequate.

## Rules

- NEVER skip a human checkpoint — each step must be approved before the next begins
- NEVER modify the ViewSet before the service is created and reviewed (step 3 before step 4)
- Keep the public API (URLs, request/response format) identical — this is an internal refactor
- Services must NOT import `request` or anything HTTP-related
- Repositories must NOT contain business logic
- Use type hints on all service and repository methods
- If a ViewSet method is simple CRUD with no extra logic, leave it — don't create a service just for `objects.create()`
- One ViewSet at a time — never refactor multiple ViewSets in a single pipeline run
