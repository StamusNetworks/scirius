## Repository Structure: Open Source / Closed Source Split

This repo contains both **open-source** and **closed-source (appliance)** code. A script (`tests/master-build.py`) builds the open-source version by cherry-picking commits from the `appliance` branch to the `master` branch, dropping any commit that only touches closed-source files.

### Branches

- **`appliance`** — Main development branch (closed source, contains everything)
- **`master`** — Open-source branch (subset of appliance, auto-built)
- **`staging-builder`** — Staging branch used for preparing builds

### Closed-source directories (appliance-only)

These paths are filtered out when building the open-source `master` branch:

- `appliances/`, `ui/app/appliance/`, `stamus-docs/`, `ui/cypress/`
- `tests/`, `debian/`, `ansible/`, `volumetry/`
- `.gitlab-ci-rf.yml`, `.gitlab-ci-cypress.yml`, `.gitlab-ci-manual-es6.yml`, `.gitlab-ci-always.yml`, `.gitlab-ci-manual.yml`, `.gitlab-ci-functests.yml`, `.gitlab-ci-docker.yml`, `.gitlab-ci-claude-review.yml`
- `.gitlab-test.sh`, `requirements-app.txt`, `requirements-base.txt`

Everything else is considered open-source code.

### Test conventions

- **Old-style tests**: `test_*.py` — Django `TestCase`/`APITestCase` classes (being migrated away)
- **New-style tests**: `pytest_*.py` — Plain pytest functions with fixtures (target pattern)
- **Functional tests**: `tests/functional/test_*.py` — Async httpx tests against a live server (replacing Cypress)
- File naming is intentional: `pytest_` prefix = modern pytest, `test_` prefix = legacy unittest

### Refactoring direction

The codebase is moving toward **controller/service/repository** with dependency injection:
- **ViewSets** (controllers) handle HTTP only: parse request, validate, call service, return response
- **Services** (`<app>/services/`) contain business logic, receive dependencies via constructor
- **Repositories** (`<app>/repositories/`) handle data access (only when non-trivial)

### Critical commit rule

**Never mix open-source and closed-source files in the same commit.** The build script (`tests/master-build.py`) will abort with an error if a commit touches files from both sides. When working on changes that span both:

1. Make one commit for the open-source changes
2. Make a separate commit for the closed-source (appliance) changes

This ensures the cherry-pick process can cleanly include or skip each commit.

---

## Development Commands

### Setup

```bash
uv venv
source .venv/bin/activate
uv pip install . .[dev] .[appliances]
```

### Running tests (pytest)

```bash
# Full test suite (parallel, 3 workers)
DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -n 3 --dist loadfile -vv

# Single file or test
DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv path/to/test_file.py
DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv path/to/test_file.py::TestClass::test_method

# Without coverage (faster)
DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv --no-cov

# Only unit tests (skip DB-dependent tests)
DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv -m no_db
```

`DS` is a shorthand env var for `DJANGO_SETTINGS_MODULE`. Tests require a running PostgreSQL instance (configure via `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_PORT` env vars).

### Linting (ruff)

```bash
# Check for issues
ruff check .

# Check specific files
ruff check path/to/file.py

# Auto-fix
ruff check --fix .

# Format code
ruff format .
```

Configuration is in `pyproject.toml` (`line-length = 120`, `target-version = "py311"`).

### Type-checking (mypy)

```bash
mypy path/to/file.py
```

---

<!-- hooks:memory:start -->

## Persistent Memory

This project uses a persistent memory system in `.claude/memory/`. Memories are committed to git and shared with the team.

### Skills

- **`/remember <learning>`** — Save a learning or insight to memory. Creates structured entries in topic files and updates the YAML index.
- **`/forget <keyword>`** — Remove outdated or incorrect entries from memory. Prunes topic files and updates the index.
- **`/recall <keyword>`** — Search memory for past learnings. Reads the index and grep topic files for matches.

### Structure

- `.claude/memory/index.yaml` — Structured YAML index of all topics (auto-loaded at session start)
- `.claude/memory/topics/<name>.md` — Detailed entries grouped by topic

### What to remember

- Debugging insights that took significant effort to discover
- Architectural decisions and their rationale
- Project-specific gotchas, quirks, or non-obvious behaviors
- Environment setup issues and their solutions
- Performance findings and optimization decisions
- Integration patterns with external services

### What NOT to remember

- Routine code changes or standard patterns
- Information already in the project's documentation
- Temporary workarounds that will be removed soon
- Personal preferences or style opinions


<!-- hooks:memory:end -->

<!-- hooks:workflow:start -->

## Workflow Standards

### Always Validate

- **Lint before committing**: Run the project's linter on changed files before every commit. Fix lint errors before proceeding — never commit code that doesn't pass lint.
- **Test after changes**: Run the relevant test suite after any non-trivial code change. If tests fail, fix them before moving on. Don't wait for the user to ask.
- **Type-check when available**: If the project has a type-checker, run it after structural changes.


### Use Agents Proactively

- **Delegate specialized work** to subagents via the Task tool when the work matches an agent's expertise. Don't do everything in the main conversation when a specialized agent would be more effective.
- **Run agents in parallel** when their tasks are independent — e.g., launch a security audit and a test strategy review simultaneously.
- **Use the Explore agent** for broad codebase research instead of many sequential Grep/Glob calls.


### Build Institutional Memory

- **Use `/remember` proactively** when you discover something non-obvious: a debugging insight, a gotcha, an architectural decision, or a tricky integration pattern. Don't wait to be asked.
- **Use `/recall` at session start** or when working in an unfamiliar area of the codebase to check if past sessions left relevant insights.
- **Use `/forget`** when you find outdated or incorrect entries in memory.

### Be Proactive

- **Fix adjacent issues** you notice while working — broken imports, dead code, obvious bugs — if the fix is small and safe. Mention what you fixed.
- **Suggest improvements** when you see patterns that could be better, but don't implement them without asking.
- **Run `/review` on your own changes** before presenting them to the user when the changes are substantial.

<!-- hooks:workflow:end -->
