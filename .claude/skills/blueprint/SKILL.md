---
name: blueprint
description: Generate a structured YAML plan for multi-step implementation tasks.
argument-hint: "<goal description>"
user-invocable: true
tags: [universal]
---

# Blueprint

Generate a structured YAML plan for the given goal. The plan will be executed by an external orchestrator (`bun run plan-run <plan-file>`) that invokes Claude per-task, runs configurable checks, retries on failure, and commits on success.

## Process

1. **Understand the goal**: Read and analyze `$ARGUMENTS`. Explore the codebase to understand the current state, relevant files, patterns, and conventions.

2. **Identify checks**: Determine which validation commands should run after each task. Look at the project's package.json scripts, Makefile, CI config, etc. Common checks include linting, type-checking, and testing. These must be commands that return exit code 0 on success.


3. **Ripple analysis — what else is affected?** Before writing any tasks, trace the full impact of the change:
   - **Grep for references**: Search for every type, function, constant, schema, and pattern you plan to modify. Who calls it? Who imports it? Who documents it?
   - **Check for parallel representations**: If you're changing a data structure, look for schemas, validation, serialization, documentation, skills, templates, and tests that describe the same shape. All of them need updating.
   - **Walk the boundaries**: If the change crosses a boundary (library → CLI, type → YAML file, code → documentation), check both sides.
   - **Ask yourself**: "If I only did the obvious tasks, what would break or become stale?" List those things explicitly.
   - **Flag uncertainty to the user**: If you find something that MIGHT need updating but you're not sure, say so before writing the plan. Better to ask than to miss it.

4. **Break the work into steps and tasks**:
   - **Steps** are logical groupings (e.g. "Setup", "Core logic", "Tests").
   - **Tasks** are atomic units of work. Each task runs in a **fresh Claude session** with no prior context, so every task prompt must be **self-contained** — include all necessary context, file paths, function signatures, and conventions.
   - Each task should produce changes that pass all checks independently.
   - Keep tasks small enough that checks can validate them, but large enough to be meaningful.

5. **Write self-contained task prompts**: Each prompt must include:
   - What to do (specific, actionable instructions)
   - Where to do it (exact file paths)
   - How to do it (patterns to follow, functions to use, conventions to respect)
   - What NOT to do (common pitfalls for this codebase)

6. **Write the plan file**: Write the YAML plan to `.claude/plans/<descriptive-name>.yaml` using the Write tool.
   - The file MUST be written to the `.claude/plans/` directory (create it if it doesn't exist)
   - Use a short, kebab-case name derived from the goal (e.g. `add-auth.yaml`, `refactor-api.yaml`)
   - Do NOT just output the YAML in the conversation — it must be a file on disk
   - The file will be executed via: `bun run plan-run .claude/plans/<name>.yaml`

Use this exact schema:

```yaml
goal: "<one-line description of what we're building>"
checks:
  - name: <check-name>
    command: "<shell command that exits 0 on success>"
steps:
  - name: "<step name>"
    tasks:
      - id: "<step.task>"
        summary: "<short task description — used as context for auto-generated commit messages>"
        prompt: |
          <self-contained instructions for a fresh Claude session>
        files: [optional/list/of/relevant/files.ts]
        # done: true — set automatically by plan-run on completion, do not set manually
```

## Rules

- The plan MUST be written to `.claude/plans/<name>.yaml` — never output it inline.
- Task IDs must be hierarchical: `1.1`, `1.2`, `2.1`, etc.
- Task prompts must be self-contained — assume no prior context from earlier tasks.
- The `files` field is optional hints for Claude to read first, not a restriction.
- Check commands must work from the project root.
- The `summary` field is a short description used as context when auto-generating commit messages — keep it concise and descriptive.
- Do NOT set `done: true` on tasks — `plan-run` sets this automatically when a task passes all checks. On re-run, tasks with `done: true` are skipped.

