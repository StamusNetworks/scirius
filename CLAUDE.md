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
