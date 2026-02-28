---
name: commit
description: Create a clean, well-structured git commit with automated pre-checks.
argument-hint: "[message-hint]"
user-invocable: true
---

# Commit

Create a git commit for staged or recent changes. If `$ARGUMENTS` is provided, use it as a hint for the commit message topic.

## Process

1. **Check for changes**: Run `git status` and `git diff --cached --stat`. If nothing is staged, look at unstaged changes and suggest what to stage. If `$ARGUMENTS` hints at specific files, stage those.

2. **Run pre-commit checks**: Before committing, run the project's lint and test commands to catch issues early.


3. **Review the diff**: Run `git diff --cached` (or `git diff` if nothing is staged) to understand what changed. Read modified files if needed for full context.

4. **Check for unrelated changes**: Analyze the diff for logically distinct units of work. Changes are unrelated if they have **different purposes** (e.g. a bug fix and a new feature, a refactor and a test addition, two independent features). Signs of unrelated changes:
   - Files in different subsystems with no shared motivation
   - Mix of conventional commit types (e.g. `fix:` + `feat:` + `test:`)
   - Changes that would need different commit messages to describe accurately

   If changes are unrelated:
   - Tell the user you've identified N distinct logical changes and list them briefly
   - Ask for confirmation before proceeding with multi-commit
   - Stage and commit each group separately, in a logical order (foundations first, dependents after)
   - Run pre-commit checks before each commit
   - Report all commits at the end

   If all changes are part of one logical unit, proceed normally with a single commit.

5. **Draft the commit message** following these rules:
   - Use imperative mood ("add feature" not "added feature")
   - First line under 72 characters
   - Separate subject from body with a blank line if body is needed
   - Focus on WHY the change was made, not just WHAT changed
   - **NEVER reference Claude, AI, assistant, language model, or any AI tool in the commit message** — the message must read as if written by the developer
   - **NEVER add `Co-Authored-By` lines referencing any AI**
   - Match the project's existing commit message style (check `git log --oneline -10`)


6. **Create the commit**: Use a HEREDOC to pass the message:
   ```bash
   git commit -m "$(cat <<'EOF'
   <commit message here>
   EOF
   )"
   ```

7. **Report**: Show the commit hash, message, and files changed. If multiple commits were created, show all of them.

## Rules

- NEVER mention Claude, AI, or any AI assistant in commit messages
- NEVER add Co-Authored-By lines for AI
- NEVER skip pre-commit hooks (no --no-verify)
- If lint or tests fail, fix the issues first and tell the user what was fixed
- Prefer staging specific files over `git add -A`
- Do not push unless explicitly asked
