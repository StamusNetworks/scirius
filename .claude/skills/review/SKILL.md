---
name: review
description: Perform a thorough code review of recent changes or specified files.
argument-hint: "[file-or-directory]"
user-invocable: true
---

# Code Review

Review the specified target (or recent git changes if none specified).

## Process

1. **Identify scope**: If `$ARGUMENTS` specifies files/directories, review those. Otherwise, run `git diff --name-only HEAD~1` to find recently changed files.

2. **Read the code**: Use Read and Grep to examine the files thoroughly.

3. **Evaluate against criteria**:
   - **Correctness**: Logic errors, edge cases, off-by-one errors
   - **Security**: Input validation, injection risks, exposed secrets
   - **Performance**: Unnecessary allocations, N+1 queries, missing indexes
   - **Readability**: Naming, structure, comments where non-obvious
   - **Maintainability**: DRY violations, tight coupling, missing abstractions



4. **Report findings** in this format:

### Critical Issues
Items that must be fixed before merging.

### Warnings
Items that should be addressed but are not blockers.

### Suggestions
Optional improvements for code quality.

### Summary
One-paragraph overall assessment.

