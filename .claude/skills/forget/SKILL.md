---
name: forget
description: Remove outdated or incorrect entries from persistent memory.
argument-hint: "<keyword or topic to prune>"
user-invocable: true
---

# Forget

Remove outdated, incorrect, or unwanted entries from persistent memory.

## Process

1. **Get the target**: Use `$ARGUMENTS` as the keyword or topic to prune. If `$ARGUMENTS` is empty, ask the user what they'd like to forget.

2. **Search for matches**:
   - Read `.claude/memory/index.yaml` for topic-level matches.
   - Use Grep to search `.claude/memory/topics/` for the keyword (case-insensitive).

3. **Show matches to the user**: Present all matching entries with enough context to identify them. Ask which ones to remove.

4. **Remove selected entries**:
   - Delete the matching entries from their topic files.
   - If a topic file becomes empty after removal, delete the entire file.

5. **Update `index.yaml`**: Remove topics that no longer have files, update summaries and tags for topics that still have entries.

6. **Commit** the changes with message: `memory: remove <brief description of what was forgotten>`
