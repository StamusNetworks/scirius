---
name: remember
description: Save a learning or insight to persistent memory for future sessions.
argument-hint: "<what to remember>"
user-invocable: true
---

# Remember

Save a learning or insight to persistent memory so it persists across sessions.

## Process

1. **Get the learning**: Use `$ARGUMENTS` as the learning to capture. If `$ARGUMENTS` is empty, ask the user what they'd like to remember.

2. **Read the memory index**: Read `.claude/memory/index.yaml` to see existing topics and determine where this learning fits.

3. **Pick the right topic file**:
   - If an existing topic in `index.yaml` is a good fit, use that file.
   - Otherwise, create a new topic file at `.claude/memory/topics/<topic-name>.md` using kebab-case naming.

4. **Append a structured entry** to the topic file:

```markdown
### <Short descriptive title>
- **Date**: YYYY-MM-DD
- **Context**: What task or situation triggered this learning
- **Tags**: keyword1, keyword2

<Concrete, actionable description of the learning>
```

5. **Update `index.yaml`**: Add or update the topic entry with `file`, `summary`, `tags`, and `updated` fields. Keep summaries to one line.

6. **Commit** the memory files with message: `memory: <brief description of what was remembered>`

## Guidelines

- Keep entries concrete and actionable — future you should be able to act on them
- Use specific tags that will help `/recall` find the entry later
- One entry per learning — don't bundle unrelated things
- If a topic file is getting long (>20 entries), consider splitting it
