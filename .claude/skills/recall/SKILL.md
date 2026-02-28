---
name: recall
description: Search persistent memory for past learnings related to a keyword or topic.
argument-hint: "<keyword or topic>"
user-invocable: true
---

# Recall Memory

Search the project's persistent memory for past learnings related to `$ARGUMENTS`.

## Process

1. **Read the memory index**: Read `.claude/memory/index.yaml` for an overview of all captured topics.

2. **Search topic files**: Use Grep to search `.claude/memory/topics/` for `$ARGUMENTS` (case-insensitive). Also search for related terms and synonyms.

3. **Read matching files**: Read any topic files that contain matches or are related to the query based on the index.

4. **Synthesize**: Present the relevant learnings in a concise summary. Include:
   - The key findings and their context
   - When they were captured (dates)
   - Any caveats or conditions that apply
   - Links to the specific topic files for further reading

If no relevant memories are found, say so and suggest what keywords might exist based on the index.
