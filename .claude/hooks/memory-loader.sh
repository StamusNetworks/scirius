#!/bin/bash
# SessionStart hook: loads persistent memory index as additional context.
# Reads .claude/memory/index.yaml and injects it via additionalContext.

INPUT=$(cat)

# Determine project dir
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
INDEX_PATH="$PROJECT_DIR/.claude/memory/index.yaml"

if [ ! -f "$INDEX_PATH" ]; then
  exit 0
fi

CONTENT=$(cat "$INDEX_PATH")

# Skip if topics list is empty (seed content with no entries)
if echo "$CONTENT" | grep -q "^topics: \[\]"; then
  exit 0
fi

# 4KB size cap: truncate if the file exceeds 4096 bytes
FILE_SIZE=$(wc -c < "$INDEX_PATH" | tr -d ' ')
if [ "$FILE_SIZE" -gt 4096 ]; then
  CONTENT=$(head -c 4096 "$INDEX_PATH")
  CONTENT="${CONTENT}
...
[Memory index truncated — $(( FILE_SIZE - 4096 )) bytes omitted. Use /recall to search for specific topics.]"
fi

ESCAPED=$(echo "$CONTENT" | jq -Rs .)

echo "{\"hookSpecificOutput\":{\"hookEventName\":\"SessionStart\",\"additionalContext\":${ESCAPED}}}" | jq .

exit 0
