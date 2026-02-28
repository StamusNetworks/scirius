#!/bin/bash
# PreToolUse hook: blocks dangerous Bash commands.
# Receives JSON on stdin with tool_name and tool_input.

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name')

if [ "$TOOL_NAME" != "Bash" ]; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

BLOCKED_PATTERNS=(
  'rm -rf /'
  'rm -rf ~'
  'rm -rf \.'
  ':(){:|:&};:'
  'mkfs\.'
  'dd if=/dev/zero'
  '> /dev/sd'
  'chmod -R 777 /'
)

for pattern in "${BLOCKED_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qE "$pattern"; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Blocked: potentially destructive command"}}' | jq .
    exit 0
  fi
done

exit 0
