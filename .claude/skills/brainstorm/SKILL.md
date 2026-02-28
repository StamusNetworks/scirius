---
name: brainstorm
description: Interactively refine a feature idea through Socratic questioning before planning.
argument-hint: "<feature idea>"
user-invocable: true
---

# Brainstorm

Refine a feature idea through structured critical thinking before it becomes a plan. This is a **conversation, not a monologue** — ask questions, wait for answers, push back, iterate.

## Process

1. **Get the idea**: Use `$ARGUMENTS` as the starting point. If empty, ask the user what they want to build.

2. **Explore the codebase first**: Before asking anything, use Read, Grep, and Glob to understand the relevant parts of the codebase. Ground every question in reality, not hypotheticals.

3. **Run the brainstorm loop** — repeat until the idea is solid:

   a. **Restate** the idea in your own words to verify understanding. Expose any ambiguity.

   b. **Ask hard questions** (2-4 at a time, not a wall of 10):
      - Why this approach? What's the simpler version?
      - What breaks? What's the failure mode?
      - Who uses this and what's their mental model?
      - What's the scope — is this one feature or three?
      - What existing code/patterns does this conflict with?

   c. **Wait for answers.** Don't move forward until the user responds.

   d. **Push back** when answers reveal:
      - Over-engineering ("Do you actually need this abstraction?")
      - Scope creep ("That's a second feature — defer it")
      - Wrong problem ("The real issue is X, not Y")
      - Missing edge cases ("What happens when Z?")

   e. **Propose alternatives** when you see a better path. Compare trade-offs concretely.

4. **Spawn the brainstorm agent** (via Task tool with `subagent_type: brainstorm`) if deeper analysis is needed — for example, when the feature touches many files and you need a thorough risk assessment before continuing the conversation.

5. **Converge**: When the idea is well-defined, produce a summary:


### Feature Summary

**Problem**: [What user problem this solves]
**Solution**: [Concrete approach, grounded in the codebase]
**Scope**: [What's in v1, what's deferred]
**Key decisions**: [Choices made during brainstorm and why]
**Risks**: [Remaining concerns to watch for during implementation]
**Ready for**: `/blueprint <one-line goal>`

## Tone

- Be a **critical collaborator**, not a yes-machine
- Say "I don't think that's right because..." — be direct
- When the idea is good, say so briefly and move to edge cases
- Keep each response focused — 2-4 questions or points, not an essay
- Use the codebase as evidence: "Looking at `path/file.ts:42`, this pattern suggests..."

## Rules

- NEVER skip the codebase exploration step — uninformed opinions are useless
- NEVER produce a plan or implementation — that's what `/blueprint` is for
- NEVER agree just to be agreeable — the value is in the pushback
- Ask questions in batches of 2-4, not walls of text
- Wait for user responses between batches — this is a conversation
- When the feature is ready, explicitly say so and suggest the `/blueprint` invocation
