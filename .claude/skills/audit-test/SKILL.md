---
name: audit-test
description: Audit test files for false-green tests — tests that pass but shouldn't.
argument-hint: "<test-file-or-directory>"
user-invocable: true
---

# Audit Test

Deep-analyze test files to find false-green tests — tests that pass but are actually testing broken behavior, testing nothing, or testing the wrong thing. `$ARGUMENTS` should be a test file or directory to audit.

## Context

This codebase has a known problem: many tests inherited from the unittest era are green but don't actually validate what they claim to. This skill exists to systematically find and report these before migration.

## Process

1. **Identify target files**: If `$ARGUMENTS` is a directory, find all test files (`test_*.py` and `pytest_*.py`). If it's a file, audit just that file.

2. **Read the test file(s)** and the corresponding source code being tested. Understanding what the code *should* do is essential to spotting false greens.

3. **For each test, check these anti-patterns**:

   **Missing or weak assertions:**
   - Test calls an endpoint but only checks status code, not response body
   - Test creates objects but never verifies they were persisted correctly
   - `assertEqual(len(qs), N)` without checking the actual objects
   - Assertions on mocked return values (testing the mock, not the code)

   **Tests that can't fail:**
   - Asserting on data created in `setUp` that doesn't go through the code path
   - Catching exceptions too broadly (`except Exception: pass`)
   - Mocking the function under test instead of its dependencies
   - Testing default/empty state that would pass even with no implementation

   **Wrong expectations:**
   - POST endpoint expected to return 200 (should be 201)
   - DELETE expected to return 200 (should be 204)
   - PUT/PATCH not checking the object was actually updated in DB
   - Permission tests that don't actually test with a restricted user

   **Stale tests:**
   - Tests referencing fields/endpoints that no longer exist (but pass because of broad exception handling)
   - Tests for features that were removed or rewritten
   - Assertions on deprecated response formats

   **Logic errors:**
   - `assertEqual(a, a)` — comparing something to itself
   - Asserting before the action (`self.assertEqual(count, 0)` before creating anything)
   - Testing the serializer output instead of the actual API response
   - `setUp` that swallows failures silently

4. **Classify each test**:
   - **GREEN-OK**: Test is correct, assertions are meaningful
   - **FALSE-GREEN**: Test passes but doesn't validate what it claims — explain why
   - **WEAK**: Test has some value but assertions should be strengthened
   - **DEAD**: Test is for removed/changed functionality

5. **Output a report** in this format:

   ```
   ## Audit: <filename>

   ### Summary
   - Total tests: N
   - GREEN-OK: N
   - FALSE-GREEN: N (list)
   - WEAK: N (list)
   - DEAD: N (list)

   ### FALSE-GREEN Details
   #### test_method_name (line NN)
   **Problem**: <what's wrong>
   **Evidence**: <why it can't actually fail / why it tests the wrong thing>
   **Fix**: <what the test should actually assert>
   ```

6. **Do NOT modify any files** — this skill is read-only analysis. Use `/migrate-test` to act on findings.

## Rules

- Read the source code being tested, not just the tests — you need to know what correct behavior looks like
- Be specific: "this test is weak" is not useful; "this test asserts status 200 but never checks that the ruleset was actually created in the database" is
- When in doubt, classify as WEAK rather than FALSE-GREEN
- Check if the test's setUp/fixtures create state that makes the test trivially pass
