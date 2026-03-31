---
name: refactor-service:analyze
description: "Step 1/5: Analyze a ViewSet's business logic, dependencies, and side effects before refactoring."
argument-hint: "<viewset-file-or-class>"
user-invocable: true
---

# Refactor Analyze (Step 1/5)

Read-only analysis of a ViewSet to prepare for service extraction. `$ARGUMENTS` is the ViewSet file or class name.

This is step 1 of the `/refactor-service` pipeline, but can also be invoked standalone as `/refactor-service:analyze`.

## Process

1. **Find and read the ViewSet**. If `$ARGUMENTS` is a class name, search for it.

2. **Read all related files**:
   - Serializers used by the ViewSet
   - Models referenced
   - URL configuration (router registration)
   - Existing tests for this ViewSet
   - Any utilities/helpers called by ViewSet methods

3. **Check for existing patterns**: Look for any `services/` or `repositories/` directories in the same app or other apps to follow established conventions.

4. **For each ViewSet method**, document:

   | Method | Business Logic | Side Effects | Dependencies | Complexity |
   |--------|---------------|--------------|--------------|------------|
   | `create` | Validates categories, links sources | UserAction log | Source model, Category model | Medium |
   | `destroy` | Checks if ruleset is in use | UserAction log, signals | Suricata model | High |

5. **Identify the dependency graph**: What does this ViewSet need from outside?
   - Other Django models (direct ORM access)
   - External services (Elasticsearch, Celery, file system, SSH)
   - Other app modules
   - Django settings

6. **Assess refactoring complexity**:
   - **Simple**: 1-2 methods with logic, no external deps → quick extraction
   - **Medium**: 3-5 methods, some external deps → straightforward but needs care
   - **Complex**: Many methods, heavy external deps, shared state → needs careful planning

7. **Output the analysis report** in this format:

   ```
   ## Analysis: <ViewSetName> (<app>/api/<file>.py)

   ### Overview
   <1-2 sentence summary>

   ### Method Breakdown
   <table from step 4>

   ### Dependencies
   - Models: ...
   - External: ...
   - Settings: ...

   ### Side Effects
   - UserAction: ... (methods X, Y)
   - Signals: ... (method Z)
   - Celery tasks: ...

   ### Existing Patterns
   <any service/repo patterns found in the codebase>

   ### Complexity Assessment
   <Simple/Medium/Complex> — <reasoning>

   ### Risks
   - <anything tricky or non-obvious>
   ```

## Rules

- This is a READ-ONLY skill — do not modify any files
- Be thorough: read the actual source code, don't guess based on method names
- Flag any methods that are too entangled to extract cleanly
- Note any circular dependencies between apps
