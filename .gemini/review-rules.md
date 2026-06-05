# Gemini Code Review Guidelines

## Scope and Exclusions

### 1. Automated Backport Pull Requests
- **Rule:** Do not perform code reviews, generate summaries, or post comments on pull requests or merge requests that contain the phrase `autobackport` in the name of the pull request or branch.
- **Action:** If the name matches `*autobackport*`, immediately halt the automated review process and output a passive acknowledgment if required, without executing deep code analysis.

### 2. Contextual Exception
- Only provide a review on an `autobackport` if explicitly and manually commanded by a user prompt tagging you directly. Otherwise, default to skipping the review entirely.
