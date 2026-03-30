# Copilot Workspace Instructions

- Mandatory QA gate: For every implementation iteration (any code or config change), run subagent "Quality Acceptance Controller" before finalizing the iteration.
- Report QA result in the response: include verdict and key risks/findings.
- If QA verdict is "Requires rework" or "Rejected", continue iterations until issues are resolved or explicitly waived by the user.
