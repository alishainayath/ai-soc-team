---
description: Run the full SOC team investigation on a scenario folder
argument-hint: scenarios/<folder-name>
---
Investigate the log file inside $ARGUMENTS as a SOC team.

Before starting, read playbook.md and lessons-learned.md. When you call each subagent, tell it to read both files first and follow them.

Use these subagents in order, passing each one the previous findings: data-masker, triage-analyst, threat-intel, incident-responder, report-writer, soc-manager.

The data-masker must save masked.log inside $ARGUMENTS. The report-writer must save the report in the reports folder, named after the scenario folder followed by -report.md (for example, scenarios/01-bruteforce becomes reports/01-bruteforce-report.md).

At the end, give:
1. A 3-line summary: what happened, severity, and the SOC manager's verdict.
2. Up to 3 suggested lessons for lessons-learned.md, based on any mistakes the SOC manager found. Do not edit lessons-learned.md yourself.
