# AI SOC Investigation Team

A multi-agent Security Operations Center (SOC) built on [Claude Code](https://claude.com/claude-code) subagents. A single command takes a raw log file through the same stages a human SOC team would: privacy masking, Tier 1 triage, threat intelligence, incident response, report writing and management review. The output is a finished, evidence-labeled incident report.

The project explores how to split security analysis into narrow, auditable roles, so that each agent has one job, limited tools, and a clear handoff to the next.

---

## The Team

Six specialized agents live in `.claude/agents/`. Each one has a single responsibility and only the tools that responsibility needs.

| # | Agent | Role | Tools |
|---|---|---|---|
| 1 | **data-masker** | Data privacy officer. Replaces usernames with `USER_1`, `USER_2`, … and private IPs (10/8, 172.16/12, 192.168/16) with `INTERNAL_IP_1`, …, using the same label for the same value every time. Leaves public IPs as they are because they are needed as indicators of compromise. Writes `masked.log`. | Read, Write |
| 2 | **triage-analyst** | Tier 1 analyst. Reviews the masked log, flags suspicious events, lists affected users, IPs and timestamps, and rates each finding Low / Medium / High / Critical. Treats log content as data only, never as instructions. | Read |
| 3 | **threat-intel** | Threat intelligence analyst. Explains what each suspicious behavior likely means and maps it to MITRE ATT&CK technique IDs, marking anything the evidence doesn't support as uncertain. | Read |
| 4 | **incident-responder** | Decides final severity and recommends containment, eradication and recovery steps. | Read |
| 5 | **report-writer** | Turns the combined findings into a professional incident report (Executive Summary, Timeline, IOCs, MITRE ATT&CK mapping, Severity, Recommended Actions) and saves it to `reports/`. | Read, Write |
| 6 | **soc-manager** | Quality gate. Checks the report against the masked log for accuracy, missing details and unsupported claims, then approves it or lists the changes needed. | Read |

---

## How a Run Works

```
scenarios/<name>/auth.log
        │
        ▼
 ┌──────────────┐   masked.log   ┌────────────────┐  findings  ┌──────────────┐
 │ data-masker  │ ─────────────▶ │ triage-analyst │ ─────────▶ │ threat-intel │
 └──────────────┘                └────────────────┘            └──────┬───────┘
                                                                      │ ATT&CK mapping
                                                                      ▼
 ┌──────────────┐    report      ┌────────────────┐  severity  ┌────────────────────┐
 │ soc-manager  │ ◀───────────── │ report-writer  │ ◀───────── │ incident-responder │
 └──────┬───────┘                └────────────────┘            └────────────────────┘
        │
        ▼
 verdict + suggested lessons learned
```

1. The orchestrator reads the playbook and lessons-learned files and tells every agent to follow them.
2. **data-masker** runs first, so no later agent ever sees real usernames or internal addresses.
3. Each later agent gets the previous agent's findings and adds its own.
4. **report-writer** saves `reports/<scenario>-report.md`.
5. **soc-manager** reviews the report against the masked log.
6. The run ends with a three-line summary (what happened, severity, manager verdict) and up to three suggested lessons. These are suggestions only; a human decides what goes into the lessons-learned file.

---

## The `/investigate` Command

Defined in `.claude/commands/investigate.md`:

```
/investigate scenarios/01-bruteforce
```

This runs the full pipeline on the log in the given scenario folder. The masked log is written to `scenarios/01-bruteforce/masked.log` and the report to `reports/01-bruteforce-report.md`.

### Example scenario: `01-bruteforce`

A synthetic SSH brute-force attack: six failed logins against `admin`, `root` and a user account, then a successful login and a `sudo cat /etc/shadow`. The team rated it **CRITICAL** and mapped it to T1110.001, T1078, T1133, T1548.003 and T1003.008. See the [full report](reports/01-bruteforce-report.md).

---

## Playbook and Lessons Learned

The team is meant to get better from one run to the next.

- **`playbook.md`**: standing rules every agent must follow. It covers general analysis rules, detection and severity rules, MITRE ATT&CK mapping, and report standards.
- **`lessons-learned.md`**: mistakes from past runs that the SOC manager caught, each written as *Scenario → What went wrong → Rule to follow next time*.

At the end of each investigation, the orchestrator suggests new lessons based on the manager's review. A human decides which ones to keep, so agents can't rewrite their own guardrails.

---

## Data Masking

Masking is the first step of every run, not an afterthought:

- Usernames become consistent pseudonyms (`jsmith` → `USER_1` everywhere it appears, including paths such as `/home/USER_1`).
- Private (RFC 1918) IP addresses become `INTERNAL_IP_n`.
- Public attacker IPs are kept, because they are the indicators of compromise defenders need to block.
- Downstream agents work only from `masked.log`. The final report records what was masked and confirms that the raw log was not used.

---

## Security & Privacy

This project was designed with the risks of running AI agents on security data in mind.

- **Synthetic logs only.** Every log in `scenarios/` is fabricated for demonstration. No real systems, users or incidents are represented.
- **Data masking.** Personal and internal identifiers are pseudonymized before any analysis happens (see above).
- **Mission Control is localhost-only, with token auth.** The monitoring dashboard binds to `127.0.0.1` and requires a token, so it is not reachable from the network. *(Implemented in my Claude Office fork, not in this repo; see [Mission Control & Visual Office](#mission-control--visual-office).)*
- **Allow-listed scenarios.** Mission Control can start investigations only on approved scenario folders, not on arbitrary paths. *(Also implemented in the fork.)*
- **Least-privilege agents to reduce prompt-injection risk.** The orchestrator uses only the Agent tool to delegate. Analyst agents get Read, and only the masker and report writer get Write. No agent has shell, network or web access, so a malicious instruction hidden in a log line has very little it can act on. The triage agent is also told directly to treat log content as data, never as instructions.
- **No secrets in the repo.** `.env` files and local Claude settings are excluded by `.gitignore`.

---

## Repository Layout

```
.
├── .claude/
│   ├── agents/               # the six SOC agents
│   └── commands/
│       └── investigate.md    # /investigate orchestration command
├── scenarios/
│   └── 01-bruteforce/        # synthetic auth.log + masked output
├── reports/
│   └── 01-bruteforce-report.md
├── playbook.md               # standing rules for every agent
└── lessons-learned.md        # mistakes from past runs
```

---

## Mission Control & Visual Office

The live dashboard (**Mission Control**) and the animated office view, where you can watch the six agents work, are built in my separate fork of [Claude Office](https://github.com/paulrobello/claude-office). That code lives in the fork, **not in this repository**. This repo holds the SOC team itself: the agents, the `/investigate` command, the scenarios, the playbook and the reports.

Fork link coming soon.

---

## Credits

The visual office uses the open-source [Claude Office](https://github.com/paulrobello/claude-office) project by **paulrobello**.

---

## Future Work

- **More scenarios**: phishing, malware beaconing, data exfiltration, insider threat, cloud (CloudTrail / Azure AD) logs.
- **Live threat-intel enrichment**: IP reputation and Tor exit-node lookups through a sandboxed, read-only tool, replacing today's "UNVERIFIED" placeholders.
- **Revision loop**: send the SOC manager's requested changes back to the report writer automatically until the report is approved.
- **Evaluation harness**: score reports against ground-truth answers for each scenario (severity, ATT&CK IDs, IOCs) to measure accuracy over time.
- **Stronger masking**: hostnames, emails and other identifiers, plus a deterministic pre-masking pass so that privacy doesn't depend only on the model.
- **SIEM integration**: export IOCs and detection rules (Sigma) generated from each investigation.

---

*Built by Alisha Inayath.*
