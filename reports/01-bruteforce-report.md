# Incident Report: SSH Brute Force Leading to Account Compromise and Credential File Access

| Field | Value |
|---|---|
| Report ID | 01-bruteforce |
| Report date | 2026-10-30 |
| Incident date | 2026-10-28, 02:14:03 – 02:16:02 (timezone not recorded in log) |
| Data source | `scenarios/01-bruteforce/masked.log` (10 lines, masked copy) |
| Affected host | Not identified (no hostname in log) |
| Affected account | USER_1 (masked) |
| Final severity | **CRITICAL** |
| Status | Open, response actions pending |

**How to read this report:** Statements are labeled **[FACT]** when the log shows them directly, and **[INFERENCE]** when they are analyst interpretation or hypothesis. Anything marked **UNVERIFIED** has not been checked against an authoritative source.

---

## 1. Executive Summary

On 2026-10-28, starting at 02:14:03, an external IP address (185.220.101.47) made a short, automated password-guessing attack against the SSH service on one host. It tried six passwords in 12 seconds across three accounts (`admin`, `root`, `USER_1`). On its seventh attempt (02:14:15) it logged in successfully as **USER_1**. **[FACT]**

About 85 seconds later, the attacker's session used `sudo` to run `/bin/cat /etc/shadow` as root. **[FACT]** No denial was logged, so sudo appears to have allowed the command. **[INFERENCE]** The log does not show whether the password hashes were actually returned. The external session ended at 02:16:02, about 1 minute 47 seconds after login. **[FACT]** The log has no entries after that time.

One more entry (line 9, 02:15:52) records an SSH connection from an internal address (INTERNAL_IP_1) tied to USER_1. Its meaning is unclear and it has **not** been confirmed as attacker activity (see Section 7).

**Bottom line:** This is a confirmed account takeover from the internet, followed by an attempt at root-level credential theft. Until proven otherwise, every password hash on the affected host should be treated as exposed. Severity is **CRITICAL**. The priority actions are to capture evidence, isolate the host, block the source IP, disable USER_1, and reset all credentials stored on the host.

---

## 2. Severity

**Final severity: CRITICAL**

Reasons:
1. **Confirmed compromise [FACT]:** a valid account (USER_1) was logged into successfully from an external IP right after scripted password guessing.
2. **Privilege abuse [FACT]:** the compromised session ran a root-level `sudo` command against `/etc/shadow`. No denial was logged, so it was likely permitted. **[INFERENCE]**
3. **Credential exposure [INFERENCE]:** if the read succeeded, the attacker holds the hashes of every local account, including root, and can crack them offline.
4. **Visibility gap [FACT]:** the log stops at 02:16:02, and it has no PAM session lines or command auditing. Persistence or other activity cannot be ruled out.

**Downgrade criteria:** Severity may drop to **High**, and no lower, only if both of these are true: (a) forensic evidence proves the `/etc/shadow` read failed or returned no data, and (b) a persistence hunt on the host comes back clean.

---

## 3. Timeline of Events

All times are from the log, 2026-10-28. The timezone is not recorded.

| Log line | Time | Event | Basis |
|---|---|---|---|
| 1 | 02:14:03 | Failed password for `admin` from 185.220.101.47 port 51122 (sshd PID 2211) | FACT |
| 2 | 02:14:05 | Failed password for `admin` from 185.220.101.47 port 51124 (PID 2213) | FACT |
| 3 | 02:14:07 | Failed password for `root` from 185.220.101.47 port 51126 (PID 2215) | FACT |
| 4 | 02:14:09 | Failed password for `root` from 185.220.101.47 port 51128 (PID 2217) | FACT |
| 5 | 02:14:11 | Failed password for `USER_1` from 185.220.101.47 port 51130 (PID 2219) | FACT |
| 6 | 02:14:13 | Failed password for `USER_1` from 185.220.101.47 port 51132 (PID 2221) | FACT |
| 7 | 02:14:15 | **Accepted password for `USER_1`** from 185.220.101.47 port 51134 (PID 2223). This was the 7th attempt overall and the 3rd against USER_1. | FACT |
| 8 | 02:15:40 | **`sudo`**: USER_1, TTY=pts/0, PWD=/home/USER_1, USER=root, COMMAND=`/bin/cat /etc/shadow` | FACT (command run). Allowed by policy: INFERENCE (no denial logged). Linking pts/0 to the external session: INFERENCE. Output and success: UNKNOWN |
| 9 | 02:15:52 | `sshd[2228]: Connection from INTERNAL_IP_1 port 60211 by USER_1`. Inbound to this host. No Accepted/Failed line follows, and the line format is not standard sshd. | FACT (line exists). Meaning: UNKNOWN, see Section 7 |
| 10 | 02:16:02 | Received disconnect from 185.220.101.47 port 51134 (PID 2230). Session length about 1m47s. | FACT |
| - | after 02:16:02 | No further log entries | FACT (gap) |

**Observed patterns (lines 1–7) [FACT]:** attempts were exactly 2 seconds apart, and source ports went up by exactly 2 each time (51122 to 51134). Two attempts were made per account.
**Interpretation [INFERENCE]:** this is an automated or scripted tool using a short list of candidate passwords. Getting in on the third USER_1 attempt points to a weak, guessable, reused, or previously leaked password.

---

## 4. Indicators of Compromise

| Type | Indicator | Context | Confidence |
|---|---|---|---|
| IPv4 (external) | `185.220.101.47` | Source of all brute-force attempts and of the successful USER_1 login. Source ports 51122–51134. The compromised session used port 51134. | High (FACT) |
| IP range | `185.220.101.0/24` | Possibly a Tor exit node range. **UNVERIFIED.** No reputation lookup has been done. | Low / UNVERIFIED |
| Account | `USER_1` | Compromised. Successful attacker login at 02:14:15. | High (FACT) |
| Account | `admin`, `root` | Targeted but not breached according to the log (2 failures each). | High (FACT) |
| Command | `sudo /bin/cat /etc/shadow` (as root, TTY pts/0, 02:15:40) | Credential file access | High that it was run. Success unconfirmed. |
| Process IDs | sshd 2211, 2213, 2215, 2217, 2219, 2221, 2223, 2228, 2230 | For correlating with host forensics | FACT |
| Internal IP | `INTERNAL_IP_1` port 60211 (line 9) | **Lead only, not a confirmed IOC.** Its relationship to the attack is unknown. | Unknown |
| Behavioral | Fixed 2 s interval between attempts, source port +2 each attempt, fail-then-success from one IP | Detection signature for the tool | Medium |

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence (log line) | Confidence |
|---|---|---|---|
| Credential Access | **T1110.001** Brute Force: Password Guessing | Lines 1–7: repeated passwords against 3 accounts from one IP | High |
| Credential Access | T1110.003 Password Spraying (alternative) | Several accounts tried, but only 2 attempts each | Low |
| Credential Access | T1110.004 Credential Stuffing (alternative) | Success on the 3rd try could mean a leaked credential was used | Low |
| Initial Access / Persistence | **T1133** External Remote Services | SSH reached from an external IP (line 7) | High |
| Initial Access / Defense Evasion / Persistence / Privilege Escalation | **T1078** Valid Accounts (.003 Local Accounts if USER_1 is local, otherwise sub-technique unknown) | Line 7: logged in with USER_1's valid password | High |
| Execution | T1059.004 Command and Scripting Interpreter: Unix Shell | Interactive pts/0 session (line 8) | Medium (inferred) |
| Privilege Escalation / Defense Evasion | **T1548.003** Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Line 8: sudo to root | Medium |
| Credential Access | **T1003.008** OS Credential Dumping: /etc/passwd and /etc/shadow | Line 8: `cat /etc/shadow` | High that it was attempted. Success unconfirmed. |
| Lateral Movement | T1021.004 Remote Services: SSH | Line 9 only. **Hypothesis only, not asserted.** | Low |

**Considered and not mapped, because the log does not show them:** T1110.002 Password Cracking (offline cracking of the hashes is possible later but not observed), T1098.004 SSH Authorized Keys, T1136.001 Create Local Account.

---

## 6. Impact

**Confirmed [FACT]:**
- An external party gained interactive SSH access as USER_1 for about 1m47s.
- A root-privileged command targeting `/etc/shadow` was run in USER_1's sudo context.

**Probable / potential [INFERENCE]:**
- **Credential exposure:** every local account hash on the host, including root, may now be in attacker hands and open to offline cracking. Any password reused elsewhere (for example a shared root or admin password) puts other systems at risk.
- **Effective root compromise:** USER_1 had sudo rights broad enough to run `cat /etc/shadow` as root, so the attacker could probably have run other root commands too. The log does not show any.
- **Persistence:** cannot be ruled out because of the visibility gap after 02:16:02 and the lack of command auditing.
- **Personal data / privacy:** USER_1 is a real person whose account was misused. Exposure of credential data may trigger notification obligations (to be assessed by Legal/Privacy).
- **Host criticality and business impact:** unknown. The host is not identified in the log.

---

## 7. Note on Log Line 9

`2026-10-28 02:15:52 sshd[2228]: Connection from INTERNAL_IP_1 port 60211 by USER_1`

- **[FACT]** The line records an inbound connection *to this host* from an internal (RFC1918) address, associated with USER_1, while the external session was still active.
- **[FACT]** No Accepted or Failed authentication line follows it. The format does not match standard OpenSSH log messages.
- **Not lateral movement.** The line does not show the attacker moving from this host to another system. Possible explanations include a legitimate connection by the real USER_1, a monitoring or automation system, a connection through some internal relay, or a logging artifact. None of these has been confirmed.
- **Action:** treat INTERNAL_IP_1 as an investigative lead (see P0 action 6).

---

## 8. Recommended Response Actions (Prioritized)

### P0: Immediate (0–1 hour)
| # | Action | Owner |
|---|---|---|
| 1 | Capture evidence before making changes: memory, full disk or volatile data, all logs (auth, sudo, journal, shell history, auditd if present). | IR |
| 2 | Isolate the host from the network. **Keep it powered on** to preserve volatile evidence. | NetSec + IR |
| 3 | Block 185.220.101.47 at the perimeter. Consider a temporary block of 185.220.101.0/24. | NetSec |
| 4 | Disable USER_1 locally and in the directory. Kill active sessions. Revoke SSH keys and tokens. | IAM + SysAdmin |
| 5 | Contact the real USER_1 out of band (not by email on possibly compromised systems) to confirm whether they recognize the login and the line 9 connection. | IR |
| 6 | Identify the host behind INTERNAL_IP_1 and pull its logs for 02:10–02:30. Isolate it if anything looks suspicious. | IR + NetSec |

### P1: Short term (1–24 hours)
| # | Action | Owner |
|---|---|---|
| 7 | Search the whole environment (30+ days) for any activity from 185.220.101.47 / the /24, and for unusual USER_1 logins. | IR |
| 8 | Reset passwords for **every account in the host's /etc/shadow**, root first. Rotate any reused credentials, plus service credentials, API keys, and SSH keys on the host. | IAM + SysAdmin |
| 9 | Check whether root or admin passwords are shared across other hosts, and rotate them wherever they are. | SysAdmin |
| 10 | Hunt for persistence: authorized_keys, new accounts, cron/systemd, sudoers changes, modified binaries, shell rc files. | IR |
| 11 | Review auditd/EDR telemetry for pts/0, 02:14:15–02:16:02. Determine whether the shadow read succeeded and what else ran. | IR |
| 12 | Verify IP reputation and possible Tor exit status for 185.220.101.47 (currently **UNVERIFIED**). | Threat Intel |
| 13 | Review why USER_1 had sudo rights that allowed reading /etc/shadow. | SysAdmin |

### P2: Remediation (1–3 days)
| # | Action |
|---|---|
| 14 | Rebuild the host from a known-good image. Restore data only from backups taken before 2026-10-28 02:14, or from backups that have been verified clean. |
| 15 | Harden SSH: `PasswordAuthentication no`, `PermitRootLogin no`, `AllowUsers`/`AllowGroups`, access only through VPN or a bastion host, rate limiting or fail2ban. |
| 16 | Apply least-privilege sudo rules (no blanket root, no access to credential files). |
| 17 | Re-issue USER_1's credentials with MFA, after the account owner's identity has been verified. |
| 18 | Run enhanced monitoring for 30 days on the host, USER_1, and related accounts. |

### P3: Longer term (1–2 weeks)
| # | Action |
|---|---|
| 19 | Build SIEM detections: failures followed by success from the same IP; sudo access to /etc/shadow; logins from Tor or anonymizer ranges. |
| 20 | Find every internet-facing SSH host that still allows password authentication. |
| 21 | Close logging gaps: central log forwarding, auditd execve logging. Find out why the log ends at 02:16:02 and why line 9 is in a non-standard format. |
| 22 | Legal/Privacy to assess whether notification is required. |
| 23 | Hold a post-incident review and record lessons learned in the playbook. |

---

## 9. Open Questions

1. Did `cat /etc/shadow` succeed and return hashes?
2. What other commands ran on pts/0 between 02:14:15 and 02:16:02?
3. What is INTERNAL_IP_1, and what does line 9 actually record?
4. Why does the log end at 02:16:02? Was logging stopped or tampered with, or was this just where the extract was cut?
5. Was USER_1's password weak, reused, or previously leaked? Does the account owner recognize the 02:14:15 login?
6. Is 185.220.101.47 a known Tor exit or known-malicious address? Did it touch other hosts?
7. Is the root password hash shared with other systems?
8. Why did USER_1 have sudo rights that allowed reading /etc/shadow?
9. Was any persistence established?
10. What is the host, and how critical is it to the business?

---

## 10. Data Handling and Process Notes

- **Playbook check:** `playbook.md` was read before writing this report. It currently contains only a Lessons Learned template with no entries ("(none yet)"), so no prior lessons applied. `lessons-learned.md` does not exist.
- **Masking:** this report was written from the masked log only (`scenarios/01-bruteforce/masked.log`). The raw `auth.log` was not opened by the report writer. The real username is replaced with **USER_1** (6 log lines, including the `/home/USER_1` path). The private 192.168.0.0/16 address is replaced with **INTERNAL_IP_1**. The generic accounts `root` and `admin`, and the external attacker IP 185.220.101.47, were left unmasked on purpose. The log contained no hostnames.
- **Verification:** the timeline, line numbers, ports, and PIDs in this report were checked line by line against the masked log.
- **Inputs:** this report combines findings from the Data-masker, Triage, Threat-intel, and Incident-responder stages.
- **Limitations:** the timezone is not recorded. The data set is 10 lines with no PAM session records and no command auditing. The IP reputation is **UNVERIFIED**.
