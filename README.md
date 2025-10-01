
## LateralMovementAnalyzer.py 

### Purpose and Use Case

The `LateralMovementAnalyzer.py` script processes Windows event logs in the EvtxECmd CSV format to identify and correlate possible lateral movement activities via RDP or PowerShell remoting.  

Its purpose is to scan relevant events, group them into sessions, and output a CSV of those sessions for further analysis. The tool is designed for security professionals to get a quick analysis of lateral movements between hosts.  

Users should be aware that these cases may hide some lateral movement indicators, this script is meant to assist you during investigations and is not exhaustive.  

Its output can be fed into the accompanying `visualisation_mouvements.py` script to generate lateral movement graphs.

---

### CLI Usage and Arguments
The script requires only python standard libraries. 
Run the script from the command line with:

```bash
python lateralmovementanalyzer.py <input.csv> <output.csv> [options]
```

- `<input.csv>`: Path to an EvtxECmd-exported CSV file of Windows events.  
- `<output.csv>`: Path where the correlated sessions CSV will be written.  

Supported options (flags) include:

- `--includeAlldirections` – Include sessions with undetermined (“unknown”) direction in the output.  
- `--include_eid_4648` – Keep Event ID 4648 events (which are noisy and not conclusive by themselves) in the analysis. By default, 4648-derived sessions are skipped unless this flag is set.  
- `--only-ps` – Perform only PowerShell remoting correlation (skip RDP session detection).  
- `--only-rdp` – Perform only RDP session correlation (skip PowerShell remoting detection).  
- `--provider-filter-disabled` – Disable the default filter that restricts processed records to certain event providers (Terminal Services, WinRM, etc.)  

---
### Detection Logic

More details for each function can be found in each function's documentation in the script.  

#### RDP Sessions

RDP session correlation is handled by `correlate_rdp_sessions()`. It scans pre-filtered EvtxECmd rows and groups events that belong to the same RDP session.  

This function determines the session length and its associated events by aggregating events by keys that act as a session identifier.  

For each identified session key, the script aggregates all matching events to compute the earliest (`start_time`) and latest (`end_time`) timestamps, and collects relevant details (source/destination host, user, process ID, outcome status, etc.) into the session record.  

The `direction` field is set to “inbound” or “outbound” as determined; if unknown, the unknown sessions are dropped by default unless `--includeAlldirections` is specified.  

###### Inbound detection 


| Source log                                                   | Event IDs                          |
|---------------------------------------------------------------|------------------------------------|
| Security                                                     | 4624 (LogonType 10), 4778, 4779    |
| Microsoft-Windows-Terminal-Services-LocalSessionManager / Operational | 21, 22, 25, 40, 41          |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager   | 1149                               |
| Microsoft-Windows-RemoteDesktopServices-RdpCore              | 98, 131                            |

Inbound session keys rely on logon identifiers such as TargetLogonID, LogonID or SessionID.  

###### Outbound detection 


| Source log                                                   | Event IDs                          |
|---------------------------------------------------------------|------------------------------------|
| Microsoft-Windows-TerminalServices-RDPClient                 | 1024, 1102     |


Outbound session keys rely on process ID when available.  

###### Event ID 4648 

The Event ID 4648 is only processed when the argument `--include_eid_4648` is provided.  

- Machine account targets and localhost events excluded.  
- Events where it's the same source and destination are also excluded.  

Classified as outbound:  
- If the process is `mstsc`.  
- If the target information, server name or Remote host information exist and it's not localhost, the direction is considered as outbound.  

Classified as inbound: 
- If the process is `winlogon`, `svchost` or `lsass`.  
- If the target information, server name or remote host information exist, the direction is considered as outbound.  
- Otherwise, direction is considered unknown.  

---

#### PowerShell Remoting Sessions

PowerShell/WinRM remoting sessions are handled by `correlate_psremoting_sessions()`.  

The script watches for two key event types in WinRM operational channels:

- Event ID 91 (Inbound): Indicates an incoming WinRM session. The script extracts the user and client IP from the `resourceUri` field of the payload column (using a regex).  
- Event ID 6 (Outbound): Represents an outgoing WinRM connection. Here the script takes the source computer name and the target from the payload’s `connection` field.  


---

### Limitations

- **LogonType 3 and 7 Ignored:** Network-level logons (logon type 3, NLA) and RDP “reconnect” events (logon type 7) are not processed.  
- **Unknown Sessions Default Exclusion:** Sessions determined to have “unknown” direction are not output by default. They only appear if `--includeAlldirections` is specified.  
- **Localhost and Machine Accounts:** Events originating from or targeting localhost and machine-account targets (names ending with `$`) are discarded and not correlated.  
- **PS Remoting Session:** is only based on the WinRm journal.  

Many other improvements can be added to the project such as code improvement and refactoring, extending event and protocols coverage, multiple output format, integration with other tools, maintainability, adding process field, etc.  

---

### Python Version

The script does not require any external dependencies; it only uses Python's standard library.
Main version used for the dev: Python 3.13.3

---

### Output Format

| Column name   | Origin                                                                 |
|---------------|------------------------------------------------------------------------|
| `start_time`  | start of session time (earliest event)                                 |
| `end_time`    | end of session time                                                    |
| `direction`   | "inbound" or "outbound" or "unknown"                                   |
| `src`         | source IP or hostname                                                  |
| `dst`         | destination IP or hostname                                             |
| `sid`         | Security Identifier                                                    |
| `user`        | account name                                                           |
| `logon_id`    | RDP session identifier from Payload nested field (TargetLogonId, LogonId, SessionId) |
| `pid`         | Process ID of initiating process                                       |
| `server_name` | The target server name                                                 |
| `target_info` | TargetInfo from EID 4648                                               |
| `outcome`     | 'Success' or 'Failure' if status information available                 |
| `Events`      | Events used for correlation of the session                             |
| `providers`   | Windows logs used such as Security, System or TerminalServices-LocalSessionManager |
| `protocol`    | Protocol related to the session (RDP or Powershell remoting) | 

---
### Evtxecmd Usage
We use EvtxEcmd to process evtx files and retrieve the CSV output provided by the tool. 
You can find below examples of commands used for analyzing a repository of multiple event logs, or a single log file.  

```bash
.\EvtxECmd.exe -d "C:\Windows\System32\winevt\logs" --csv "locationoftheouputFile" --csvf FileName
```

```bash
EvtxECmd.exe" -f Security.evtx --csv "E:\outputrepository" - --csvf OutputNameFile.csv
```

Refer to EvtxECmd documentation for more information.  



