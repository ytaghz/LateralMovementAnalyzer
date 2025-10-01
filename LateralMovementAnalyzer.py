#!/usr/bin/env python3
"""
lateralmovementanalyzer.py

Purpose
-------
Parse an EvtxECmd CSV export and correlate Windows events into RDP and/or PS Remoting sessions.
Produces a CSV containing the correlated sessions to help lateral movement investigations.

CSVs outputs can be provided as an input for the visualisation_mouvements.py script to produce visualisation graphs of lateral movements. 

Usage: 
    python lateralmovementanalyzer.py <input.csv> <output.csv> [options]
              Options 
               --includeAlldirections            : Include sessions with undetermined direction 
               -- include_eid_4648               : Include 4648 events that are noisy. 4648 events alone don't prove lateral movement but it can be useful for the correlation of outbound movements.
               --only-ps                         : output only PS-Remoting sessions (skip RDP correlation)
               --only-rdp                        : output only RDP sessions (skip PS correlation)
               --provider-filter-disabled        : disable provider-name filtering when reading CSV
              )
              
Output columns and their origins:
    start_time     - start of session time (earliest event)
    end_time       - end of session time
    direction      - "inbound" or "outbound" or "unknown"
    src            - source IP or hostname 
    dst            - destination hostname 
    user           - account name 
    logon_id       - RDP session identifier from Payload nested field (TargetLogonId, LogonId, SessionId)
    pid            - Process ID
    server_name    - targetServerName
    target_info    - TargetInfo from EID 4648 
    outcome        - 'Success' or 'Failure' if status information available (e.g., LogonStatus) 
    events         - Events used for correlation
    providers      - Windows logs used such as Security, System or TerminalServices-LocalSessionManager
    protocol       - Protocol related to the session (RDP or Powershell remoting)

                    
"""

import csv
import sys
import json
from datetime import datetime
import re


def load_evtx_csv(file_path, disable_provider_filter=False):

    """
    Read EvtxECmd CSV and return a list of filtered rows with parsed timestamps.
    The function expects EvtxECmd-style column names (EventId, Provider,
      TimeCreated, Payload, PayloadDataN, RemoteHost, Computer, etc.).

      - Keeps only rows whose EventId is in a configured list
      - By default filters on Provider keywords (TerminalServices, WinRM, etc.).
        This provider-based filter can be disabled via `disable_provider_filter`.

      - Parses the CSV `TimeCreated` value into a Python datetime.

    Note: Datetime truncates fractional seconds to 6 digits, while EVTX events may contain 7.  


    Parameters
    ----------
    file_path : str
        Path to the EvtxECmd CSV file.
    disable_provider_filter : bool, optional
        When True, skip provider keyword filtering; default False.

    Returns
    -------
    list[dic
        A list of CSV rows (dictionaries). Each dictionary represents a filtered and processed event record. 
        Each record includes a new key, '_timestamp', containing a datetime object.
     
    

    """

    records = []

    relevant_event_ids = {
        '4648', '4624', '4778', '4779', '40', '21', '22', '25', '41', '98', '131', '1149', '1024', '1102', '400','403','91', '6'
    }

    relevant_provider_keywords = {
        'TerminalServices', 'RemoteDesktopServices', 'Security', 'WinRM', 'Powershell'
    }
    with open(file_path, encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('EventId') not in relevant_event_ids:
                continue  

            provider = row.get('Provider','')
            if not disable_provider_filter:
                if not any(keyword in provider for keyword in relevant_provider_keywords):
                    continue
            
            raw_ts = row.get('TimeCreated', '')
            try:
                row['_timestamp'] = datetime.fromisoformat(raw_ts.replace('Z', '+00:00'))
            except Exception:
                row['_timestamp'] = None
            records.append(row)
    return records

def parse_payload_json(row):
    """
    Parse the Payload field of a Evtxecmd log record. 
    The field is in a JSON Format representing the content of the EventData structure.  


    Parameters
    ----------
    row : A dictionary representing a single log record, containing a 'Payload' key.

    Returns:
        dict: A dictionary containing key-value pairs from the parsed 'Payload'
            data. Returns an empty dictionary if parsing fails, if the 'Payload'
            is not a valid JSON string, or if the expected data structure is
            not found.

    """
    result = {}
    raw = row.get('Payload', '')
    if raw and raw.startswith('{'):
        try:
            payload_obj = json.loads(raw)
            if not isinstance(payload_obj, dict):
                return result
            event_data = payload_obj.get('EventData')
            if not isinstance(event_data, dict):
                return result
            entries = event_data.get('Data', [])
            if isinstance(entries, dict):
                entries = [entries]
            for entry in entries:
                if isinstance(entry, dict): 
                    name = entry.get('@Name') or entry.get('Name')
                    value = entry.get('#text') or entry.get('Text')
                    if name:
                        result[name] = value
        except (json.JSONDecodeError, TypeError):
            pass
    return result

def safe_get_field(row, payload, field_name, fallback_keys=None):
    """
    Retrieve a value from a CSV row or its parsed JSON payload with optional fallbacks.

    Lookup order
    ------------
    1. Try to read `field_name` directly from the CSV row (`row[field_name]`).
       - If present and non-empty, return its `.strip()` result.
    2. If `fallback_keys` is provided:
       - Iterate over the keys in `fallback_keys`.
       - For the first key present in `payload`, return its `.strip()` result.
    3. If no `fallback_keys` are given:
       - Try to return `payload[field_name]` (if present), stripped.
    4. If none of the above yield a value, return `None`.

    Parameters
    ----------
    row : dict
        A single CSV row 
    payload : dict
        Parsed JSON payload (from `parse_payload_json`).
    field_name : str
        Primary field name to look up.
    fallback_keys : list[str], optional
        Alternative keys to try in `payload` if the primary field is missing or empty.

    Returns
    -------
    str or None
        The cleaned (stripped) string value, or None if no value was found.
    
    """
    val = row.get(field_name)
    if val:
        return val.strip()
    if fallback_keys:
        for key in fallback_keys:
            if key in payload:
                return payload[key].strip()
    elif field_name in payload:
        return payload[field_name].strip()

    return None

def remove_prefixes(value,prefixes):
    """
    Removes the first matching prefix from a string value.

    This function iterates through a provided list of prefixes and removes the
    first one it finds at the beginning of the input string. The comparison
    is case-insensitive. 

    Args:
        value (str): The string from which to remove a prefix.
        prefixes (list): A list of strings representing the prefixes to be removed.

    Returns: 
        str or None: The modified string with the prefix removed . 
            Returns the original string if no prefix is found. Returns None if the input value is empty or None.

    """
    value = str(value).strip()
    if not value:
        return None

    val_lower = value.lower()   
    for prefix in prefixes:
        if val_lower.startswith(prefix.lower()):
            
            return value[len(prefix):].strip()
        
    return value.strip()


def extract_logon_id(payload):
    """
    Extract a logon/session identifier from parsed payload.
    Using TargetLogonId, logonId or SessionID as session identifier depending on the event type. 

    Parameters
    ----------
    payload : dict
        Parsed payload (from parse_payload_json).

    Returns
    -------
        str or None
            The first matching id string found or None if none present.
    """
    for key in ('TargetLogonId', 'LogonId', 'SessionId'):
        if key in payload:
            return payload[key]
    return None

def extract_user(row, payload):
    """
    Extract a normalized user identifier from a CSV row or its JSON payload.

    Lookup strategy
    ---------------
    1. Iterate over candidate fields: ('UserName', 'PayloadData1', 'AccountName', 'User').
    2. For each field:
       - Check the CSV row first; if empty, try `payload[field]`.
       - Skip if still empty.
       - Special case: if field is 'PayloadData1' and value starts with
         'Connection Type', ignore it (Event ID 131 noise where PayloadData1 contains the connection type instead of the user name).
       - Remove common prefixes (e.g. "Target:", "User:", "AccountName", "TargetInfo:")
         using `remove_prefixes`.
       - Return the cleaned value immediately once found.
    3. If no usable value is found, return None.

    Eid 4624 and LogonType 10
    ---------------
    For this specific case, check if username exists in PayloadData1 and remove prefixe "Target:". 
        - If it's empty, retrieve username from payload[TargetUserName]
        - If no value is found, return None. 

    Eid 40 and Eid 98
    ---------------
    The username is not logged for this event so it's skipped. 
    
    Parameters
    ----------
    row : dict
        Single CSV event record. 
    payload : dict
        Parsed payload (from parse_payload_json).

    Returns
    -------
        str or None
            The first valid, cleaned user value, or None if none available.

    """
    prefixes_cleaning_words = ["Target:", "User:", "AccountName", "TargetInfo:"]
    fields_candidate = ('UserName', 'PayloadData1', 'AccountName', 'User')

    eid = row.get('EventId', '')
    if eid == '4624' and payload.get('LogonType') == '10':
        raw = row.get('PayloadData1')
        if raw:
            val = str(raw).strip()
            return remove_prefixes(val,["Target:"])
        elif payload.get('TargetUserName'):
            val = str(payload.get('TargetUserName')).strip()
            return val 
        else:
            return None

    if eid == '40' or eid == '98': 
        return None

    for field in fields_candidate:
        value = row.get(field)
        val = (value or payload.get(field))  
        if not val:
            continue

        val = value.strip()
        if field == 'PayloadData1' and val.lower().startswith("connection type"):
            continue

        val = remove_prefixes(val, prefixes_cleaning_words)
          
        return val

    return None

def extract_outcome(payload):
    """
    Derive a simple 'Success' / 'Failure' outcome from the payload. 
    This function requires further refinement to properly handle success and failure indicators across different event codes.

    Checks payload keys such as 'Status' and 'SubStatus' when available. Values equal to
    "0x0" or "0" indicate success; any other non-empty status is treated as failure.

    Parameters
    ----------
    payload : dict
        Parsed payload.

    Returns
    -------
    str
        'Success', 'Failure', or '' when no status information is available.
    """
    for key in ('Status', 'SubStatus'):
        val = payload.get(key)
        if val:
            if val.strip() in ('0x0', '0'):
                return 'Success'
            return 'Failure'
    return ''

def correlate_rdp_sessions(records, include_unknown=False, include_4648=False):
    """
     Correlate RDP-related events into session records.

    Summary
    ---------------
    Scans pre-filtered EvtxECmd rows and groups events that belong to the same
    RDP session.  This function determines the session length and its associated events by aggregating events by keys that act as a session identifier. 
   
    Key construction
    ----------------
	Outbound primary key: ('outbound', server, pid)
	    - server comes from TargetServerName), pid from Process ID when available.
	    
	Inbound primary key: ('inbound', logon_id) :
		-  when available, the key has an unique identifier related         to the session   (TargetLogonId / LogonId / SessionId). If no logon id, falls back to ('inbound', src_basename, user).
	
	    - Unknown direction key (optional): captures both equipments related to the connection when possible. 
	

    Event ID 4648
    --------------------------------
		Processed if the argument include_eid_4648 has been provided.
	 
		- Classified as outbound if  the process is mstsc.exe.
		- Classified as inbound if the process is winlogon, svchost, lsass.exe 
	            Localhost events are excluded. 
		 Events where it's the same source and destination are also excluded. 
	            Machine account targets (e.g., HOSTNAME$) are excluded. 
		 If the target information, server name or Remote host information exist and it's not localhost, the direction is considered as outbound. 
			- Otherwise direction is considered unknown and added to the output if the parameter include_unknown has been provided. 
	        
	
    Other Events IDs
    --------------------------------
      Inbound detection
	
	    Security : 
			Events 4778 / 4779 
			Event ID 4624 with LogonType=10.
				
		Microsoft-Windows-Terminal-Services-LocalSessionManager / Operational : 
			Events 41 / 21 / 22 / 25 / 40 
			
		Microsoft-Windows-RemoteDesktopServices-RdpCore / Operational : 
			Events 131 / 98 
		
		Microsoft-Windows-TerminalServices-RemoteConnectionManager / Operational : 
			Event ID 1149
	
	
     Outbound detection

		Microsoft-Windows-TerminalServices-RDPClient / Operational 
			Events 1024 / 1102 
			
    Parameters
    ----------
    records : list[dict]
        CSV rows (dicts) 
    include_unknown : bool
        If True, records sessions with undetermined direction (default False).
    include_4648 : bool
        If True, process and records EventId 4648-derived sessions (default False).

    Returns
    -------
    dict
        RDP Sessions


    """
    sessions = {}

    def make_outbound_key(row):
        server = row.get('PayloadData2', '')
        pid = row.get('PayloadData3', '')
        if server and pid:
            return ('outbound', server, pid)
        return None

    def make_inbound_key(row, payload):
        logon_id = extract_logon_id(payload)
        if logon_id:
            return ('inbound', logon_id)
        src = row.get('RemoteHost', '') or row.get('Computer', '')
        user = extract_user(row, payload)
        return ('inbound', src.split()[0] if src else '', user)

    for row in records:

        eid = row.get('EventId', '')
        channel = row.get('Channel', '')
        ts = row.get('_timestamp')
        payload = parse_payload_json(row)

        direction, key = None, None


        if eid == '4648' and include_4648:

            src = row.get('Computer', '').strip().lower()
            target_info = safe_get_field(row, payload, 'PayloadData4', ['TargetInfo'])
            server_name_raw = (safe_get_field(row, payload, 'PayloadData2', ['TargetServerName'])).lower()
            if server_name_raw.startswith('targetservername:'):
                server_name = server_name_raw.split('targetservername:', 1)[1].strip()
            else : 
                server_name = server_name_raw
            if target_info.lower().startswith('targetinfo:'):
                target_info = target_info.removeprefix('TargetInfo:').strip()
                


            src_basename = src.split('.')[0]  # MACHINENAME.DOMAIN → MACHINENAME
            target_basename = target_info.replace('$', '')  # MACHINENAME$ → MACHINENAME
            server_basename = server_name.replace('$', '')  # TargetServerName MACHINENAME$ → MACHINENAME
            outbound_indicators = ['mstsc.exe']
            inbound_indicators = ['winlogon.exe', 'svchost.exe', 'lsass.exe']
                  
            direction = "unknown"
            target_host = ""

            if src_basename and (src_basename == target_basename or src_basename == server_basename):
                continue

            if target_info in ('127.0.0.1', '::1', 'localhost'):
                continue  

            if 'localhost' in server_basename:
                continue 

            process_name = row.get('ProcessName', '').lower()
            if any(proc in process_name for proc in outbound_indicators):
                direction = "outbound"
                target_host = target_info
            elif any(proc in process_name for proc in inbound_indicators):
                direction = "inbound"
                target_host = src 
            else:
                if target_info and target_info != "127.0.0.1" and target_info != "::1":
                    direction = "outbound"
                    target_host = target_info
                elif server_name:
                    direction = "outbound"
                    target_host = server_name


            remote_host = row.get("RemoteHost", "").strip().lower()
            if remote_host:
                direction = "outbound"  

            # Build session key
            if direction == "outbound":
                key = make_outbound_key(row)
            elif direction == "inbound":
                key = make_inbound_key(row, payload)
            else:
                if not include_unknown:
                        continue 
                target = target_info
                source = row.get('Computer', '').strip().lower() or payload.get('Computer', '').strip().lower()
                key = ('unknown', target, source)


        elif eid in ('1024', '1102'):
            direction = 'outbound'
            target = row.get('PayloadData1') or row.get('PayloadData2')
            target = remove_prefixes(target,["Target:", "Dest:"])
            key = ('outbound', target, None)
        elif eid == '4624' and payload.get('LogonType') == '10':
            direction = 'inbound'
            key = make_inbound_key(row, payload)
        elif eid in ('4778', '4779', '40', '21', '22', '25', '41', '98', '131', '1149'):
            direction = 'inbound'
            key = make_inbound_key(row, payload)

        if not key:
            continue

        if key not in sessions:
            sessions[key] = {
                'start_time': ts,
                'end_time': ts,
                'direction': direction,
                'src': None,
                'dst': None,
                'sid': None,
                'user': None,
                'logon_id': None,
                'pid': None,
                'server_name': None,
                'target_info': None,
                'outcome': '',
                'events': [],  
                'providers':[],
                'protocol':'RDP'
            }

        s = sessions[key]
        if ts:
            if not s['start_time'] or ts < s['start_time']:
                s['start_time'] = ts
            if not s['end_time'] or ts > s['end_time']:
                s['end_time'] = ts

        if direction == 'outbound':
            if eid == '4648':
                
                s['src'] = row.get('Computer', '')
                s['user'] = extract_user(row, payload)
                s['server_name'] = remove_prefixes(row.get('PayloadData2', ''),["Target:", "TargetServerName:"])
                s['pid'] = remove_prefixes(row.get('PayloadData3',''), ["PID:"])
                s['target_info'] = remove_prefixes(row.get('PayloadData4',''), ["Target:", "TargetInfo:"])

            elif eid in ('1024', '1102'):
                if not s['server_name']:
                    s['server_name'] = remove_prefixes(row.get('PayloadData1') or row.get('PayloadData2'),["Dest:", "Address:"])
                s['src'] = row.get('Computer', '')
                destination = row.get('PayloadData1')
                s['dst']=remove_prefixes(destination,["Target:", "Dest:", "Address:"])
                s['sid']=row.get('UserId', '')
                                      
        else:
            s['dst'] = row.get('Computer', '')
            if eid != '40':
                s['src'] = row.get('RemoteHost', '').split()[0] if row.get('RemoteHost') else ''
            else:
                s['src'] = ''            
            s['user'] = extract_user(row, payload)
            s['logon_id'] = extract_logon_id(payload)
            if not s['outcome']:
                s['outcome'] = extract_outcome(payload)

        s['events'].append(eid)
        provider = row.get('Provider') or payload.get('Provider')
        if provider:
            s['providers'].append(provider)
    return sessions

def correlate_psremoting_sessions(records):
    """
    Correlate PowerShell Remoting related events into session records.

    Summary
    -------
    Scans EvtxECmd-exported rows and groups WinRM/PowerShell events that
    represent the same session. A Session is identified by a key. 

    Key construction
    ----------------
    To avoid collisions with RDP sessions, the key includes the protocol name.

      - Inbound key : (client_ip, destination, user, ts, 'Powershell Remoting')
 
      - Outbound key : (src, dst, sid, ts, 'Powershell Remoting')

    By including Timestamps in the key construction, the session aggregation is less "agressive" and effective compared to the RDP session aggregation. 

    Event ID 91 (Inbound)
    ---------------------
    Source: Microsoft-Windows-WinRM/Operational   
    `resourceUri` contains user and client IP:  
         Parsed with regex to retrieve user + client_ip.  


    Event ID 6 (Outbound)
    ---------------------
    Source: Microsoft-Windows-WinRM/Operational (source side).  
    Destination extracted from payload field `connection`.  

    Parameters
    ----------
    records : list[dict]
        CSV rows (dicts), pre-parsed and timestamped.

    Returns
    -------
    dict
        Powershell remoting sessions


    """
    sessions = {}

    for row in records:
        eid = row.get('EventId', '')
        channel = row.get('Channel', '').lower()
        ts = row.get('_timestamp')
        payload = parse_payload_json(row)

        direction, key = None, None
        if eid == '91' and 'winrm' in channel:

            resource = payload.get('resourceUri') or payload.get('ResourceUri') or ''
            destination = row.get('Computer', '')
            sid = row.get('UserId','')
            m = re.search(r'\((?P<user>[^\s]+)\s+clientIP:\s+(?P<ip>[0-9\.]+)\)', resource)
            if m:
                user = m.group('user')
                client_ip = m.group('ip')
                key = (client_ip, destination, user, ts, 'Powershell Remoting')
                pid = row.get('ProcessId','')

                if key not in sessions:
                    sessions[key] = {
                    'start_time': ts,
                    'end_time': ts,
                    'direction': 'inbound',
                    'src': client_ip,
                    'dst': destination,
                    'sid': sid,
                    'user': user,
                    'logon_id': None,
                    'pid': pid,
                    'server_name': None,
                    'target_info': None,
                    'outcome': '',
                    'events': [],  
                    'providers':[],
                    'protocol': 'Powershell Remoting',
                }
                s = sessions[key]
                s['events'].append(eid)
                provider = row.get('Provider','')
                if provider:
                    s['providers'].append(provider)

        elif eid == '6' and 'winrm' in channel:
            src = row.get('Computer', '') 
            sid = row.get('UserId', '')
            pid = row.get('ProcessId','')
            
            connection = payload.get('connection') or payload.get('Connection') or ''
            dst = ''
            if connection:
                dst = connection.split('/')[0]

            key = (src, dst, sid, ts, 'Powershell Remoting')

            if key not in sessions:
                sessions[key] = {
                    'start_time': ts,
                    'end_time': ts,
                    'direction': 'outbound',
                    'src': src,
                    'dst': dst,
                    'sid': sid,
                    'user': '',
                    'logon_id': None,
                    'pid': pid,
                    'server_name': None,
                    'target_info': None,
                    'outcome': '',
                    'events': [],
                    'providers': [],
                    'protocol': 'Powershell Remoting',
                }

            s = sessions[key]
            s['events'].append(eid)
            provider = row.get('Provider', '')
            if provider:
                s['providers'].append(provider)

    return sessions

def save_sessions_to_csv(sessions, output_path):
    """
    Export sessions to a CSV file.
    Overwrites the file at `output_path` if it already exists.

    Parameters
    ----------
    sessions : dict
        
    output_path : str
        Path to the CSV file to write.


    """

    headers = [
        'start_time', 'end_time', 'direction', 'src', 'dst',
        'sid', 'user', 'logon_id', 'pid', 'server_name', 'target_info', 'outcome', 'protocol', 'events', 'providers'
    ]
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for sess in sessions.values():
            writer.writerow([
                sess['start_time'].isoformat() if sess['start_time'] else '',
                sess['end_time'].isoformat() if sess['end_time'] else '',
                sess['direction'], sess['src'], sess['dst'], sess['sid'],
                sess['user'], sess['logon_id'], sess['pid'],
                sess['server_name'], sess['target_info'], sess['outcome'], sess['protocol'],
                ";".join(sess['events']), 
                ";".join(sess['providers']) 
            ])

def main():

    if len(sys.argv) < 3:
        print("Usage: python lateralmovementanalyzer.py <input.csv> <output.csv> [options]\n"
              "Options :\n"
              "  --includeAlldirections             : Include sessions with undetermined direction\n"
              "  --include_eid_4648                 : Keep 4648 events (noisy). 4648 events alone usually don't prove lateral movement but it can be useful for the correlation of outbound movements. \n"
              "  --only-ps                          : output only PS-Remoting sessions (skip RDP correlation)\n"
              "  --only-rdp                         : output only RDP sessions (skip PS correlation)\n"
              "  --provider-filter-disabled         : disable provider-name filtering when reading CSV\n"
              )
        sys.exit(1)
    input_csv, output_csv = sys.argv[1], sys.argv[2]

    include_unknown = '--includeAlldirections' in sys.argv
    include_4648 = '--include_eid_4648' in sys.argv
    only_ps = '--only-ps' in sys.argv
    only_rdp = '--only-rdp' in sys.argv
    disable_provider_filter = '--provider-filter-disabled' in sys.argv 

    valid_args = {
    '--includeAlldirections',
    '--include_eid_4648',
    '--only-ps',
    '--only-rdp',
    '--provider-filter-disabled'
    }

    user_args = {arg for arg in sys.argv[3:] if arg.startswith('--')}
    invalid_args = user_args - valid_args
    if invalid_args:
        print(f"Error : Unknown options {', '.join(invalid_args)}")
        sys.exit(1)

    if only_ps and only_rdp:
        print("Error: Options --only-ps and --only-rdp are mutually exclusive. Choose one or none.")
        sys.exit(2)

    records = load_evtx_csv(input_csv, disable_provider_filter=disable_provider_filter)
    all_sessions = {}
    if only_ps:
        psremoting_sessions = correlate_psremoting_sessions(records)
        all_sessions.update(psremoting_sessions)
        
    elif only_rdp:
        rdp_sessions = correlate_rdp_sessions(records, include_unknown=include_unknown, include_4648=include_4648)
        all_sessions.update(rdp_sessions)

    else:
        rdp_sessions = correlate_rdp_sessions(records, include_unknown=include_unknown, include_4648=include_4648)
        psremoting_sessions = correlate_psremoting_sessions(records)
        
        all_sessions.update(rdp_sessions)
        all_sessions.update(psremoting_sessions)
    
    save_sessions_to_csv(all_sessions, output_csv)
    if only_ps: 
        print(f"Correlated {len(psremoting_sessions)} Powershell remoting sessions into '{output_csv}'")

    elif only_rdp:
        print(f"Correlated {len(rdp_sessions)} RDP sessions into '{output_csv}'")
    
    else:  
        print(f"Correlated {len(rdp_sessions)} RDP sessions into '{output_csv}'")
        print(f"Correlated {len(psremoting_sessions)} Powershell remoting sessions into '{output_csv}'")
    

if __name__ == '__main__':
    main()
