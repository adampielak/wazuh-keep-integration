#!/usr/bin/python3
#
# Wazuh & Keep integration by Adam Pielak tick@linuxmafia.pl
#
# ADD THIS TO ossec.conf configuration:
#  <ossec_config>
#    <!-- Keep integration -->
#    <integration>
#      <name>custom-keep</name>
#      <hook_url>http://<KEEP_IP_ADDRESS>:8080/alerts/event</hook_url>
#      <api_key><KEEP_API_KEY></api_key>
#      <level>3</level>
#      <alert_format>json</alert_format>
#    </integration>
#  </ossec_config>

import json
import os
import sys
from datetime import datetime, timezone

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# Hardcode your environment value here
environment = "ENV"
url = "https://wazuh.siem.local"
ticket_url = "https://jira.prod.local"

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log path
LOG_FILE = f"{pwd}/logs/integrations.log"

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
WEBHOOK_INDEX = 3

def main(args):
    global debug_enabled
    try:
        bad_arguments = False
        if len(args) >= 4:
            msg = " ".join(args[1:6])
            debug_enabled = len(args) > 4 and args[4] == "debug"
        else:
            msg = "# ERROR: Wrong arguments"
            bad_arguments = True

        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")

        if bad_arguments:
            debug("# ERROR: Exiting, bad arguments. Inputted: %s" % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        process_args(args)

    except Exception as e:
        debug(str(e))
        raise

def process_args(args):
    debug("# Running Custom Keep script")

    alert_file_location = args[ALERT_INDEX]
    webhook = args[WEBHOOK_INDEX]
    api_key = args[API_KEY_INDEX]
    options_file_location = ""

    for idx in range(4, len(args)):
        if args[idx].endswith("options"):
            options_file_location = args[idx]
            break

    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug("# Generating message")
    msg = generate_msg(json_alert, json_options)

    if not msg:
        debug("# ERROR: Empty message")
        raise Exception

    debug(f"# Sending message {json.dumps(msg, indent=2)} to Keep server")
    send_msg(msg, webhook, api_key)

def debug(msg):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")

# Helper to extract agent.ip, agent.srcip, agent_ip for ip_address field
def get_ip_address(alert):
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    # Try agent["ip"]
    if "ip" in agent:
        return agent["ip"]
    # Try agent["srcip"]
    if "srcip" in agent:
        return agent["srcip"]
    # Try data["agent_ip"]
    if "agent_ip" in data:
        return data["agent_ip"]
    # Try data["srcip"]
    if "srcip" in data:
        return data["srcip"]
    # Try data["ip"]
    if "ip" in data:
        return data["ip"]
    return "unknown"

def generate_msg(alert, options):
    level = alert.get("rule", {}).get("level", 0)
    title = alert.get("rule", {}).get("description", "N/A")
    rule_id = alert.get("rule", {}).get("id", "N/A")
    agent = alert.get("agent", {})
    agent_id = agent.get("id", "N/A")
    agent_name = agent.get("name", "N/A")
    full_log = alert.get("full_log", "N/A")

    severity = "low"
    if level > 14:
        severity = "critical"
    elif level > 11:
        severity = "high"
    elif level > 6:
        severity = "info"

    created_at = alert.get("timestamp", datetime.now(timezone.utc).astimezone().isoformat())
    fingerprint = f"{agent_id}-{rule_id}"

    labels = alert.get("data", {}).copy()
    labels.update({
        "agent_id": agent_id,
        "agent_name": agent_name,
        "rule_id": rule_id
    })

    # Set IP using the new helper function
    agent_ip = get_ip_address(alert)

    result = {
        "id": f"{fingerprint}-{int(datetime.now().timestamp())}",
        "name": title,
        "status": "firing",
        "created_at": created_at,
        "lastReceived": created_at,
        "environment": environment,
        "service": agent_name,
        "source": ["wazuh"],
        "message": title,
        "description": f"Rule ID {rule_id}\nLevel {level}\nAgent ID {agent_id}\nAgent Name {agent_name}\n\nFull Log:\n{full_log}",
        "severity": severity,
        "host_name": agent_name,
        "hostname": agent_name,
        "ip_address": agent_ip,
        "host_ip": agent_ip,
        "pushed": True,
        "url": url,
        "labels": labels,
        "ticket_url": ticket_url,
        "fingerprint": fingerprint
    }
    return result

def send_msg(msg, url, api_key):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": api_key,
    }
    try:
        res = requests.post(url, json=msg, headers=headers, timeout=10)
        debug(f"# Response received: {res.status_code} {res.text}")
    except Exception as e:
        debug(f"# Error sending message: {e}")

def get_json_alert(file_location):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug(f"# JSON file for alert {file_location} doesn't exist")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug(f"Failed getting JSON alert. Error: {e}")
        sys.exit(ERR_INVALID_JSON)

def get_json_options(file_location):
    if not file_location:
        return {}
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug(f"# JSON file for options {file_location} doesn't exist")
        return {}
    except Exception as e:
        debug(f"Failed getting JSON options. Error: {e}")
        sys.exit(ERR_INVALID_JSON)

if __name__ == "__main__":
    main(sys.argv)
