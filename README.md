# Wazuh & Keep integration
Wazuh integration to send alerts to Keep (open-source alert management and AIOps platform) with custom environment field, as described in [seamless integration between Keep and Wazuh](https://docs.keephq.dev/providers/documentation/wazuh-provider/)


## Installation and Setup

1. Clone the Repository oraz download custom scripts

```bash
cd /var/ossec/integrations
wget -O custom-keep.py https://raw.githubusercontent.com/adampielak/wazuh-keep-integration/refs/heads/main/custom-wazuh-keep.py
wget -O custom-keep https://raw.githubusercontent.com/adampielak/wazuh-keep-integration/refs/heads/main/custom-wazuh-keep

```

2. After cloning navigate to the script's directory and open it:

```bash
cd /var/ossec/integrations
vi custom-keep.py

```
3. Modify the Script

- Adding Custom Environment Fields:

```bash
# Global vars
debug_enabled = False
environment = "linuxmafia" #<- here
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

```

4. Give it the right ownership and permissions

```bash
chmod 750 /var/ossec/integrations/custom-keep.py /var/ossec/integrations/custom-keep
chown root:wazuh /var/ossec/integrations/custom-keep.py /var/ossec/integrations/custom-keep

```

5. Update the `ossec.conf` File
Append the following configuration to the `/var/ossec/etc/ossec.conf` file to enable the integration with Keep:
```bash
  <ossec_config>
    <!-- Keep integration -->
    <integration>
      <name>custom-keep</name>
      <hook_url>http://<KEEP_IP_ADDRESS>:8080/alerts/event/wazuh</hook_url>
      <api_key><KEEP_API_KEY></api_key> <!-- Replace with your Keep API key -->
      <level>11</level>
      <alert_format>json</alert_format>
    </integration>
  </ossec_config>

```
- Replace <KEEP_IP_ADDRESS> with the IP address of the Keep server. Ensure to include the port number if Keep is not listening on the default port 8080.

5. Restart Wazuh Manager:

```bash
systemctl restart wazuh-manager

```
