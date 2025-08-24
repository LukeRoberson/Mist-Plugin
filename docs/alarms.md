# JSON body format for Alarm webhooks

# Regular Alarms

There are several different formats, depending on the alarm type
</br></br>


**sw_bad_optics**
**sw_alarm_chassis_poe**

```json
{
    "count": 1,
    "fw_version": "22.4R3-S6.5",
    "group": "infrastructure",
    "hostnames": [
        "Switch Name"
    ],
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "last_seen": "2025-06-05T04:00:00",
    "model": "EX4650-48Y",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "peer": {
    },
    "port_ids": [
        "xe-0/0/0"
    ],
    "reasons": [
        "xe-0/0/0: LaserBiasCurrent of optical interface is low (131.07 mA) < (131.07 mA); xe-0/0/0: TX power of optical interface is low (8.16 dBm) < (8.16 dBm); xe-0/0/0: ModuleVoltage of optical interface is low (6.55 V) < (6.55 V); xe-0/0/0: ModuleTemperature of optical interface is low (0.00 C/F) < (-0.00 C/F); xe-0/0/0: RX power of optical interface is low (8.16 dBm) < (8.16 dBm)"
    ],
    "severity": "warn",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "switches": [
        "xxxxxxxxxxxx"
    ],
    "timestamp": 1749096017.5365038,
    "type": "sw_bad_optics"
}
```
</br></br>




**ap_bad_cable**
**bad_cable**
```json
{
    "alert_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "category": "layer_1",
    "count": 1,
    "details": {
        "action": "test_replace_cable",
        "category": "layer_1",
        "status": "resolved",
        "symptom": "bad_cable"
    },
    "email_content": {
        "Connected switch": "Switch-Name(xxxxxxxxxxxx)",
        "Status": "resolved",
        "ap": "Switch-Name(xxxxxxxxxxxx)"
    },
    "group": "marvis",
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "impacted_entities": [
        {
            "connected_switch_mac": "xxxxxxxxxxxx",
            "connected_switch_name": "Switch Name",
            "entity_mac": "xxxxxxxxxxxx",
            "entity_name": "Switch Name",
            "entity_type": "ap",
            "port_id": "ge-0/0/19"
        }
    ],
    "last_seen": "2025-04-01T16:58:27",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "org_name": "Org Name",
    "port_ids": [
        "ge-0/0/19"
    ],
    "resolved_time": "2025-06-13T15:01:20",
    "severity": "critical",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "status": "resolved",
    "suggestion": "test_replace_cable",
    "timestamp": 1749826902.0342431,
    "type": "ap_bad_cable"
}
```
</br></br>




**device_restarted**
```json
{
    "aps": [
        "xxxxxxxxxxxx",
        "xxxxxxxxxxxx",
        ...
    ],
    "count": 4,
    "group": "infrastructure",
    "hostname": "AP Hostname",
    "hostnames": [
        "Hostname",
        "Hostname",
        ...
    ],
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "last_seen": "2025-06-15T14:25:19",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "reasons": [
        "power_cycle"
    ],
    "severity": "info",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "timestamp": 1749998077.6217253,
    "type": "device_restarted"
}
```
</br></br>






## Marvis Minis

These simulate traffic, etc, to test network functions.
Notice that the 'group' is set to 'marvis'.
</br></br>


**dhcp_failure**
```json
{
    "alert_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "category": "connectivity",
    "count": 1,
    "details": {
        "action": "check_dhcp",
        "category": "connectivity",
        "status": "resolved",
        "symptom": "dhcp_failure"
    },
    "email_content": {
        "Reason": "wlan_site",
        "Status": "resolved",
        "impacted_client_count": "13",
        "wlan": "SSID(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
    },
    "group": "marvis",
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "impacted_client_count": 13,
    "impacted_entities": [
        {
            "entity_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "entity_name": "ENTITY/SSID",
            "entity_type": "wlan",
            "ui_display_field": "ENTITY/SSID"
        }
    ],
    "last_seen": "2025-05-19T02:00:15",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "org_name": "Org Name",
    "resolved_time": "2025-06-05T19:25:09",
    "root_cause": "wlan_site",
    "severity": "critical",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Pearson St Mall",
    "status": "resolved",
    "suggestion": "check_dhcp_failure",
    "timestamp": 1749151526.6709626,
    "type": "dhcp_failure"
}
```
