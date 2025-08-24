# Device Webhooks

JSON body format for device webhooks


## Switches

Unless specified, they all follow the format below.
The 'type' will be "SW_PORT_DOWN" or similar.

```json
{
    "device_name": "Switch name",
    "device_type": "switch",
    "mac": "50c709xxxxxx",
    "model": "EX3400-48P",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "port_id": "ge-0/0/31",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "text": "A Mist generated summary",
    "timestamp": 1749073244,
    "type": "SW_PORT_DOWN"
}
```
</br></br>


## Sample text fields

SW_PORT_DOWN
    "ifIndex 546, ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/31 Port Description: Management"
SW_PORT_UP
    "ifIndex 519, ifAdminStatus up(1), ifOperStatus up(1), ifName ge-0/0/4"
SW_IP_CONFLICT
    "KERN_ARP_DUPLICATE_ADDR: duplicate IP address 10.18.104.1! sent from address: 98:49:25:7b:a8:00 (error count = 1)"
SW_DOT1XD_USR_AUTHENTICATED
    "Custom_log Dot1x User gmrichardson@lakemac.nsw.gov.au logged in MacAddress c4:d6:d3:7b:37:26 interface ge-0/0/32.0 vlan Workstations"
SW_DOT1XD_USR_SESSION_DISCONNECTED
    "Dot1x User ac91a1xxxxxx session with MacAddress ac:91:a1:xx:xx:xx interface ge-0/0/2.0 vlan (null) disconnected"
SW_DOT1XD_USR_SESSION_HELD
    "Dot1x User host/host.example.com session with MacAddress 6c:2b:59:xx:xx:xx interface ge-0/0/5.0 vlan (null) is held"
SW_DOT1XD_USR_ON_SRVR_REJECT_VLAN
    "MAC-RADIUS User ac91a1xxxxxx logged in MacAddress ac:91:a1:xx:xx:xx interface ge-0/0/2.0 authenticated on server reject vlan Public_Internet"
SW_ALARM_OPTICS_IFACE_SFP_LOW
    "xe-0/0/0: LaserBiasCurrent of optical interface is low (131.07 mA) < (131.07 mA); xe-0/0/0: TX power of optical interface is low (8.16 dBm) < (8.16 dBm); xe-0/0/0: ModuleVoltage of optical interface is low (6.55 V) < (6.55 V); xe-0/0/0: ModuleTemperature of optical interface is low (0.00 C/F) < (-0.00 C/F); xe-0/0/0: RX power of optical interface is low (8.16 dBm) < (8.16 dBm)"
SW_LACP_RX_STALE
    "LACP RX of interface ae340 xe-0/0/30 is no longer increasing"
SW_MAC_LIMIT_RESET
    "Resumed adding MAC addresses learned by ge-0/0/6.0; current count is 0"
SW_BGP_NEIGHBOR_STATE_CHANGED
    "BGP peer 10.250.2.7 (Internal AS 132906) changed state from Established to Idle (event RecvNotify) (instance master)"
SW_BGP_NEIGHBOR_DOWN
    "BGP peer 10.250.2.7 (Internal AS 132906) changed state from Established to Idle (event RecvNotify) (instance master)"
SW_EVPN_BGP_PEER_STATUS_CHANGE
    "iBGP peer status changed to down (6 currently established)"
SW_BGP_NEIGHBOR_UP
    "BGP peer 10.250.2.7 (Internal AS 132906) changed state from OpenConfirm to Established (event RecvKeepAlive) (instance master)"
SW_CONFIG_CHANGED_BY_USER
    NO TEXT FIELD
SW_CONFIG_ERROR_ADDTL_COMMAND
    Command [set system services ssh no-tcp-forwarding] from the additional commands has an error in no-tcp-forwarding: syntax error
SW_CONFIGURED
    UI_COMMIT_COMPLETED: : commit complete
SW_ALARM_CHASSIS_POE
    PoE Short CirCuit in Interface ge-0/0/7
SW_ALARM_CHASSIS_POE_CLEAR
    PoE Short CirCuit in Interface ge-0/0/7
SW_DDOS_PROTOCOL_VIOLATION_SET
    Warning: Host-bound traffic for protocol/exception L3NHOP:aggregate exceeded its allowed bandwidth at fpc 0 for 86 times, started at 2025-06-06 00:08:48 AEST
SW_DDOS_PROTOCOL_VIOLATION_CLEAR
    INFO: Host-bound traffic for protocol/exception L3NHOP:aggregate has returned to normal. Its allowed bandwidth was exceeded at fpc 0 for 94 times, from 2025-06-06 01:11:56 AEST to 2025-06-06 01:12:06 AEST
SW_STP_TOPO_CHANGED
    TopoChgCnt 5, RootID 32768.08:05:e2:5e:dc:7e, RootCost 10000, RootPort ae0


## Differences

Some have slightly different bodies:
    SW_CONNECTED
    SW_DISCONNECTED

```json
{
    "device_name": "Switch Name",
    "device_type": "switch",
    "mac": "60c78dxxxxxx",
    "model": "EX3400-48P",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "timestamp": 1749080793,
    "type": "SW_DISCONNECTED"
}
```
</br></br>


SW_STP_TOPO_CHANGED
    The same as the main body at the top, but does not have a port_id.



## MARVIS

```json
CONNECTIVITY_TEST (Access Point)
{
    "ap": "xxxxxxxxxxxx",
    "ap_name": "AP Name",
    "device_name": "Device Name",
    "device_type": "ap",
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "text": "A connectivity test was triggered automatically.",
    "timestamp": 1749073097,
    "type": "CONNECTIVITY_TEST"
}
```
</br></br>



## Access Points

These are very similar to switches, with a few differences.
They follow this format:

```json
{
    "ap": "xxxxxxxxxxxx",
    "ap_name": "Device Name",
    "audit_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "device_name": "Device Name",
    "device_type": "ap",
    "ev_type": "NOTICE",
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "timestamp": 1749101162,
    "type": "AP_CONFIG_CHANGED_BY_USER"
}
```
</br></br>



Differences:

AP_RADAR_DETECTED contains additional fields, showing how RRM has tuned it

```json
{
    "band": "5",
    "bandwidth": 40,
    "channel": 36,
    "pre_bandwidth": 40,
    "pre_channel": 60,
    "reason": "radar-detected",
}
```
</br></br>




## Gateway's (SRX)

```json
{
    "audit_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "device_name": "Device Name",
    "device_type": "gateway",
    "ev_type": "NOTICE",
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "timestamp": 1749101162,
    "type": "GW_CONFIG_CHANGED_BY_USER"
}
```
</br></br>



