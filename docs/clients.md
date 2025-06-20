# Client Webhooks

JSON body format for Client webhooks

Unlike NAC or device events, there is no 'type' field to categorise these webhooks.
These custom 'types' are used:
* user-connect
* guest-connect
* disconnect
* client-info
</br></br>


## Disconnect

When there is a 'connect' and a 'disconnect' field, this is a client disconnection

Example:
```json
{
    "ap": "xxxxxxxxxxxx",
    "ap_name": "AP Name",
    "band": "5",
    "bssid": "xxxxxxxxxxxx",
    "client_family": "iPhone",
    "client_manufacture": "Apple",
    "client_model": "",
    "client_os": "18.5.0",
    "connect": 1749093060,
    "connect_float": 1749093060.39,
    "disconnect": 1749093077,
    "disconnect_float": 1749093077.921,
    "duration": 17.531571348,
    "mac": "xxxxxxxxxxxx",
    "next_ap": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": false,
    "rssi": -67,
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site",
    "ssid": "SSID",
    "termination_reason": 3,
    "timestamp": 1749093077,
    "version": 2,
    "wlan_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "type": "disconnect"
}
```
</br></br>




## Connect & Guest

If there is a 'connect' field, but no 'disconnect' field, this is a client connection of some type.

Example:
```json
{
    "ap": "xxxxxxxxxxxx",
    "ap_name": "AP Name",
    "band": "24",
    "bssid": "xxxxxxxxxxxx",
    "connect": 1749088902,
    "connect_float": 1749088902.64,
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": false,
    "rssi": -57,
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_name": "Site Name",
    "ssid": "SSID",
    "timestamp": 1749088902,
    "version": 2,
    "wlan_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```
</br></br>



Sometimes these will include extra fields, if Mist can work them out.
For example, if a user authenticates with username/password, these fields will be here.
If the device is on guest WiFi, they won't be here

```json
{
    "client_hostname": "Hostname",
    "client_ip": "x.x.x.x",
    "client_username": "user@domain.com",
}
```
</br></br>



If client_username is present:
* user-connect

If not:
* guest-connect
</br></br>



## Client-info

Anything with very little information is 'client-info'
This is a fragment of an update, and probably correlates to some other webhook.
This may be an event within an aggregated webhook

Example:
```json
{
    "ip": "x.x.x.x",
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "timestamp": 1749088902
}
```
