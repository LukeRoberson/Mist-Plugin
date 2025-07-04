# NAC Webhooks

JSON body format for NAC webhooks

This will break down the events in to categories
* NAC Accounting
* Session and client events
* Certificate events
* IDP Events
* MDM Events



## NAC Accounting

NAC_ACCOUNTING_START

```json
{
    "ap": "xxxxxxxxxxxx",
    "bssid": "xxxxxxxxxxxx",
    "client_type": "wireless",
    "crc": [
        3505419366,
        3349273194,
        ...
    ],
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749084229888,
    "type": "NAC_ACCOUNTING_START",
    "username": "user@domain.com"
}
```
</br></br>



NAC_ACCOUNTING_STOP

```json
{
    "ap": "xxxxxxxxxxxx",
    "bssid": "xxxxxxxxxxxx",
    "client_ip": "x.x.x.x",
    "client_type": "wireless",
    "crc": [
        2985966897,
        3077937141,
        ...
    ],
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "rx_bytes": 28828,
    "rx_pkts": 61,
    "session_duration_in_mins": 0,
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749084222950,
    "tx_bytes": 51633,
    "tx_pkts": 79,
    "type": "NAC_ACCOUNTING_STOP",
    "username": "user@domain.com"
}
```
</br></br>



NAC_ACCOUNTING_UPDATE

```json
{
    "crc": [
        2905138499,
        559721735,
        ...
    ],
    "device_mac": "50c709xxxxxx",
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "mac": "cc96e5xxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "port_id": "ge-0/0/17.0",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "timestamp": 1749086961066,
    "type": "NAC_ACCOUNTING_UPDATE",
    "username": "user@domain.com"
}
```
</br></br>



## Session and client events

NAC_CLIENT_DENY
```json
{
    "ap": "xxxxxxxxxxxx",
    "auth_type": "eap-peap",
    "bssid": "xxxxxxxxxxxx",
    "client_type": "wireless",
    "crc": [
        816874768,
        2761861480,
        ...
    ],
    "mac": "xxxxxxxxxxxx",
    "nacrule_id": "00000000-0000-0000-0000-000000000000",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "true",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "text": "eap_peap: The users session was previously rejected: returning reject (again.)",
    "timestamp": 1749083623737,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_CLIENT_DENY",
    "username": "user@domain.com"
}
```
</br></br>



NAC_CLIENT_IP_ASSIGNED
```json
{
    "ap": "xxxxxxxxxxxx",
    "aps": [
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-04T23:28:52.764423163Z"
        }
    ],
    "bssid": "xxxxxxxxxxxx",
    "bssids": [
        {
            "value": "d4dc093df3a1",
            "when": "2025-06-04T23:28:52.764423163Z"
        }
    ],
    "client_ip": "x.x.x.x",
    "client_ips": [
        {
            "value": "x.x.x.x",
            "when": "2025-06-05T01:28:52.92683301Z"
        }
    ],
    "client_type": "wireless",
    "crc": [
        1578513088,
        1340315504,
        ...
    ],
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "session_last_updated_at": "2025-06-05T01:28:52.92683301Z",
    "session_started_at": "2025-06-04T23:28:52.764423163Z",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749086932927,
    "type": "NAC_CLIENT_IP_ASSIGNED",
    "username": "user@domain.com"
}
```
</br></br>



NAC_CLIENT_PERMIT
```json
{
    "ap": "xxxxxxxxxxxx",
    "auth_type": "eap-tls",
    "bssid": "xxxxxxxxxxxx",
    "cert_cn": "user",
    "cert_expiry": "2025-09-05T03:26:08Z",
    "cert_issuer": "/DC=com/DC=domain/CN=CA-Server",
    "cert_san_upn": [
        "user@domain.com"
    ],
    "cert_serial": "1b00001dde21b4a6f710f6c2b6000000001dde",
    "cert_subject": "/CN=user/emailAddress=user@domain.com",
    "cert_template": "1.3.6.1.4.1.311.21.8.14626627.11750298.13385910.5196327.16027577.228.16764821.720296",
    "client_type": "wireless",
    "crc": [
        2761861480,
        1392017575,
        ...
    ],
    "idp_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "idp_lookup_source": "Cache",
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "idp_username": "user@domain.com",
    "lookup_time_taken": 0.000267106,
    "mac": "xxxxxxxxxxxx",
    "nacrule_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "nacrule_matched": "true",
    "nacrule_name": "NAC Rule",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "resp_attrs": [
        "Tunnel-Type=VLAN",
        "Tunnel-Medium-Type=IEEE-802",
        "Tunnel-Private-Group-Id=15",
        "User-Name=user@domain.com"
    ],
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "Wireless-SSID",
    "timestamp": 1749083558858,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 CertificateRequest",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 Certificate",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 CertificateVerify",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_CLIENT_PERMIT",
    "username": "user@domain.com",
    "vlan": "15",
    "vlan_source": "nactag"
}
```
</br></br>



NAC_SESSION_ENDED
```json
{
    "ap": "xxxxxxxxxxxx",
    "aps": [
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:31:18.775967996Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:02.960132576Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:07.721268739Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:23.700307781Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:32.523158516Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:33:41.176209026Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:43:16.663359237Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:43:21.574136575Z"
        }
    ],
    "bssid": "xxxxxxxxxxxx",
    "bssids": [
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:31:18.775967996Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:02.960132576Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:07.721268739Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:23.700307781Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:32:32.523158516Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:33:41.176209026Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:43:16.663359237Z"
        },
        {
            "value": "xxxxxxxxxxxx",
            "when": "2025-06-05T01:43:21.574136575Z"
        }
    ],
    "client_ip": "x.x.x.x.",
    "client_ips": [
        {
            "value": "x.x.x.x.",
            "when": "2025-06-05T00:52:12.343522537Z"
        }
    ],
    "client_type": "wireless",
    "crc": [
        3653938562,
        1512060830,
        ...
    ],
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "mac": "xxxxxxxxxxxx",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "session_duration_in_mins": 51,
    "session_ended_at": "2025-06-05T01:43:40.401579286Z",
    "session_last_updated_at": "2025-06-05T01:43:40.401579286Z",
    "session_started_at": "2025-06-05T00:52:12.343522537Z",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749087852442,
    "total_bytes_received": 1185618,
    "total_bytes_sent": 1129258,
    "total_packets_received": 5689,
    "total_packets_sent": 4080,
    "type": "NAC_SESSION_ENDED",
    "username": "user@domain.com"
}
```
</br></br>



NAC_SESSION_STARTED
```json
{
    "ap": "xxxxxxxxxxxx",
    "client_type": "wireless",
    "crc": [
        779929167,
        3660994674,
        ...
    ],
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "session_started_at": "2025-06-05T01:40:56.835202783Z",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749087656836,
    "type": "NAC_SESSION_STARTED",
    "username": "user@domain.com"
}
```
</br></br>



## Certificate events

NAC_CLIENT_CERT_CHECK_SUCCESS
```json
{
    "ap": "xxxxxxxxxxxx",
    "auth_type": "eap-tls",
    "bssid": "xxxxxxxxxxxx",
    "cert_cn": "user",
    "cert_expiry": "2025-09-05T03:26:08Z",
    "cert_issuer": "/DC=com/DC=domain/CN=CA-Server",
    "cert_san_upn": [
        "user@domain.com"
    ],
    "cert_serial": "1b00001dde21b4a6f710f6c2b6000000001dde",
    "cert_subject": "/CN=user/emailAddress=user@domain.com",
    "cert_template": "1.3.6.1.4.1.311.21.8.14626627.11750298.13385910.5196327.16027577.228.16764821.720296",
    "client_type": "wireless",
    "crc": [
        2932710676,
        2761861480,
        ...
    ],
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749083558853,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 CertificateRequest",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 Certificate",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 CertificateVerify",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_CLIENT_CERT_CHECK_SUCCESS",
    "username": "user@domain.com"
}
```
</br></br>



NAC_CLIENT_CERT_CHECK_FAILURE
```json
{
    "ap": "xxxxxxxxxxxx",
    "auth_type": "eap-tls",
    "bssid": "xxxxxxxxxxxx",
    "cert_cn": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "cert_expiry": "2025-08-13T21:39:36Z",
    "cert_issuer": "/C=US/ST=CA/L=SantaClara/CN=konea",
    "cert_serial": "55ed0bc52d524e82",
    "cert_subject": "/O=Quest Software, Inc./OU=1/CN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_type": "wireless",
    "crc": [
        3182048838,
        580023336,
        ...
    ],
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "text": "TLS Client Certificate Check failed by the Server. Please check Certificate configuration on the client. Also check if the server has the correct CA configuration",
    "timestamp": 1749158551781,
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 CertificateRequest",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 Certificate",
        "send TLS 1.2 Alert, fatal unknown_ca"
    ],
    "type": "NAC_CLIENT_CERT_CHECK_FAILURE",
    "username": "username"
}
```
</br></br>



NAC_SERVER_CERT_VALIDATION_SUCCESS
```json
{
    "ap": "xxxxxxxxxxxx",
    "auth_type": "eap-tls",
    "bssid": "xxxxxxxxxxxx",
    "cert_expiry": "2026-06-17T03:34:36Z",
    "cert_issuer": "/DC=com/DC=domain/CN=CA-Server",
    "cert_subject": "CN=Mist.domain.com,ST=NSW,C=AU",
    "client_type": "wireless",
    "crc": [
        3421622557,
        2932710676,
        ...
    ],
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749083558851,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 CertificateRequest",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 Certificate",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 CertificateVerify",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_SERVER_CERT_VALIDATION_SUCCESS",
    "username": "user@domain.com"
}
```
</br></br>





## IDP Events

NAC_IDP_AUTHC_SUCCESS
```json
{
    "client_type": "wired",
    "crc": [
        2963729148,
        806859175,
        ...
    ],
    "device_mac": "xxxxxxxxxxxx",
    "idp_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "idp_username": "user@domain.com",
    "lookup_time_taken": 0.14344934,
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "10.17.104.65",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "port_id": "ge-1/0/5.0",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "timestamp": 1749087985403,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_IDP_AUTHC_SUCCESS",
    "username": "user@domain.com"
}
```
</br></br>



NAC_IDP_GROUPS_LOOKUP_FAILURE
```json
{
    "auth_type": "eap-tls",
    "cert_cn": "xxxxxxxxxxxx",
    "cert_expiry": "2026-01-30T03:15:33Z",
    "cert_issuer": "/DC=com/DC=domain/CN=CA-Server",
    "cert_san_dns": [
        "xxxxxxxxxxxx"
    ],
    "cert_serial": "d4dc0922306e0000679aeed10201",
    "cert_subject": "CN=Mist.domain.com,ST=NSW,C=AU",
    "client_type": "wired",
    "crc": [
        3102426541,
        897409844,
        ...
    ],
    "device_mac": "xxxxxxxxxxxx",
    "idp_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "idp_lookup_source": "Cache",
    "idp_username": "xxxxxxxxxxxx",
    "lookup_time_taken": 0.000275676,
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "port_id": "ge-0/0/12.0",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "text": "AD returned empty deviceID response for displayName: <client_mac>",
    "timestamp": 1749086944908,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 CertificateRequest",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 Certificate",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 CertificateVerify",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_IDP_GROUPS_LOOKUP_FAILURE",
    "username": "Username"
}
```
</br></br>



NAC_IDP_GROUPS_LOOKUP_SUCCESS
```json
{
    "ap": "xxxxxxxxxxxx",
    "auth_type": "eap-tls",
    "bssid": "xxxxxxxxxxxx",
    "cert_cn": "user",
    "cert_expiry": "2025-09-05T03:26:08Z",
    "cert_issuer": "/DC=com/DC=domain/CN=CA-Server",
    "cert_san_upn": [
        "user@domain.com"
    ],
    "cert_serial": "1b00001dde21b4a6f710f6c2b6000000001dde",
    "cert_subject": "/CN=user/emailAddress=user@domain.com",
    "cert_template": "1.3.6.1.4.1.311.21.8.14626627.11750298.13385910.5196327.16027577.228.16764821.720296",
    "client_type": "wireless",
    "crc": [
        2761861480,
        3133665887,
        ...
    ],
    "idp_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "idp_lookup_source": "Cache",
    "idp_role": [
        "Group-1",
        "Group-n"
    ],
    "idp_username": "user@domain.com",
    "lookup_time_taken": 0.000267106,
    "mac": "xxxxxxxxxxxx",
    "nas_ip": "x.x.x.x",
    "nas_vendor": "juniper-mist",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "ssid": "SSID",
    "timestamp": 1749083558853,
    "tls_cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
    "tls_client_preferred_version": "TLS 1.3",
    "tls_states": [
        "recv TLS 1.3 ClientHello",
        "send TLS 1.2 ServerHello",
        "send TLS 1.2 Certificate",
        "send TLS 1.2 ServerKeyExchange",
        "send TLS 1.2 CertificateRequest",
        "send TLS 1.2 ServerHelloDone",
        "recv TLS 1.2 Certificate",
        "recv TLS 1.2 ClientKeyExchange",
        "recv TLS 1.2 CertificateVerify",
        "recv TLS 1.2 Finished",
        "send TLS 1.2 ChangeCipherSpec",
        "send TLS 1.2 Finished"
    ],
    "tls_version": "TLS 1.2",
    "type": "NAC_IDP_GROUPS_LOOKUP_SUCCESS",
    "username": "user@domain.com"
}
```
</br></br>



## MDM Events

NAC_CLIENT_COA_REAUTH
```json
{
    "client_type": "wired",
    "coa_source": "MDM",
    "crc": [
        1424110091,
        2795093986,
        ...
    ],
    "mac": "xxxxxxxxxxxx",
    "mdm_account_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "mdm_client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "mdm_compliance": "compliant",
    "mdm_last_checked": "2025-06-04T05:39:00Z",
    "mdm_provider": "intune",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "pre_mdm_compliance": "unknown",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "text": "Due to compliance status change",
    "timestamp": 1749090165143,
    "type": "NAC_CLIENT_COA_REAUTH"
}
```
</br></br>



NAC_MDM_LOOKUP_SUCCESS

```json
{
    "ap": "xxxxxxxxxxxx",
    "client_type": "wireless",
    "crc": [
        2939584110,
        3133665887,
        ...
    ],
    "mac": "xxxxxxxxxxxx",
    "mdm_account_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "mdm_client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "mdm_compliance": "compliant",
    "mdm_last_checked": "2025-06-04T22:59:56Z",
    "mdm_manufacturer": "Apple",
    "mdm_model": "iPhone 13",
    "mdm_operating_system": "iOS",
    "mdm_os_version": "18.5",
    "mdm_provider": "intune",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "timestamp": 1749083559682,
    "type": "",
    "username": "user@domain.com"
}
```
</br></br>




NAC_MDM_LOOKUP_FAILURE

```json
{
    "client_type": "wired",
    "crc": [
        3292832317,
        3561678071,
        ...
    ],
    "device_mac": "xxxxxxxxxxxx",
    "mac": "xxxxxxxxxxxx",
    "mdm_account_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "mdm_client_id": "xxxxxxxxxxxx",
    "mdm_provider": "intune",
    "org_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "port_id": "ge-0/0/25.0",
    "random_mac": "false",
    "site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "text": "Reason : Gateway Timeout",
    "timestamp": 1749592710466,
    "type": "NAC_MDM_LOOKUP_FAILURE",
    "username": "xxxxxxxxxxxx"
}
```
</br></br>


