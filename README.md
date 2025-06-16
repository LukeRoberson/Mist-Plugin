# Mist Plugin

Receives webhooks from Mist, filters, parses, and logs them accordingly.

Uses Flask as the web server to receive the webhooks.

Everything runs from main.py.
</br></br>


# Project Organization
## Python Files

| File             | Provided Function                                             |
| ---------------- | ------------------------------------------------------------- |
| main.py          | Entry point to the plugin, load configuration, set up routes  |
| parser.py        | Parses an event and builds fields for logging/alerting        |
| systemlog.py     | Handles sending alerts to the logging service                 |
</br></br>


## YAML Files

| File               | Provided Function                           |
| ------------------ | ------------------------------------------- |
| config.yaml        | Configuration for the plugin                |
| event_alarms.yaml  | Rules to create/format alarms               |
| event_audits.yaml  | Rules to create/format audits               |
| event_clients.yaml | Rules to create/format clients              |
| event_devices.yaml | Rules to create/format devices              |
| event_nac.yaml     | Rules to create/format nac                  |
| event_updown.yaml  | Rules to create/format updown               |
</br></br>


# Configuration

## Plugin Configuration
### Main Configuration
Configuration is handled in config.yaml. The two mandatory parts are:

```yaml
name: "Mist"
chats:
  default: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

This defines the name of the plugin, and the Teams Chat ID that alerts are sent to.

The **chats** fields is a list of chats to send to. Think of this as a list of _aliases_ of 1:1 chats or group chats.

Certain events can be sent to a specific chat destination. The **default** chat ID is for all other events (most of them really), that aren't configured with a specific chat alias.
</br></br>


### Alert Configuration

There are a series of alert types, with actions assigned. This is the action to take, such as sending to Teams, logging to live alerts, etc, when that particular event is received. They are further grouped into main areas (as defined by Mist).

For example:

```yaml
alarms:
  ap_bad_cable:
    web: true
    sql: false
    syslog: false
    teams: true
```

This is the **alarms** group (called a _topic_ in Mist documentation), with an **ap_bad_cable** alert.

A default set of actions is defined for each group, in case an unknown alert is received:

```yaml
alarms:
    default:
        web: true
        sql: false
        syslog: false
        teams: true
```

If we add the **chat** field to an event, we can send the Teams message for the event to a specific chat group. For example:

```yaml
chats:
  default: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  network_admin: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

alarms:
  ap_bad_cable:
    web: true
    sql: false
    syslog: false
    teams: true

  device_down:
    web: true
    sql: false
    syslog: false
    teams: true
    chat: network_admin
```

In this example, any **device_down** event will be sent to the **network_admin** chat ID. The **ap_bad_cable** event does not have a chat ID listed, so it will go to the **default** chat ID.


</br></br>


## Event Rules

Event rules are used for formatting logs and messages. When an event is received, it is parsed (fields are extracted), and rules are applied to create the log entries and messages.

These rules are stored in several different YAML files (event_*.yaml), which identify each Mist _topic_. For example:

```yaml
device_down:
  description: "A device has gone down, possibly due to a reboot, internet outage, or upstream failure"
  message: "Device {self.hostname} at {self.site_name} has gone down"
  severity: "warning"
```

This is an event type called **device_down** which is found in the **event_alarms.yaml** file. The description is for documentation only, and does not affect the plugin.

The **message** is the formatted output that goes to logs and optionally Teams.

Optionally a **teams** field may be present. This is for a customised Teams message. If this field is not present, the **message** field is used when sending to Teams.

The **severity** is the severity level to assign to this event, if the event doesn't come with a severity of its own.
</br></br>


# Webhooks
## Secrets

When defining a webhook in Mist, a secret may be added (which is highly recommended). When the webhook is sent, it is hashed using this secret, and is included in the **X-Mist-Signature-v2* header.

When a webhhook is received, the signature is send to the security service for validation
</br></br>


## Message Bodies

There are a lot of differently formatted message bodies depending on the topic and the event.

See the files in the **docs** folder for detailed information.
