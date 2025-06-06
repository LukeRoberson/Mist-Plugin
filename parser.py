"""
Module: parser.py

Parses and handles webhook events from the Mist plugin, preparing them for
    logging to a web interface, syslog, SQL database, or Teams.

Parsing involves extracting relevant fields from the raw event data, which is
    different for each topic and event type. There is a class to represent
    each topic.
An event handler, configured as a YAML file, contains the logic for
    parsing the event data and formatting the message body for each event type.

Classes:
    - Events: Base class for all event types.
    - NacEvent: Represents a NAC event object.
    - ClientEvent: Represents a client session object.
    - DeviceEvents: Represents a device event object.
    - Alarms: Represents an alarm object.
    - Audits: Represents an audit object.
    - DeviceUpdowns: Represents a device up or down event object.
"""


from datetime import datetime
import logging
from flask import current_app
import yaml


# Set up logging
logging.basicConfig(level=logging.INFO)

# Get the event handler configs
with open("event_nac.yaml", "r") as file:
    NAC_EVENTS = yaml.safe_load(file)

with open("event_clients.yaml", "r") as file:
    CLIENT_EVENTS = yaml.safe_load(file)

with open("event_devices.yaml", "r") as file:
    DEVICE_EVENTS = yaml.safe_load(file)

with open("event_alarms.yaml", "r") as file:
    ALARM_EVENTS = yaml.safe_load(file)

with open("event_audits.yaml", "r") as file:
    AUDIT_EVENTS = yaml.safe_load(file)

with open("event_updown.yaml", "r") as file:
    UPDOWN_EVENTS = yaml.safe_load(file)


class Events:
    """
    Base class for all event types.

    This class provides the interface and common logic for parsing
        and handling webhook events.
    Subclasses should override the _collect_fields and _parse methods
        to extract and process event-specific data.

    Args:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the Events object and process the event.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Side Effects:
            Calls _collect_fields, _parse, and _action in sequence.
        """

        # Time the webhook was received
        #   This may be different from the event time
        self.received = datetime.now()

        # This is the original event data from the webhook
        self.event = event

        # Collect and store fields from the raw event
        self._collect_fields()

        # Parse the event data
        self._parse(config)

        # Perform an action based on the event type
        self._action(config)

    def __repr__(
        self
    ) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        message = f"Event:\n \
                {self.group}.{self.category}.{self.alert}\n \
                {self.timestamp}\n \
                {self.message}"

        return message

    def _collect_fields(
        self
    ) -> None:
        """
        Extract and assign relevant fields from the raw event.

        This method should be overridden by subclasses to extract
            event-specific fields.

        Returns:
            None
        """
        pass

    def _parse(
        self,
        config: dict,
    ) -> None:
        pass

    def _parse_event(
        self,
        event_type: str,
        handler_map: dict,
        config: dict,
        event_label: str = "event",
    ) -> None:
        """
        Common method to parse event data based on a handler map.

        Args:
            event_type (str): The type of the event to parse.
            handler_map (dict): A dictionary mapping event types to handlers.
            config (dict): Event handling configuration.
            event_label (str): Label for the event, used in logging.
        """

        # Set defaults
        self.teams_msg = None
        self.severity = "info"
        self.alert = event_type or "unspecified"

        # Get the handler for this event type
        handler = handler_map.get(self.alert, None)
        if handler:
            try:
                # Get the formatted message
                self.event_message = handler.get(
                    "message",
                    self.event
                ).format(self=self)

                # If there is a Teams message (optional), get it too
                self.teams_msg = handler.get("teams", None)
                if self.teams_msg:
                    self.teams_msg = self.teams_msg.format(self=self)

                # Get the severity from the handler, default to "info"
                self.severity = handler.get("severity", "info")

            except Exception as e:
                logging.error(
                    f"Error formatting event message for {self.alert}: {e}"
                )
                self.event_message = "No message included"
                self.teams_msg = str(self.event)
                self.severity = "warning"

        # If no handler is found, log as an unhandled event
        else:
            self.event_message = f"Unhandled {event_label} event: {self.event}"
            self.teams_msg = str(
                f"Unhandled {event_label} event: {self.event}"
            )

        if self.alert not in config:
            logging.info(
                f"New type of {event_label} Event alert: %s",
                self.event
            )
            self.event_message = f"Unhandled {event_label} event: {self.event}"
            self.teams_msg = str(
                f"Unhandled {event_label} event: {self.event}"
            )

        if self.teams_msg is None:
            self.teams_msg = self.event_message

    def _action(
        self,
        config: dict,
    ) -> None:
        """
        Perform configured actions for this event.

        Depending on the configuration, this may:
        - Send an alert to the web interface
        - Log to an SQL server
        - Log to a syslog server
        - Send a message to Teams

        Args:
            config (dict): Event handling configuration specifying which
                actions to perform.
        """

        # Log if the event does not have a timestamp
        if not self.timestamp:
            logging.error(
                "Event without a timestamp.",
                self.event
            )

        # Convert timestamp to seconds if it's in milliseconds
        if self.timestamp > 10000000000:
            self.timestamp = self.timestamp / 1000

        # If the event is older than 5 minutes, do not process it
        current_time = datetime.now().timestamp()
        if (current_time - self.timestamp) > 300:
            logging.warning(
                "Event is older than 5 minutes, not processing: %s",
                self.event
            )
            return

        # Get the actions to perform
        if self.alert in config:
            actions = config[self.alert]
        else:
            actions = config["default"]

        # Convert this to a list of actions, add to the parsed body
        action_list = []
        action_list = [
            k for k in ("web", "teams", "syslog", "sql") if actions.get(k)
        ]
        self.parsed_body["destination"] = action_list

        # If no actions are specified, do nothing
        if not action_list:
            return

        # Log to logging service
        system_log = current_app.config['SYSTEM_LOG']
        system_log.log(
            message=self.event_message,
            destination=action_list,
            group=self.group,
            category=self.category,
            alert=self.alert,
            severity=self.severity,
            teams_msg=self.teams_msg,
        )


class NacEvent(Events):
    """
    Represents a NacEvent object.
        One single NAC event is logged here.
        One web hook from Mist may contain multiple NAC events.

    This includes events such as:
        - Authentication succeeds or fails
        - NAC rule applied
        - VLAN assigned
        - Client or server certificate validation
        - MDM evaluation
        - IDP lookup
        - WiFi device roaming
        - Client session started or ended

    Methods:
        __init__(self, event: dict): Initializes the NacEvent object.
        __repr__(self): Returns a string representation of the NacEvent object.
        __collect_fields(self): Collects fields from the raw event.
        __parse(self): Parses the raw event data.
        __action(self, config: dict): Performs an action based on the event.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Certificate information
        self.cert_cn = self.event.get("cert_cn")
        self.cert_expiry = self.event.get("cert_expiry")
        self.cert_issuer = self.event.get("cert_issuer")
        self.cert_san_dns = self.event.get("cert_san_dns")
        self.cert_serial = self.event.get("cert_serial")
        self.cert_subject = self.event.get("cert_subject")
        self.cert_template = self.event.get("cert_template")
        self.cert_san_upn = self.event.get("cert_san_upn")
        self.cert_san_email = self.event.get("cert_san_email")

        # TLS information
        self.tls_cipher_suite = self.event.get("tls_cipher_suite")
        self.tls_client_preferred_version = self.event.get(
            "tls_client_preferred_version"
        )
        self.tls_version = self.event.get("tls_version")

        # IDP information
        self.idp_id = self.event.get("idp_id")
        self.idp_lookup_source = self.event.get("idp_lookup_source")
        self.idp_role = self.event.get("idp_role")
        self.idp_username = self.event.get("idp_username")
        self.lookup_time_taken = self.event.get("lookup_time_taken")

        # 802.1x authentication components
        self.auth_type = self.event.get("auth_type")
        self.username = self.event.get("username")
        self.nas_ip = self.event.get("nas_ip")
        self.nas_vendor = self.event.get("nas_vendor")
        self.resp_attrs = self.event.get("resp_attrs")

        # NAC Rules
        self.nacrule_id = self.event.get("nacrule_id")
        self.nacrule_matched = self.event.get("nacrule_matched")
        self.nacrule_name = self.event.get("nacrule_name")

        # NAC Actions
        self.usermac_labels = self.event.get("usermac_labels")
        self.vlan = self.event.get("vlan")
        self.egress_vlan_names = self.event.get("egress_vlan_names")
        self.vlan_source = self.event.get("vlan_source")
        self.device_macs = self.event.get("device_macs")

        # Client information
        self.client_type = self.event.get("client_type")
        self.device_mac = self.event.get("device_mac")
        self.mac = self.event.get("mac")
        self.random_mac = self.event.get("random_mac")
        self.port_id = self.event.get("port_id")
        self.client_ip = self.event.get("client_ip")
        self.client_ips = self.event.get("client_ips")

        # Network information
        self.ssid = self.event.get("ssid")
        self.ap = self.event.get("ap")
        self.bssid = self.event.get("bssid")
        self.aps = self.event.get("aps")
        self.bssids = self.event.get("bssids")

        # MDM information
        self.mdm_account_id = self.event.get("mdm_account_id")
        self.mdm_client_id = self.event.get("mdm_client_id")
        self.mdm_compliance = self.event.get("mdm_compliance")
        self.mdm_last_checked = self.event.get("mdm_last_checked")
        self.mdm_manufacturer = self.event.get("mdm_manufacturer")
        self.mdm_model = self.event.get("mdm_model")
        self.mdm_operating_system = self.event.get("mdm_operating_system")
        self.mdm_os_version = self.event.get("mdm_os_version")
        self.mdm_provider = self.event.get("mdm_provider")
        self.coa_source = self.event.get("coa_source")
        self.pre_mdm_compliance = self.event.get("pre_mdm_compliance")

        # Session information
        self.session_duration_in_mins = self.event.get(
            "session_duration_in_mins"
        )
        self.session_ended_at = self.event.get("session_ended_at")
        self.session_last_updated_at = self.event.get(
            "session_last_updated_at"
        )
        self.session_started_at = self.event.get("session_started_at")
        self.total_bytes_received = self.event.get("total_bytes_received")
        self.total_bytes_sent = self.event.get("total_bytes_sent")
        self.total_packets_received = self.event.get(
            "total_packets_received"
        )
        self.total_packets_sent = self.event.get("total_packets_sent")
        self.rx_bytes = self.event.get("rx_bytes")
        self.rx_pkts = self.event.get("rx_pkts")
        self.tx_bytes = self.event.get("tx_bytes")
        self.tx_pkts = self.event.get("tx_pkts")

        # Other useful fields
        self.site_id = self.event.get("site_id")
        self.type = self.event.get("type")
        self.text = self.event.get("text")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Wireless events usually have a 'type' field
            This is used to determine the event type
        Wired events do not have a 'type' field
            They require some extra parsing to determine the event type

        Event is in the format:
            y.z
            y = Client type; wireless, wired
            z = Event type
        """

        # Set the group
        self.group = "nac"

        # Get the category
        if self.client_type and self.client_type == "wireless":
            self.category = "wireless"
        elif self.client_type and self.client_type == "wired":
            self.category = "wired"
        elif self.port_id:
            self.category = "wired"
        else:
            self.category = "unspecified"

        # Get the event type
        event_type = self.type if self.type else "unspecified"

        # Parse the event
        self._parse_event(
            event_type,
            NAC_EVENTS,
            config,
            event_label="NAC"
        )

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class ClientEvent(Events):
    """
    Represents a Client Session object.

    Methods:
        __init__(self, event: dict): Initializes the ClientSessions object.
        __repr__(self): Returns a string representation of the object.
        __collect_fields(self): Collects fields from the raw event.
        __parse(self): Parses the raw event data.
        __action(self, config: dict): Performs an action based on the event.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Get the timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # If no timestamp is provided, use the current time
        if not self.timestamp:
            self.timestamp = datetime.now()

        # Client Details
        self.client_family = self.event.get("client_family")
        self.client_manufacture = self.event.get("client_manufacture")
        self.client_model = self.event.get("client_model")
        self.client_os = self.event.get("client_os")
        self.mac = self.event.get("mac")
        self.random_mac = self.event.get("random_mac")
        self.client_hostname = self.event.get("client_hostname")
        self.client_username = self.event.get("client_username")
        self.client_ip = self.event.get("client_ip")

        # Network Details
        self.ap = self.event.get("ap")
        self.ap_name = self.event.get("ap_name")
        self.next_ap = self.event.get("next_ap")
        self.band = self.event.get("band")
        self.wlan_id = self.event.get("wlan_id")
        self.ssid = self.event.get("ssid")
        self.bssid = self.event.get("bssid")
        self.rssi = self.event.get("rssi")
        self.ip = self.event.get("ip")

        # Connect/Disconnect Details
        self.connect = self.event.get("connect")
        self.connect_float = self.event.get("connect_float")
        self.disconnect = self.event.get("disconnect")
        self.disconnect_float = self.event.get("disconnect_float")
        self.duration = self.event.get("duration")
        self.termination_reason = self.event.get("termination_reason")

        # Other useful fields
        self.site_id = self.event.get("site_id")
        self.site_name = self.event.get("site_name")
        self.version = self.event.get("version")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            y.z
            y = Client type; wireless, wired
            z = Event type
        """

        # Set the group
        self.group = "client"

        # Get the category
        self.category = "wireless"

        # Get the event type
        if self.connect and self.disconnect:
            self.alert = "disconnect"
        elif self.connect and self.client_username:
            self.alert = "user-connect"
        elif self.connect:
            self.alert = "guest-connect"
        else:
            self.alert = "client-info"

        # Client events don't have a 'type' field, so add it
        self.event["type"] = self.alert
        self.type = self.alert
        event_type = self.type if self.type else "unspecified"

        # Parse the event
        self._parse_event(
            event_type,
            CLIENT_EVENTS,
            config,
            event_label="Client"
        )

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class DeviceEvents(Events):
    """
    Represents a Device Event object.

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Device Details
        self.device_name = self.event.get("device_name")
        self.device_type = self.event.get("device_type")
        self.type = self.event.get("type")
        self.mac = self.event.get("mac")
        self.model = self.event.get("model")
        self.port_id = self.event.get("port_id")

        # WiFi device Details
        self.ap = self.event.get("ap")
        self.ap_name = self.event.get("ap_name")
        self.band = self.event.get("band")
        self.bandwidth = self.event.get("bandwidth")
        self.channel = self.event.get("channel")
        self.power = self.event.get("power")
        self.pre_bandwidth = self.event.get("pre_bandwidth")
        self.pre_channel = self.event.get("pre_channel")
        self.pre_power = self.event.get("pre_power")
        self.pre_usage = self.event.get("pre_usage")
        self.usage = self.event.get("usage")

        # Other useful fields
        self.site_id = self.event.get("site_id")
        self.site_name = self.event.get("site_name")
        self.text = self.event.get("text")
        self.ev_type = self.event.get("ev_type")
        self.reason = self.event.get("reason")
        self.ext_ip = self.event.get("ext_ip")
        self.audit_id = self.event.get("audit_id")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        # Set the group
        self.group = "device"

        # Get the category
        if self.device_type:
            self.category = self.device_type
        else:
            self.category = "unspecified"

        # Get the event type
        event_type = self.type if self.type else "unspecified"

        # Parse the event
        self._parse_event(
            event_type,
            DEVICE_EVENTS,
            config,
            event_label="Device"
        )

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class Alarms(Events):
    """
    Represents an Alarm object.

    Methods:
        __init__(self, event: dict): Initializes the Alarms object.
        __repr__(self): Returns a string representation of the Alarms object.
        __collect_fields(self): Collects fields from the raw event.
        __parse(self): Parses the raw event data.
        __action(self, config: dict): Performs an action based on the event.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Alert Details
        self.severity = self.event.get("severity")
        self.reasons = self.event.get("reasons")
        self.start = self.event.get("start")
        self.when = self.event.get("when")
        self.alert_id = self.event.get("alert_id")
        self.category = self.event.get("category")
        self.details = self.event.get("details")
        self.email_content = self.event.get("email_content")
        self.resolved_time = self.event.get("resolved_time")
        self.root_cause = self.event.get("root_cause")
        self.status = self.event.get("status")
        self.suggestion = self.event.get("suggestion")
        self.message = self.event.get("message")
        self.last_seen = self.event.get("last_seen")

        # Device/Client Information
        self.type = self.event.get("type")
        self.model = self.event.get("model")
        self.fw_version = self.event.get("fw_version")
        self.hostnames = self.event.get("hostnames")
        self.id = self.event.get("id")
        self.port_ids = self.event.get("port_ids")
        self.vlans = self.event.get("vlans")
        self.macs = self.event.get("macs")
        self.hostname = self.event.get("hostname")

        # Network Information
        self.aps = self.event.get("aps")
        self.ssids = self.event.get("ssids")
        self.switches = self.event.get("switches")
        self.wlan_ids = self.event.get("wlan_ids")
        self.port_id = self.event.get("port_id")

        # Other useful fields
        self.count = self.event.get("count")
        self.group = self.event.get("group")
        self.peer = self.event.get("peer")
        self.site_id = self.event.get("site_id")
        self.site_name = self.event.get("site_name")
        self.client_count = self.event.get("client_count")
        self.incident_count = self.event.get("incident_count")
        self.servers = self.event.get("servers")
        self.impacted_client_count = self.event.get(
            "impacted_client_count"
        )
        self.impacted_entities = self.event.get("impacted_entities")
        self.admin_name = self.event.get("admin_name")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Category; wireless, connectivity, etc
            y = Event type; 'type' field

        While listed as 'device' here, this could be more than a single
            device, such as ane entire WLAN or service such as DHCP.

        Where possible the parsed message is taken from the text field.

        Arguments:
            config (dict): Event handling configuration.
        """

        # Set the group
        if not self.group:
            self.group = "alarm"

        # Get the category
        if self.category:
            self.category = self.category
        elif (
            ('switch' in self.type) or
            (self.type and self.type.startswith('sw_')) or
            (self.port_ids) or
            (self.port_id)
        ):
            self.category = "switch"
        elif (
            self.type and self.type.startswith('ap_') or
            self.aps
        ):
            self.category = "wireless"
        elif self.admin_name:
            self.category = "admin-action"
        elif self.severity == "info":
            self.category = "info"
        else:
            self.category = "unspecified"

        # Get the event type
        event_type = self.type if self.type else "unspecified"

        # Parse the event
        self._parse_event(
            event_type,
            ALARM_EVENTS,
            config,
            event_label="Alarm"
        )

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "type": f"{self.group}.{self.category}.{self.alert}",
                "timestamp": self.timestamp,
                "message": self.event_message
            }
        }


class Audits(Events):
    """
    Represents an Audit object.

    Methods:
        __init__(self, event: dict): Initializes the Audits object.
        __repr__(self): Returns a string representation of the Audits object.
        __collect_fields(self): Collects fields from the raw event.
        __parse(self): Parses the raw event data.
        __action(self, config: dict): Performs an action based on the event.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Admin Details
        self.admin_name = self.event.get("admin_name")
        self.src_ip = self.event.get("src_ip")
        self.user_agent = self.event.get("user_agent")

        # Device Details
        self.device_id = self.event.get("device_id")
        self.site_id = self.event.get("site_id")
        self.site_name = self.event.get("site_name")

        # Config changes
        self.after = self.event.get("after")
        self.before = self.event.get("before")

        # Other useful fields
        self.id = self.event.get("id")
        self.message = self.event.get("message")
        self.webhook_id = self.event.get("webhook_id")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Arguments:
            config (dict): Event handling configuration.
        """

        # Set the group
        self.group = "audit"

        # Get the category
        self.category = "audit"

        # Get the event type
        if self.before and self.after:
            self.alert = "configuration"
        elif "Invoked Webshell" in self.message:
            self.alert = "webshell"
        elif "Login with Role" in self.message:
            self.alert = "mist-login"
        elif "Accessed Org" in self.message:
            self.alert = "accessed-org"
        elif "manually restarted" in self.message:
            self.alert = "restart"
        elif "firmware upgrade" in self.message:
            self.alert = "firmware"
        elif "Add Webhook" in self.message:
            self.alert = "add-webhook"
        else:
            self.alert = "unspecified"

        # There is no 'type' field in audit events, so set it to the alert
        self.type = self.alert
        event_type = self.type if self.type else "unspecified"

        # Parse the event
        self._parse_event(
            event_type,
            AUDIT_EVENTS,
            config,
            event_label="Audit"
        )

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message
            }
        }


class DeviceUpdowns(Events):
    """
    Represents a Device Up or Down object.

    Methods:
        __init__(self, event: dict): Initializes the DeviceUpdowns object.
        __repr__(self): Returns a string representation of the object.
        __collect_fields(self): Collects fields from the raw event.
        __parse(self): Parses the raw event data.
        __action(self, config: dict): Performs an action based on the event.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Device Details
        self.device_type = self.event.get("device_type")
        self.device_name = self.event.get("device_name")
        self.ap = self.event.get("ap")
        self.ap_name = self.event.get("ap_name")
        self.mac = self.event.get("mac")
        self.model = self.event.get("model")

        # Other useful fields
        self.audit_id = self.event.get("audit_id")
        self.ev_type = self.event.get("ev_type")
        self.reason = self.event.get("reason")
        self.site_id = self.event.get("site_id")
        self.site_name = self.event.get("site_name")
        self.type = self.event.get("type")
        self.ext_ip = self.event.get("ext_ip")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Where possible the parsed message is taken from the text field.

        Arguments:
            config (dict): Event handling configuration.
        """

        # Set the group
        self.group = "device-updown"

        # Get the category
        if self.device_type:
            self.category = self.device_type
        else:
            self.category = "unspecified"

        # Get the alert type
        event_type = self.type if self.type else "unspecified"

        # Parse the event
        self._parse_event(
            event_type,
            UPDOWN_EVENTS,
            config,
            event_label="UpDown"
        )

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message
            }
        }


class Location(Events):
    """
    Represents a Location event object. This refers to a map location in Mist

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Device details. 'type' is 'wifi'
        self.type = self.event.get("type")
        self.mac = self.event.get("mac")

        # Location details
        self.map_id = self.event.get("map_id")
        self.site_id = self.event.get("site_id")
        self.x = self.event.get("x")
        self.y = self.event.get("y")
        self.rssi = self.event.get("rssi")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        # Set log fields
        self.group = "location"
        self.category = "wifi"
        self.alert = "coordinate"
        self.severity = "info"

        # Set the log mesages
        self.event_message = (
            f"Location event: {self.mac} at ({self.x}, {self.y}) "
            f"on map {self.map_id}"
        )
        self.teams_msg = f"Location event for {self.mac}"

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class Occupancy(Events):
    """
    Represents an Occupancy event object.

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        pass

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        self.group = "occupancy"
        self.category = "unspecified"
        self.alert = "unspecified"
        self.severity = "info"
        self.timestamp = datetime.now().timestamp()
        self.event_message = str(self.event)
        self.teams_msg = None

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class RssiZone(Events):
    """
    Represents an RSSI Zone event object.

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        pass

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        self.group = "RSSI Zone"
        self.category = "unspecified"
        self.alert = "unspecified"
        self.severity = "info"
        self.timestamp = datetime.now().timestamp()
        self.event_message = str(self.event)
        self.teams_msg = None

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class SdkClient(Events):
    """
    Represents an SDK Client Scan event object.

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        pass

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        self.group = "SDK Client Scan"
        self.category = "unspecified"
        self.alert = "unspecified"
        self.severity = "info"
        self.timestamp = datetime.now().timestamp()
        self.event_message = str(self.event)
        self.teams_msg = None

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class VirtualBeacon(Events):
    """
    Represents a Virtual Beacon event object.

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        pass

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        self.group = "Virtual Beacon"
        self.category = "unspecified"
        self.alert = "unspecified"
        self.severity = "info"
        self.timestamp = datetime.now().timestamp()
        self.event_message = str(self.event)
        self.teams_msg = None

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


class Zone(Events):
    """
    Represents a Zone event object.

    Arguments:
        event (dict): The raw event data from the webhook.
        config (dict): Event handling configuration.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.event.get("timestamp")

        # Device details. 'type' is 'wifi'
        self.type = self.event.get("type")
        self.mac = self.event.get("mac")

        # Event trigger (eg, 'exit' a zone)
        self.trigger = self.event.get("trigger")

        # Zone details
        self.map_id = self.event.get("map_id")
        self.site_id = self.event.get("site_id")
        self.zone_id = self.event.get("zone_id")

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data.
        Collates all the fields into a useful alert

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

        Arguments:
            config (dict): Event handling configuration.
        """

        # Set log fields
        self.group = "Zone"
        self.category = "wifi"
        self.alert = self.trigger if self.trigger else "unspecified"
        self.severity = "info"

        # Set the log mesages
        self.event_message = (
            f"{self.mac} has {self.trigger}ed zone {self.zone_id} "
            f"on map {self.map_id} at site {self.site_id}"
        )
        self.teams_msg = f"{self.mac} zone {self.trigger} event"

        # Collect all the information we need into a single dictionary
        self.parsed_body = {
            "source": "mist",
            "destination": ["web"],
            "log": {
                "group": self.group,
                "category": self.category,
                "alert": self.alert,
                "severity": self.severity,
                "timestamp": self.timestamp,
                "message": self.event_message,
            }
        }


if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    exit(1)
