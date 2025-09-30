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

Dependencies:
    - datetime: For handling timestamps.
    - logging: For logging events and errors.
    - flask: For accessing the current application context.
    - yaml: For loading event handler configurations from YAML files.

Custom Dependencies:
    - sdk.PluginManager: For managing plugins and configurations.
"""

# Standard library imports
from datetime import datetime
import logging
from flask import current_app
import yaml
import os
from typing import Optional

# Custom imports
from sdk import PluginManager


PLUGINS_URL = "http://core:5100/api/plugins"
PLUGIN_NAME = "mist"


CONFIG_DIR = os.path.join(os.path.dirname(__file__), "config")


# Set up logging
logging.basicConfig(level=logging.INFO)

# Get the event handler configs
with open(os.path.join(CONFIG_DIR, "event_nac.yaml"), "r") as file:
    NAC_EVENTS = yaml.safe_load(file)

with open(os.path.join(CONFIG_DIR, "event_clients.yaml"), "r") as file:
    CLIENT_EVENTS = yaml.safe_load(file)

with open(os.path.join(CONFIG_DIR, "event_devices.yaml"), "r") as file:
    DEVICE_EVENTS = yaml.safe_load(file)

with open(os.path.join(CONFIG_DIR, "event_alarms.yaml"), "r") as file:
    ALARM_EVENTS = yaml.safe_load(file)

with open(os.path.join(CONFIG_DIR, "event_audits.yaml"), "r") as file:
    AUDIT_EVENTS = yaml.safe_load(file)

with open(os.path.join(CONFIG_DIR, "event_updown.yaml"), "r") as file:
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
        chats: Optional[dict] = None,
    ) -> None:
        """
        Initialize the Events object and process the event.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        # Time the webhook was received
        #   This may be different from the event time
        self.received = datetime.now()

        # This is the original event data from the webhook
        self.event = event

        # Initialize default values
        self.group = ""
        self.category = ""

        # Collect and store fields from the raw event
        self._collect_fields()

        # Parse the event data
        self._parse(config)

        # Perform an action based on the event type
        self._action(config)

        # Store chat IDs
        self.chat_ids = chats if chats else {}

    def _collect_fields(
        self
    ) -> None:
        """
        Extract and assign relevant fields from the raw event.

        This method should be overridden by subclasses to extract
            event-specific fields.

        Args:
            None

        Returns:
            None
        """

        pass

    def _parse(
        self,
        config: dict,
    ) -> None:
        """
        Parse the raw event data and prepare it for logging.
        This method should be overridden by subclasses to implement
            event-specific parsing logic.

        Args:
            config (dict): Event handling configuration.

        Returns:
            None
        """

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

        Returns:
            None
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
                    f"{handler}: Error formatting event message for "
                    f"{self.alert}: {e}"
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

        Returns:
            None
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
        if (current_time - self.timestamp) > 600:
            # Convert timestamp to human-readable format
            event_time = datetime.fromtimestamp(
                self.timestamp
            ).strftime('%Y-%m-%d %H:%M:%S')

            logging.debug(
                "Event is older than 10 minutes (%s), not processing: %s",
                event_time,
                self.event
            )
            # Log to logging service
            system_log = current_app.config['SYSTEM_LOG']
            system_log.log(
                message=(
                    f"Event is older than 10 minutes, not processing: "
                    f"{self.event} (event time: {event_time})"
                ),
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

        # If no actions are specified, do nothing
        if not action_list:
            return

        # Check if there is a custom chat ID for Teams messages
        plugin_config = {}
        with PluginManager(PLUGINS_URL) as pm:
            plugin_config = pm.read(name=PLUGIN_NAME)

        chat_ids = {}
        if isinstance(plugin_config, dict) and 'plugin' in plugin_config:
            chat_ids = plugin_config.get('chats', {})

        teams_chat = chat_ids.get('default', None)
        if 'chat' in actions:
            teams_chat = chat_ids.get(
                actions['chat'], None
            )

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
            chat_id=teams_chat,
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
        Initialize the NacEvent object and process the event.
            Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
            This is a helper function to collect fields.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "nac"

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

        The parsed event is in the format:
            y.z
            y = Client type; wireless, wired
            z = Event type

        Args:
            config (dict): Event handling configuration.

        Returns:
            None
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
        if event_type in NAC_EVENTS:
            self._parse_event(
                event_type=event_type,
                handler_map=NAC_EVENTS,
                config=config,
                event_label="NAC"
            )
        else:
            logging.warning(f"Unhandled NAC event type: {event_type}")


class ClientEvent(Events):
    """
    Represents a Client Session object.

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
        Initialize the ClientEvent object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Add the topic to the event
        self.event["topic"] = "client"

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
        """
        Initialize the DeviceEvents object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "device"

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


class Alarms(Events):
    """
    Represents an Alarm object.

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
        Initialize the Alarms object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "alarms"

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
        self.text = self.event.get("text")

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
            (self.type is not None and 'switch' in self.type) or
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


class Audits(Events):
    """
    Represents an Audit object.

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
        Initialize the Audits object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "audits"

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

        Event is in the format:
            x.y
            x = Device type; switch, ap, etc
            y = Event type; 'type' field

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
        elif self.message is not None and "Invoked Webshell" in self.message:
            self.alert = "webshell"
        elif self.message is not None and "Login with Role" in self.message:
            self.alert = "mist-login"
        elif self.message is not None and "Accessed Org" in self.message:
            self.alert = "accessed-org"
        elif self.message is not None and "manually restarted" in self.message:
            self.alert = "restart"
        elif self.message is not None and "firmware upgrade" in self.message:
            self.alert = "firmware"
        elif self.message is not None and "Add Webhook" in self.message:
            self.alert = "add-webhook"
        elif self.message is not None and "Add NACLabel" in self.message:
            self.alert = "add-nac_label"
        elif self.message is not None and "Bouncing ports" in self.message:
            self.alert = "bounce-port"
        elif self.message is not None and "Delete NACRule" in self.message:
            self.alert = "delete-nac_rule"
        elif self.message is not None and "Update Device" in self.message:
            self.alert = "update-device"
        elif self.message is not None and "Add Subscription" in self.message:
            self.alert = "add-subscription"
        elif (
            self.message is not None and
            "Accessed by Mist Support" in self.message
        ):
            self.alert = "mist-support"
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


class DeviceUpdowns(Events):
    """
    Represents a Device Up or Down object.

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
        Initialize the DeviceUpdowns object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "updown"

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
        """
        Initialize the Location object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "location"

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
        """
        Initialize the Occupancy object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "occupancy"

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
        """
        Initialize the RssiZone object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "rssi_zone"

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
        """
        Initialize the SdkClient object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "sdkclient"

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
        """
        Initialize the VirtualBeacon object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "virtual_beacon"

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
        """
        Initialize the Zone object and process the event.
        Inherits from the base Events class.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.

        Returns:
            None
        """

        super().__init__(event, config)

    def _collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.

        Args:
            None

        Returns:
            None
        """

        # Add the topic to the event
        self.event["topic"] = "zone"

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


if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    exit(1)
