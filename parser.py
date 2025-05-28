"""
Webhook Parser

This module provides classes to represent and parse webhooks from
    the Mist plugin.
Each class corresponds to a specific event type
    (e.g., NAC events, client sessions, device events).
Subclasses of Events extract relevant fields, parse event data,
    and perform configured actions.

Functions:
    - send_log: Sends a log message to the logging service.
        This is used to log events and errors.

Classes:
    - NacEvent: Represents a NAC event object.
    - ClientEvent: Represents a client session object.
    - DeviceEvents: Represents a device event object.
    - Alarms: Represents an alarm object.
    - Audits: Represents an audit object.
    - DeviceUpdowns: Represents a device up or down event object.
"""


from datetime import datetime
import logging

from systemlog import system_log


# Set up logging
logging.basicConfig(level=logging.INFO)


class Events:
    """
    Base class for all event types.

    This class provides the interface and common logic for parsing
        and handling webhook events.
    Subclasses should override the _collect_fields and _parse methods
        to extract and process event-specific data.
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
        system_log.log(
            message=self.event_message,
            destination=action_list,
            group=self.group,
            category=self.category,
            alert=self.alert,
            severity=self.severity,
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

        # Get the Event
        if self.type:
            self.alert = self.type
        else:
            self.alert = "unspecified"

        # Get the severity
        self.severity = "info"

        # Create a custom message where appropriate
        if self.type:
            # NAC Accounting events
            if self.type == "NAC_ACCOUNTING_START":
                self.event_message = (
                    f"Client session started for {self.username}"
                )
            elif self.type == "NAC_ACCOUNTING_STOP":
                self.event_message = (
                    f"Client session ended for {self.username}"
                )
            elif self.type == "NAC_ACCOUNTING_UPDATE":
                self.event_message = (
                    f"Client session updated for {self.username}"
                )
            elif self.type == "NAC_CLIENT_PERMIT":
                self.event_message = (
                    f"Client permit for {self.username}, VLAN {self.vlan}"
                )
            elif self.type == "NAC_SESSION_STARTED":
                self.event_message = (
                    f"Client session started for {self.username}"
                )
            elif self.type == "NAC_SESSION_ENDED":
                self.event_message = (
                    f"Client session ended for {self.username}"
                )
            elif self.type == "NAC_CLIENT_DENY":
                self.event_message = (
                    f"Client deny for {self.username}. "
                    f"{self.text}"
                )

            # Certificate events
            elif self.type == "NAC_CLIENT_CERT_CHECK_SUCCESS":
                self.event_message = (
                    f"Client certificate check succeeded for {self.cert_cn}"
                )
            elif self.type == "NAC_SERVER_CERT_VALIDATION_SUCCESS":
                self.event_message = (
                    f"Server certificate validation succeeded "
                    f"for {self.username}"
                )

            # MDM events
            elif self.type == "NAC_MDM_LOOKUP_SUCCESS":
                self.event_message = (
                    f"MDM lookup succeeded for {self.username}. "
                    f"{self.mdm_manufacturer} {self.mdm_model} "
                    f"is {self.mdm_compliance}"
                )
            elif self.type == "NAC_MDM_DEVICE_NOT_ENROLLED":
                self.event_message = (
                    f"MDM device not enrolled for {self.username}. {self.text}"
                )

            # IDP events
            elif self.type == "NAC_IDP_GROUPS_LOOKUP_SUCCESS":
                self.event_message = (
                    f"IDP groups lookup succeeded for {self.username}"
                )
            elif self.type == "NAC_IDP_AUTHC_SUCCESS":
                self.event_message = (
                    f"IDP authentication succeeded for {self.username}"
                )

            # Other events
            elif self.type == "NAC_CLIENT_IP_ASSIGNED":
                self.event_message = (
                    f"Client IP assigned for {self.username}. {self.client_ip}"
                )

            # When not explicitly handled, use 'text', or a default message
            elif self.text:
                self.event_message = self.text
            else:
                self.event_message = "No message included"

        # If no custom message, use the text field where available
        elif self.text:
            self.event_message = self.text

        else:
            self.event_message = "No message included"

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

        # Display alert if the event type is not in the config
        if self.alert not in config:
            logging.info(
                "New type of NAC Event alert: %s",
                self.event
            )

        # Debug if there's not enough information
        if (
            self.alert == "unspecified" or
            self.event_message == "No message included"
        ):
            logging.error(
                "NAC event without enough information:\n",
                f"{self.group}.{self.category}{self.alert}\n",
                f"Message: {self.event_message}\n",
                f"Original event: {self.event}\n",
            )


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

        # Get the Event
        if self.connect and self.disconnect:
            self.alert = "disconnect"
        elif self.connect:
            self.alert = "connect"
        else:
            self.alert = "client-info"

        # Create a custom message
        if self.alert == "disconnect":
            self.event_message = (
                f"Client {self.mac} at {self.site_name} "
                f"has disconnected from {self.ssid}"
            )
        elif self.alert == "connect":
            self.event_message = (
                f"Client {self.mac} at {self.site_name} "
                f"has connected to {self.ssid}"
            )
        elif self.alert == "client-info":
            self.event_message = (
                f"Client {self.mac} has IP {self.ip} "
                f"and is in site {self.site_id}"
            )
        else:
            self.event_message = "No message included"

        # Set the severity
        self.severity = "info"

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

        # Display alert if the event type is not in the config
        if self.alert not in config:
            logging.info(
                "New type of Client Event alert: %s",
                self.event
            )

        # Debug if there's not enough information
        if (
            self.alert == "unspecified" or
            self.event_message == "No message included"
        ):
            logging.error(
                "Client event without enough information:\n",
                f"{self.group}.{self.category}.{self.alert}\n",
                f"Message: {self.event_message}\n",
                f"Original event: {self.event}\n"
            )


class DeviceEvents(Events):
    """
    Represents a Device Event object.

    Methods:
        __init__(self, event: dict): Initializes the DeviceEvents object.
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

        Where possible the parsed message is taken from the text field.

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
        if self.type:
            self.alert = self.type
        else:
            self.alert = "unspecified"

        # Need to set a nice message
        if self.text:
            self.event_message = self.text
        elif self.type == 'AP_RESTARTED':
            self.event_message = (
                f"{self.ap_name} at {self.site_name} has restarted "
                f"({self.reason})"
            )
        elif self.type == 'AP_RESTART_BY_USER':
            self.event_message = (
                f"{self.ap_name} at {self.site_name} has been restarted "
                f"by an administrator"
            )
        elif self.type == 'AP_CONNECTED':
            self.event_message = (
                f"{self.ap_name} at {self.site_name} has connected "
            )
        elif self.type == 'AP_DISCONNECTED':
            self.event_message = (
                f"{self.ap_name} at {self.site_name} has disconnected "
            )
        elif self.type == 'AP_CONFIGURED':
            self.event_message = (
                f"{self.ap_name} at {self.site_name} has been configured"
            )
        elif (
            self.type == 'AP_CONFIG_CHANGED_BY_RRM' or
            self.type == 'AP_RRM_ACTION'
        ):
            self.event_message = (
                f"{self.ap_name} at {self.site_name} has been tuned by RRM"
            )
        else:
            self.event_message = "No message included"

        # Set the severity
        self.severity = "info"

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

        # Display alert if the event type is not in the config
        if self.alert not in config:
            logging.info(
                "New type of Device Event alert: %s",
                self.event
            )

        # Debug if there's not enough information
        if (
            self.category == "unspecified" or
            self.alert == "unspecified" or
            self.event_message == "No message included"
        ):
            logging.error(
                "Device event without enough information:\n",
                f"{self.group}.{self.category}.{self.alert}\n",
                f"Message: {self.event_message}\n",
                f"Original event: {self.event}\n"
            )


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

        # Get the Event
        if self.group == "marvis" and self.type:
            self.alert = f"marvis-{self.type}"
        elif self.type:
            self.alert = self.type
        elif self.group == "marvis":
            self.alert = "marvis"
        elif "restarted" in self.message:
            self.alert = "restart"
        else:
            self.alert = "unspecified"

        # Set a message
        if self.reasons:
            self.event_message = (
                f"Host {self.hostnames} has experienced an alarm: "
                f"{self.reasons}"
            )
        elif self.type == "infra_dhcp_success":
            self.event_message = (
                f"DHCP success on VLAN {self.vlans} at {self.site_name}"
            )
        elif self.type == "infra_dhcp_failure":
            self.event_message = (
                f"DHCP failure on VLAN {self.vlans} at {self.site_name} "
                f"on SSID {self.ssids}"
            )
        elif self.type == "infra_arp_success":
            self.event_message = (
                f"ARP success on VLAN {self.vlans} at {self.site_name}"
            )
        elif self.type == "infra_arp_failure":
            self.event_message = (
                f"ARP failure on VLAN {self.vlans} at {self.site_name}"
            )
        elif self.type == "infra_dns_failure":
            self.event_message = (
                f"DNS failure on SSID {self.ssids} at {self.site_name} "
                f"on VLAN {self.vlans}. "
                f"Affecting {self.client_count} clients."
            )
        elif self.type == "infra_dns_success":
            self.event_message = (
                f"DNS success at {self.site_name} "
                f"on VLAN {self.vlans}"
            )
        elif self.message and "manually restarted" in self.message:
            self.event_message = (
                f"{self.message} by {self.admin_name} at {self.site_name}"
            )
        elif (
            self.alert == "device_down" or
            self.alert == "switch_down"
        ):
            self.event_message = (
                f"Device {self.hostname} at {self.site_name} "
                f"has gone down"
            )
        elif (
            self.alert == "device_reconnected" or
            self.alert == "switch_reconnected"
        ):
            self.event_message = (
                f"Device {self.hostname} at {self.site_name} "
                f"has reconnected"
            )
        elif "marvis" in self.alert:
            self.event_message = (
                f"Marvis has detected an issue with {self.category}. "
                f"{self.impacted_client_count} clients affected "
                f"on {self.impacted_entities['entity_name']} "
                f"at {self.site_name}"
            )
        else:
            self.event_message = "No message included"

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

        # Display alert if the event type is not in the config
        if self.alert not in config:
            logging.info(
                "New type of Alarm Event alert: %s",
                self.event
            )

        # Debug if there's not enough information
        if (
            self.category == "unspecified" or
            self.alert == "unspecified" or
            self.event_message == "No message included"
        ):
            logging.error(
                "Alarm event without enough information:\n",
                f"{self.group}.{self.category}.{self.alert}\n",
                f"Message: {self.event_message}\n",
                f"Original event: {self.event}\n"
            )


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

        # Get the Event
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
        else:
            self.alert = "unspecified"

        # Set a message
        if self.alert == "configuration":
            self.event_message = (
                f"{self.admin_name}: {self.message}\nfrom {self.before} "
                f"to {self.after}"
            )
        elif self.alert == "webshell":
            self.event_message = (
                f"{self.admin_name} {self.message} "
                f"from {self.src_ip} at {self.site_name}"
            )
        elif (
            self.alert == "mist-login" or
            self.alert == "accessed-org"
        ):
            self.event_message = (
                f"{self.admin_name}: {self.message} "
                f"from {self.src_ip}"
            )
        elif self.alert == "restart":
            self.event_message = (
                f"{self.admin_name} has restarted the device "
                f"from {self.src_ip} at {self.site_name}"
            )
        elif (
            self.alert == "firmware" and
            "scheduled" in self.message
        ):
            self.event_message = (
                f"{self.admin_name} has scheduled a firmware upgrade "
                f"from {self.src_ip} at {self.site_name}:\n"
                f"{self.message}"
            )
        else:
            self.event_message = "No message included"

        # Set the severity
        self.severity = "info"

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

        # Display alert if the event type is not in the config
        if self.alert not in config:
            logging.info(
                "New type of Audit alert: %s",
                self.event
            )

        # Debug if there's not enough information
        if (
            self.alert == "unspecified" or
            self.event_message == "No message included"
        ):
            logging.error(
                "Audit event without enough information:\n",
                f"{self.alert}\n",
                f"Message: {self.event_message}\n",
                f"Original event: {self.event}\n"
            )


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
        if self.type:
            self.alert = self.type
        else:
            self.alert = "unspecified"

        # Need to set a nice message
        if (
            self.type == "AP_RESTARTED" or
            self.type == "SW_RESTARTED"
        ):
            self.event_message = (
                f"{self.device_name} in {self.site_name} has restarted. "
                f"Reason: {self.reason}"
            )
        elif (
            self.type == "AP_DISCONNECTED" or
            self.type == "SW_DISCONNECTED"
        ):
            self.event_message = (
                f"{self.device_name} in {self.site_name} has disconnected."
            )
        elif (
            self.type == "AP_CONNECTED" or
            self.type == "SW_CONNECTED"
        ):
            self.event_message = (
                f"{self.device_name} in {self.site_name} has connected."
            )
        else:
            self.event_message = "No message included"

        # Set the severity
        self.severity = "info"

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

        # Display alert if the event type is not in the config
        if self.alert not in config:
            logging.info(
                "New type of Device Up/Down Event alert: %s",
                self.event
            )

        # Debug if there's not enough information
        if (
            self.category == "unspecified" or
            self.alert == "unspecified" or
            self.event_message == "No message included"
        ):
            logging.error(
                "Device Updown event without enough information:\n",
                f"{self.group}.{self.category}.{self.alert}\n",
                f"Message: {self.event_message}\n",
                f"Original event: {self.event}\n"
            )


if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    exit(1)
