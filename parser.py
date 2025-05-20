"""
Webhook Parser

Classes to represent and parse webhooks from the Mist plugin.
    - NacEvent: Represents a NAC event object.
    - ClientEvent: Represents a client session object.
    - DeviceEvents: Represents a device event object.
    - Alarms: Represents an alarm object.
    - Audits: Represents an audit object.
    - DeviceUpdowns: Represents a device up or down event object.
"""


from datetime import datetime
from colorama import Fore, Style
import copy


class NacEvent:
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

    As fields are processed, they are removed from the raw_event dictionary.
        This is so we can see if there are any fields left over
            that we weren't expecting.

    Methods:
        __init__(self, event: dict): Initializes the NacEvent object.
        __repr__(self): Returns a string representation of the NacEvent object.
        __collect_fields(self): Collects fields from the raw event.
            This is a helper function to collect fields from the raw event.
        __parse(self): Parses the raw event data.
    """

    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the NacEvent object.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.
        """

        # Set up some empty fields
        #   These will be filled in as the event is processed
        self.received = datetime.now()

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event
        self.original_event = copy.deepcopy(event)

        # Remove some fields that are not needed
        self.raw_event.pop("crc", None)
        self.raw_event.pop("org_id", None)
        self.raw_event.pop("tls_states", None)
        self.raw_event.pop("cert_template", None)

        # Collect and store fields from the raw event
        self.__collect_fields()

        # Parse the event data
        self.__parse()

    def __repr__(self) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        message = f"NACEvent:\n \
                {self.parsed_client_type}.{self.parsed_event_type}\n \
                {self.timestamp}\n \
                {self.parsed_message}"

        return message

    def __collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # The timestamp (epoch) that the event occurred
        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)

        # Certificate information
        self.cert_cn = self.raw_event.get("cert_cn")
        self.raw_event.pop("cert_cn", None)

        self.cert_expiry = self.raw_event.get("cert_expiry")
        self.raw_event.pop("cert_expiry", None)

        self.cert_issuer = self.raw_event.get("cert_issuer")
        self.raw_event.pop("cert_issuer", None)

        self.cert_san_dns = self.raw_event.get("cert_san_dns")
        self.raw_event.pop("cert_san_dns", None)

        self.cert_serial = self.raw_event.get("cert_serial")
        self.raw_event.pop("cert_serial", None)

        self.cert_subject = self.raw_event.get("cert_subject")
        self.raw_event.pop("cert_subject", None)

        self.cert_template = self.raw_event.get("cert_template")
        self.raw_event.pop("cert_template", None)

        self.cert_san_upn = self.raw_event.get("cert_san_upn")
        self.raw_event.pop("cert_san_upn", None)

        self.cert_san_email = self.raw_event.get("cert_san_email")
        self.raw_event.pop("cert_san_email", None)

        # TLS information
        self.tls_cipher_suite = self.raw_event.get("tls_cipher_suite")
        self.raw_event.pop("tls_cipher_suite", None)

        self.tls_client_preferred_version = self.raw_event.get(
            "tls_client_preferred_version"
        )
        self.raw_event.pop("tls_client_preferred_version", None)

        self.tls_version = self.raw_event.get("tls_version")
        self.raw_event.pop("tls_version", None)

        # IDP information
        self.idp_id = self.raw_event.get("idp_id")
        self.raw_event.pop("idp_id", None)

        self.idp_lookup_source = self.raw_event.get("idp_lookup_source")
        self.raw_event.pop("idp_lookup_source", None)

        self.idp_role = self.raw_event.get("idp_role")
        self.raw_event.pop("idp_role", None)

        self.idp_username = self.raw_event.get("idp_username")
        self.raw_event.pop("idp_username", None)

        self.lookup_time_taken = self.raw_event.get("lookup_time_taken")
        self.raw_event.pop("lookup_time_taken", None)

        # Type of 802.1x authentication (eg, PEAP, EAP-TLS, etc)
        self.auth_type = self.raw_event.get("auth_type")
        self.raw_event.pop("auth_type", None)

        # The user or machine name trying to authenticate
        self.username = self.raw_event.get("username")
        self.raw_event.pop("username", None)

        # ID of the NAC rule that was applied
        self.nacrule_id = self.raw_event.get("nacrule_id")
        self.raw_event.pop("nacrule_id", None)

        # RADIUS response attributes
        self.resp_attrs = self.raw_event.get("resp_attrs")
        self.raw_event.pop("resp_attrs", None)

        # NAS IP (switch or AP)
        self.nas_ip = self.raw_event.get("nas_ip")
        self.raw_event.pop("nas_ip", None)

        # NAS vendor (eg, Juniper-Mist)
        self.nas_vendor = self.raw_event.get("nas_vendor")
        self.raw_event.pop("nas_vendor", None)

        # Whether a NAC rule was matched (true or false)
        self.nacrule_matched = self.raw_event.get("nacrule_matched")
        self.raw_event.pop("nacrule_matched", None)

        # The name of the NAC rule that was applied
        self.nacrule_name = self.raw_event.get("nacrule_name")
        self.raw_event.pop("nacrule_name", None)

        # Labels associated with the NAC result
        self.usermac_labels = self.raw_event.get("usermac_labels")
        self.raw_event.pop("usermac_labels", None)

        # The VLAN assigned to the client
        self.vlan = self.raw_event.get("vlan")
        self.raw_event.pop("vlan", None)

        # The VLAN source (eg, 'nactag')
        self.vlan_source = self.raw_event.get("vlan_source")
        self.raw_event.pop("vlan_source", None)

        # A list of VLANs assigned to the client
        self.egress_vlan_names = self.raw_event.get("egress_vlan_names")
        self.raw_event.pop("egress_vlan_names", None)

        # Extra MAC addresses?
        self.device_macs = self.raw_event.get("device_macs")
        self.raw_event.pop("device_macs", None)

        # Client type, eg 'wireless'
        self.client_type = self.raw_event.get("client_type")
        self.raw_event.pop("client_type", None)

        # The SSID of the wireless network
        self.ssid = self.raw_event.get("ssid")
        self.raw_event.pop("ssid", None)

        # Mist ID of the access point
        self.ap = self.raw_event.get("ap")
        self.raw_event.pop("ap", None)

        # BSSID of the access point
        self.bssid = self.raw_event.get("bssid")
        self.raw_event.pop("bssid", None)

        # MAC address of the client
        self.mac = self.raw_event.get("mac")
        self.raw_event.pop("mac", None)

        # Whether MAC is random or not
        self.random_mac = self.raw_event.get("random_mac")
        self.raw_event.pop("random_mac", None)

        # MAC - Wired
        self.device_mac = self.raw_event.get("device_mac")
        self.raw_event.pop("device_mac", None)

        # Port ID - Wired
        self.port_id = self.raw_event.get("port_id")
        self.raw_event.pop("port_id", None)

        # Site ID
        self.site_id = self.raw_event.get("site_id")
        self.raw_event.pop("site_id", None)

        # The event type
        self.type = self.raw_event.get("type")
        self.raw_event.pop("type", None)

        # Friendly event message
        self.text = self.raw_event.get("text")
        self.raw_event.pop("text", None)

        # MDM information
        self.mdm_account_id = self.raw_event.get("mdm_account_id")
        self.raw_event.pop("mdm_account_id", None)

        self.mdm_client_id = self.raw_event.get("mdm_client_id")
        self.raw_event.pop("mdm_client_id", None)

        self.mdm_compliance = self.raw_event.get("mdm_compliance")
        self.raw_event.pop("mdm_compliance", None)

        self.mdm_last_checked = self.raw_event.get("mdm_last_checked")
        self.raw_event.pop("mdm_last_checked", None)

        self.mdm_manufacturer = self.raw_event.get("mdm_manufacturer")
        self.raw_event.pop("mdm_manufacturer", None)

        self.mdm_model = self.raw_event.get("mdm_model")
        self.raw_event.pop("mdm_model", None)

        self.mdm_operating_system = self.raw_event.get("mdm_operating_system")
        self.raw_event.pop("mdm_operating_system", None)

        self.mdm_os_version = self.raw_event.get("mdm_os_version")
        self.raw_event.pop("mdm_os_version", None)

        self.mdm_provider = self.raw_event.get("mdm_provider")
        self.raw_event.pop("mdm_provider", None)

        self.coa_source = self.raw_event.get("coa_source")
        self.raw_event.pop("coa_source", None)

        self.pre_mdm_compliance = self.raw_event.get("pre_mdm_compliance")
        self.raw_event.pop("pre_mdm_compliance", None)

        # AP/BSSID that has seen the client (list)
        self.aps = self.raw_event.get("aps")
        self.raw_event.pop("aps", None)

        self.bssids = self.raw_event.get("bssids")
        self.raw_event.pop("bssids", None)

        # The client IP address
        self.client_ip = self.raw_event.get("client_ip")
        self.raw_event.pop("client_ip", None)

        self.client_ips = self.raw_event.get("client_ips")
        self.raw_event.pop("client_ips", None)

        # Session times
        self.session_duration_in_mins = self.raw_event.get(
            "session_duration_in_mins"
        )
        self.raw_event.pop("session_duration_in_mins", None)

        self.session_ended_at = self.raw_event.get("session_ended_at")
        self.raw_event.pop("session_ended_at", None)

        self.session_last_updated_at = self.raw_event.get(
            "session_last_updated_at"
        )
        self.raw_event.pop("session_last_updated_at", None)

        self.session_started_at = self.raw_event.get("session_started_at")
        self.raw_event.pop("session_started_at", None)

        # Session bytes and packets
        self.total_bytes_received = self.raw_event.get("total_bytes_received")
        self.raw_event.pop("total_bytes_received", None)

        self.total_bytes_sent = self.raw_event.get("total_bytes_sent")
        self.raw_event.pop("total_bytes_sent", None)

        self.total_packets_received = self.raw_event.get(
            "total_packets_received"
        )
        self.raw_event.pop("total_packets_received", None)

        self.total_packets_sent = self.raw_event.get("total_packets_sent")
        self.raw_event.pop("total_packets_sent", None)

        self.rx_bytes = self.raw_event.get("rx_bytes")
        self.raw_event.pop("rx_bytes", None)

        self.rx_pkts = self.raw_event.get("rx_pkts")
        self.raw_event.pop("rx_pkts", None)

        self.tx_bytes = self.raw_event.get("tx_bytes")
        self.raw_event.pop("tx_bytes", None)

        self.tx_pkts = self.raw_event.get("tx_pkts")
        self.raw_event.pop("tx_pkts", None)

    def __parse(
        self
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

        # Get the client type
        if self.client_type and self.client_type == "wireless":
            self.parsed_client_type = "wireless"
        elif self.client_type and self.client_type == "wired":
            self.parsed_client_type = "wired"
        elif self.port_id:
            self.parsed_client_type = "wired"
        else:
            self.parsed_client_type = "unspecified"

        # Get the Event
        if self.type:
            self.parsed_event_type = self.type
        else:
            self.parsed_event_type = "unspecified"

        # Create a custom message where appropriate
        if self.type:
            # NAC Accounting events
            if self.type == "NAC_ACCOUNTING_START":
                self.parsed_message = f"Client session started for {self.username}"
            elif self.type == "NAC_ACCOUNTING_STOP":
                self.parsed_message = f"Client session ended for {self.username}"
            elif self.type == "NAC_ACCOUNTING_UPDATE":
                self.parsed_message = f"Client session updated for {self.username}"
            elif self.type == "NAC_CLIENT_PERMIT":
                self.parsed_message = f"Client permit for {self.username}, VLAN {self.vlan}"
            elif self.type == "NAC_SESSION_STARTED":
                self.parsed_message = f"Client session started for {self.username}"
            elif self.type == "NAC_SESSION_ENDED":
                self.parsed_message = f"Client session ended for {self.username}"

            # Certificate events
            elif self.type == "NAC_CLIENT_CERT_CHECK_SUCCESS":
                self.parsed_message = f"Client certificate check succeeded for {self.cert_cn}"
            elif self.type == "NAC_SERVER_CERT_VALIDATION_SUCCESS":
                self.parsed_message = f"Server certificate validation succeeded for {self.username}"

            # MDM events
            elif self.type == "NAC_MDM_LOOKUP_SUCCESS":
                self.parsed_message = f"MDM lookup succeeded for {self.username}. {self.mdm_manufacturer} {self.mdm_model} is {self.mdm_compliance}"
            elif self.type == "NAC_MDM_DEVICE_NOT_ENROLLED":
                self.parsed_message = f"MDM device not enrolled for {self.username}. {self.text}"

            # IDP events
            elif self.type == "NAC_IDP_GROUPS_LOOKUP_SUCCESS":
                self.parsed_message = f"IDP groups lookup succeeded for {self.username}"
            elif self.type == "NAC_IDP_AUTHC_SUCCESS":
                self.parsed_message = f"IDP authentication succeeded for {self.username}"

            # Other events
            elif self.type == "NAC_CLIENT_IP_ASSIGNED":
                self.parsed_message = f"Client IP assigned for {self.username}. {self.client_ip}"

            # For cases not explicitly handled, use the text field, or a default message
            elif self.text:
                self.parsed_message = self.text
            else:
                self.parsed_message = "No message included"

        # If no custom message, use the text field where available
        elif self.text:
            self.parsed_message = self.text

        else:
            self.parsed_message = "No message included"

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "type": f"{self.parsed_client_type}.{self.parsed_event_type}",
            "timestamp": self.timestamp,
            "message": self.parsed_message,
        }

        # Debug if there's not enough information
        if (
            self.parsed_client_type == "unspecified" or
            self.parsed_event_type == "unspecified" or
            self.parsed_message == "No message included"
        ):
            print(
                Fore.RED,
                "DEBUG: NAC event without enough information:\n",
                f"{self.parsed_client_type}.{self.parsed_event_type}\n",
                f"Message: {self.parsed_message}\n",
                Fore.YELLOW,
                f"Original event: {self.original_event}\n",
                Style.RESET_ALL
            )


class ClientEvent:
    """
    Represents a Client Session object.

    Methods:
        __init__(self, event: dict): Initializes the ClientSessions object.
        __repr__(self): Returns a string representation of the object.
        __collect_fields(self): Collects fields from the raw event.
            This is a helper function to collect fields from the raw event.
        __parse(self): Parses the raw event data.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the ClientSessions object.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.
        """

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event
        self.original_event = copy.deepcopy(event)

        # Remove some fields that are not needed
        self.raw_event.pop("org_id", None)

        # Collect and store fields from the raw event
        self.__collect_fields()

        # Parse the event data
        self.__parse(config)

    def __repr__(self) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        message = f"Client Event:\n \
                {self.parsed_client_type}.{self.parsed_event_type}\n \
                {self.timestamp}\n \
                {self.parsed_message}"

        return message

    def __collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Event Fields
        self.ap = self.raw_event.get("ap")
        self.raw_event.pop("ap", None)

        self.ap_name = self.raw_event.get("ap_name")
        self.raw_event.pop("ap_name", None)

        self.band = self.raw_event.get("band")
        self.raw_event.pop("band", None)

        self.bssid = self.raw_event.get("bssid")
        self.raw_event.pop("bssid", None)

        self.client_family = self.raw_event.get("client_family")
        self.raw_event.pop("client_family", None)

        self.client_manufacture = self.raw_event.get("client_manufacture")
        self.raw_event.pop("client_manufacture", None)

        self.client_model = self.raw_event.get("client_model")
        self.raw_event.pop("client_model", None)

        self.client_os = self.raw_event.get("client_os")
        self.raw_event.pop("client_os", None)

        self.connect = self.raw_event.get("connect")
        self.raw_event.pop("connect", None)

        self.connect_float = self.raw_event.get("connect_float")
        self.raw_event.pop("connect_float", None)

        self.disconnect = self.raw_event.get("disconnect")
        self.raw_event.pop("disconnect", None)

        self.disconnect_float = self.raw_event.get("disconnect_float")
        self.raw_event.pop("disconnect_float", None)

        self.duration = self.raw_event.get("duration")
        self.raw_event.pop("duration", None)

        self.mac = self.raw_event.get("mac")
        self.raw_event.pop("mac", None)

        self.next_ap = self.raw_event.get("next_ap")
        self.raw_event.pop("next_ap", None)

        self.random_mac = self.raw_event.get("random_mac")
        self.raw_event.pop("random_mac", None)

        self.rssi = self.raw_event.get("rssi")
        self.raw_event.pop("rssi", None)

        self.site_id = self.raw_event.get("site_id")
        self.raw_event.pop("site_id", None)

        self.site_name = self.raw_event.get("site_name")
        self.raw_event.pop("site_name", None)

        self.ssid = self.raw_event.get("ssid")
        self.raw_event.pop("ssid", None)

        self.termination_reason = self.raw_event.get("termination_reason")
        self.raw_event.pop("termination_reason", None)

        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)
        if not self.timestamp:
            self.timestame = datetime.now()

        self.version = self.raw_event.get("version")
        self.raw_event.pop("version", None)

        self.wlan_id = self.raw_event.get("wlan_id")
        self.raw_event.pop("wlan_id", None)

        self.client_hostname = self.raw_event.get("client_hostname")
        self.raw_event.pop("client_hostname", None)

        self.client_ip = self.raw_event.get("client_ip")
        self.raw_event.pop("client_ip", None)

        self.client_username = self.raw_event.get("client_username")
        self.raw_event.pop("client_username", None)

        self.ip = self.raw_event.get("ip")
        self.raw_event.pop("ip", None)

    def __parse(
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

        # Get the client type
        if self.ap:
            self.parsed_client_type = "wireless"
        else:
            self.parsed_client_type = "unspecified"

        # Get the Event
        if self.connect and self.disconnect:
            self.parsed_event_type = "disconnect"
        if self.connect:
            self.parsed_event_type = "connect"
        else:
            self.parsed_event_type = "unspecified"

        # Create a custom message
        if self.termination_reason:
            self.parsed_message = f"Client {self.mac} at {self.site_name} has disconnected from {self.ssid}"
        if self.parsed_event_type == "connect":
            self.parsed_message = f"Client {self.mac} at {self.site_name} has connected to {self.ssid}"
        else:
            self.parsed_message = "No message included"

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "type": f"{self.parsed_client_type}.{self.parsed_event_type}",
            "timestamp": self.timestamp,
            "message": self.parsed_message,
        }

        # Debug if there's not enough information
        if (
            self.parsed_client_type == "unspecified" or
            self.parsed_event_type == "unspecified" or
            self.parsed_message == "No message included"
        ):
            print(
                Fore.RED,
                "DEBUG: Client event without enough information:\n",
                f"{self.parsed_client_type}.{self.parsed_event_type}\n",
                f"Message: {self.parsed_message}\n",
                Fore.YELLOW,
                f"Original event: {self.original_event}\n",
                Style.RESET_ALL
            )


class DeviceEvents:
    """
    Represents a Device Event object.

    Methods:
        __init__(self, event: dict): Initializes the DeviceEvents object.
        __repr__(self): Returns a string representation of the object.
        __collect_fields(self): Collects fields from the raw event.
            This is a helper function to collect fields from the raw event.
        __parse(self): Parses the raw event data.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the DeviceEvents object.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.
        """

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event
        self.original_event = copy.deepcopy(event)

        # Collect and store fields from the raw event
        self.__collect_fields()

        # Remove some fields that are not needed
        self.raw_event.pop("org_id", None)

        # Parse the event data
        self.__parse(config)

    def __repr__(self) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        message = f"DeviceEvent:\n \
                {self.parsed_device_type}.{self.parsed_event_type}\n \
                {self.timestamp}\n \
                {self.parsed_message}"

        return message

    def __collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Event Fields
        self.device_name = self.raw_event.get("device_name")
        self.raw_event.pop("device_name", None)

        self.device_type = self.raw_event.get("device_type")
        self.raw_event.pop("device_type", None)

        self.mac = self.raw_event.get("mac")
        self.raw_event.pop("mac", None)

        self.model = self.raw_event.get("model")
        self.raw_event.pop("model", None)

        self.port_id = self.raw_event.get("port_id")
        self.raw_event.pop("port_id", None)

        self.site_id = self.raw_event.get("site_id")
        self.raw_event.pop("site_id", None)

        self.site_name = self.raw_event.get("site_name")
        self.raw_event.pop("site_name", None)

        self.text = self.raw_event.get("text")
        self.raw_event.pop("text", None)

        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)

        self.type = self.raw_event.get("type")
        self.raw_event.pop("type", None)

        self.ap = self.raw_event.get("ap")
        self.raw_event.pop("ap", None)

        self.ap_name = self.raw_event.get("ap_name")
        self.raw_event.pop("ap_name", None)

    def __parse(
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

        # Get the device type
        if self.device_type:
            self.parsed_device_type = self.device_type
        else:
            self.parsed_device_type = "unspecified"

        # Get the event type
        if self.type:
            self.parsed_event_type = self.type
        else:
            self.parsed_event_type = "unspecified"

        # Need to set a nice message
        if self.text:
            self.parsed_message = self.text
        else:
            self.parsed_message = "No message included"

        # Create webhook body
        self.parsed_body = {
            "source": "mist",
            "type": f"{self.parsed_device_type}.{self.parsed_event_type}",
            "timestamp": self.timestamp,
            "message": self.parsed_message,
        }

        # Display alert if the event type is not in the config
        if self.parsed_event_type not in config:
            print(
                Fore.RED,
                "DEBUG: New type of Device Event alert:",
                self.original_event,
                Style.RESET_ALL
            )


class Alarms:
    """
    Represents an Alarm object.

    Methods:
        __init__(self, event: dict): Initializes the Alarms object.
        __repr__(self): Returns a string representation of the Alarms object.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the Alarms object.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.
        """

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event
        self.original_event = copy.deepcopy(event)

        # Remove some fields that are not needed
        self.raw_event.pop("org_id", None)

        # Collect and store fields from the raw event
        self.__collect_fields()

    def __repr__(self) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        return f"AlarmEvent: {self.raw_event}"

    def __collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Event Fields
        self.count = self.raw_event.get("count")
        self.raw_event.pop("count", None)

        self.group = self.raw_event.get("group")
        self.raw_event.pop("group", None)

        self.fw_version = self.raw_event.get("fw_version")
        self.raw_event.pop("fw_version", None)

        self.hostnames = self.raw_event.get("hostnames")
        self.raw_event.pop("hostnames", None)

        self.id = self.raw_event.get("id")
        self.raw_event.pop("id", None)

        self.last_seen = self.raw_event.get("last_seen")
        self.raw_event.pop("last_seen", None)

        self.model = self.raw_event.get("model")
        self.raw_event.pop("model", None)

        self.peer = self.raw_event.get("peer")
        self.raw_event.pop("peer", None)

        self.port_ids = self.raw_event.get("port_ids")
        self.raw_event.pop("port_ids", None)

        self.reasons = self.raw_event.get("reasons")
        self.raw_event.pop("reasons", None)

        self.severity = self.raw_event.get("severity")
        self.raw_event.pop("severity", None)

        self.site_id = self.raw_event.get("site_id")
        self.raw_event.pop("site_id", None)

        self.site_name = self.raw_event.get("site_name")
        self.raw_event.pop("site_name", None)

        self.switches = self.raw_event.get("switches")
        self.raw_event.pop("switches", None)

        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)

        self.type = self.raw_event.get("type")
        self.raw_event.pop("type", None)


class Audits:
    """
    Represents an Audit object.

    Methods:
        __init__(self, event: dict): Initializes the Audits object.
        __repr__(self): Returns a string representation of the Audits object.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the Audits object.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.
        """

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event
        self.original_event = copy.deepcopy(event)

        # Remove some fields that are not needed
        self.raw_event.pop("org_id", None)

        # Collect and store fields from the raw event
        self.__collect_fields()

    def __repr__(self) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        return f"AuditEvent: {self.raw_event}"

    def __collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Event Fields
        self.admin_name = self.raw_event.get("admin_name")
        self.raw_event.pop("admin_name", None)

        self.after = self.raw_event.get("after")
        self.raw_event.pop("after", None)

        self.before = self.raw_event.get("before")
        self.raw_event.pop("before", None)

        self.id = self.raw_event.get("id")
        self.raw_event.pop("id", None)

        self.message = self.raw_event.get("message")
        self.raw_event.pop("message", None)

        self.src_ip = self.raw_event.get("src_ip")
        self.raw_event.pop("src_ip", None)

        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)

        self.user_agent = self.raw_event.get("user_agent")
        self.raw_event.pop("user_agent", None)

        self.webhook_id = self.raw_event.get("webhook_id")
        self.raw_event.pop("webhook_id", None)


class DeviceUpdowns:
    """
    Represents a Device Up or Down object.

    Methods:
        __init__(self, event: dict): Initializes the DeviceUpdowns object.
        __repr__(self): Returns a string representation of the object.
    """
    def __init__(
        self,
        event: dict,
        config: dict,
    ) -> None:
        """
        Initialize the DeviceUpdowns object.

        Args:
            event (dict): The event data from the webhook.
            config (dict): Event handling configuration.
        """

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event
        self.original_event = copy.deepcopy(event)

        # Remove some fields that are not needed
        self.raw_event.pop("org_id", None)

        # Collect and store fields from the raw event
        self.__collect_fields()

    def __repr__(self) -> str:
        """
        Return a string representation of this object.
        This will be the parsed message body.
        """

        return f"UpDownEvent: {self.raw_event}"

    def __collect_fields(
        self
    ) -> None:
        """
        Collect fields from the raw event.
        This is a helper function to collect fields from the raw event.
        """

        # Event Fields
        self.ap = self.raw_event.get("ap")
        self.raw_event.pop("ap", None)

        self.ap_name = self.raw_event.get("ap_name")
        self.raw_event.pop("ap_name", None)

        self.audit_id = self.raw_event.get("audit_id")
        self.raw_event.pop("audit_id", None)

        self.device_name = self.raw_event.get("device_name")
        self.raw_event.pop("device_name", None)

        self.device_type = self.raw_event.get("device_type")
        self.raw_event.pop("device_type", None)

        self.ev_type = self.raw_event.get("ev_type")
        self.raw_event.pop("ev_type", None)

        self.mac = self.raw_event.get("mac")
        self.raw_event.pop("mac", None)

        self.reason = self.raw_event.get("reason")
        self.raw_event.pop("reason", None)

        self.site_id = self.raw_event.get("site_id")
        self.raw_event.pop("site_id", None)

        self.site_name = self.raw_event.get("site_name")
        self.raw_event.pop("site_name", None)

        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)

        self.type = self.raw_event.get("type")
        self.raw_event.pop("type", None)


if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    exit(1)
