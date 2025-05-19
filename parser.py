"""
Webhook Parser

Classes to represent and parse webhooks from the Mist plugin.
"""


class NacEvent:
    """
    Represents a NacEvent object.
        One single NAC event is logged here.
        One web hook from Mist may contain multiple NAC events.

    As fields are processed, they are removed from the raw_event dictionary.
        This is so we can see if there are any fields left over
            that we weren't expecting.

    Methods:
        __init__(self, event: dict): Initializes the NacEvent object.
        security(self): Parses certificate and TLS information from the event.
        idp(self): Parses IDP information from the event.
        nac(self): Parses NAC/RADIUS information from the event.
        connection(self): Parses connection information from the event.
        event(self): Parses event information from the event.
        mdm(self): Parses MDM information from the event.
        session(self): Parses session information from the event.
    """

    def __init__(
        self,
        event: dict,
    ) -> None:
        """
        Initialize the NacEvent object.

        Args:
            event (dict): The event data from the webhook.
        """

        # The event data from the webhook; Remove entries as they are processed
        self.raw_event = event

        # Remove some fields that are not needed
        self.raw_event.pop("crc", None)
        self.raw_event.pop("org_id", None)
        self.raw_event.pop("tls_states", None)
        self.raw_event.pop("cert_template", None)

        # Collect certificate information
        self.security()

        # Collect IDP information
        self.idp()

        # Collect NAC/RADIUS information
        self.nac()

        # Collect connection information
        self.connection()

        # Collect event information
        self.event()

        # Collect MDM information
        self.mdm()

        # Collect session information
        self.session()

    def security(
        self
    ) -> None:
        """
        Parse certificate and TLS information from the event.
        """

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

    def idp(
        self,
    ) -> None:
        """
        Parse IDP information from the event.
        """

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

    def nac(
        self,
    ) -> None:
        """
        Parse NAC/RADIUS information from the event.
        """

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

    def connection(
        self,
    ) -> None:
        """
        Information about the client connection.
        Wireless or wired, and connection about either.
        """

        # Client type, eg 'wireless'
        self.client_type = self.raw_event.get("client_type")
        self.raw_event.pop("client_type", None)

        # The SSID of the wireless network
        self.ssid = self.raw_event.get("ssid")
        self.raw_event.pop("ssid", None)

        # Mist ID of the access point
        self.ap_id = self.raw_event.get("ap")
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

    def event(
        self,
    ) -> None:
        """
        Collect event data.
        """

        # Epoch the event occurred in Mist
        self.timestamp = self.raw_event.get("timestamp")
        self.raw_event.pop("timestamp", None)

        # The event type
        self.type = self.raw_event.get("type")
        self.raw_event.pop("type", None)

        # Friendly event message
        self.text = self.raw_event.get("text")
        self.raw_event.pop("text", None)

    def mdm(
        self,
    ) -> None:
        """
        Collect MDM information.
        """

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

    def session(
        self,
    ) -> None:
        """
        Collect session information.
        This seems to happen when wifi clients roam
        """

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


if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    exit(1)
