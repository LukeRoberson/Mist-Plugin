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

        # TLS information
        self.tls_cipher_suite = self.raw_event.get("tls_cipher_suite")
        self.raw_event.pop("tls_cipher_suite", None)

        self.tls_client_preferred_version = self.raw_event.get(
            "tls_client_preferred_version"
        )
        self.raw_event.pop("tls_client_preferred_version", None)

        self.tls_states = self.raw_event.get("tls_states")
        self.raw_event.pop("tls_states", None)

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


if __name__ == "__main__":
    print("This module is not meant to be run directly.")
    exit(1)
