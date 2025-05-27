"""
The Mist plugin

Receives and processes webhooks from the Mist plugin.
"""

from flask import Flask, request
from colorama import Fore, Style
import yaml
import logging

from parser import (
    NacEvent,
    ClientEvent,
    DeviceEvents,
    Alarms,
    Audits,
    DeviceUpdowns
)


# Set up logging
logging.basicConfig(level=logging.INFO)

# Initialize the Flask application
app = Flask(__name__)

# Load the configuration file
with open('config.yaml', 'r') as f:
    config_data = yaml.safe_load(f)


@app.route('/webhook', methods=['POST'])
def webhook():
    # Parse the incoming webhook request
    data = request.get_json()

    # Create an object to represent the alert
    topic = data.get("topic")
    event_list = data.get("events")
    if len(event_list) > 1:
        print(
            Fore.GREEN,
            f"DEBUG: More than one event for {topic}",
            Style.RESET_ALL
        )

    for event in event_list:
        # NAC events
        if (
            topic == "nac-events" or
            topic == "nac-accounting"
        ):
            # Create a NacEvent object
            event_manager = NacEvent(event, config_data['nac-events'])

            # Print unmanaged fields, if any
            if event_manager.raw_event:
                logging.debug("New type of NAC event alert:", data)
                logging.debug("Unmanaged fields:", event_manager.raw_event)

        # Client events (wireless, wired)
        elif (
            topic == "client-sessions" or
            topic == "client-join" or
            topic == "client-info"
        ):
            # Create a ClientSessions object
            event_manager = ClientEvent(event, config_data['client-events'])

            # Print unmanaged fields, if any
            if event_manager.raw_event:
                logging.debug("New type of Client Session alert:", data)
                logging.debug("Unmanaged fields:", event_manager.raw_event)

        # Device events (switches, APs, etc.)
        elif (
            topic == "device-events"
        ):
            # Create a DeviceEvents object
            event_manager = DeviceEvents(event, config_data['device-events'])

            # Print unmanaged fields, if any
            if event_manager.raw_event:
                logging.debug("New type of Device alert:", data)
                logging.debug("Unmanaged fields:", event_manager.raw_event)

        # Alarms (alerts)
        elif (
            topic == "alarms"
        ):
            # Create an Alarms object
            event_manager = Alarms(event, config_data['alarms'])

            # Print unmanaged fields, if any
            if event_manager.raw_event:
                logging.debug("New type of Alarm alert:", data)
                logging.debug("Unmanaged fields:", event_manager.raw_event)

        # Audits (audit logs)
        elif (
            topic == "audits"
        ):
            # Create an Audits object
            event_manager = Audits(event, config_data['audits'])

            # Print unmanaged fields, if any
            if event_manager.raw_event:
                logging.debug("New type of Audit alert:", data)
                logging.debug("Unmanaged fields:", event_manager.raw_event)

        # Device updowns (device status changes)
        elif (
            topic == "device-updowns"
        ):
            # Create a DeviceUpdowns object
            event_manager = DeviceUpdowns(event, config_data['device-updowns'])

            # Print unmanaged fields, if any
            if event_manager.raw_event:
                logging.debug("New type of Device Up/Down alert:", data)
                logging.debug("Unmanaged fields:", event_manager.raw_event)

        # Unknown topic
        else:
            print(
                Fore.RED,
                f"ERROR: Unknown topic: {topic}",
                Style.RESET_ALL
            )
            continue

    return "Received", 200


'''
NOTE: When running in a container, the host and port are set in the
    uWSGI config. uWSGI starts the process, which means the
    Flask app is not run directly.
    This can be uncommented for local testing.
'''
# if __name__ == "__main__":
#     app.run(
#         debug=True,
#         port=5000
#     )
