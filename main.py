"""
The Mist plugin
    Receives and processes webhooks from the Mist plugin.
    Events are grouped by topic and processed by the appropriate event manager.
    Event manager classes are imported from the parser module.

Functions:
    - send_log:
        Sends a log message to the logging service.
    - get_event_manager:
        Returns the event manager class based on the topic of the event.

Routes:
    - webhook:
        Handles webhook requests, validates them, and processes events.
"""

from flask import Flask, request, jsonify
import yaml
import logging
import requests
from typing import Optional
from datetime import datetime

from parser import (
    NacEvent,
    ClientEvent,
    DeviceEvents,
    Alarms,
    Audits,
    DeviceUpdowns
)


# Get global config
global_config = None
try:
    response = requests.get("http://web-interface:5100/api/config", timeout=3)
    response.raise_for_status()  # Raise an error for bad responses
    global_config = response.json()

except Exception as e:
    logging.critical(
        "Failed to fetch global config from web interface."
        f" Error: {e}"
    )

if global_config is None:
    raise RuntimeError("Could not load global config from web interface")

# Set up logging
log_level_str = global_config['config']['web']['logging-level'].upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
logging.info("Logging level set to: %s", log_level_str)

# Initialize the Flask application
app = Flask(__name__)


def send_log(
    message: str,
    url: str = "http://logging:5100/api/log",
    source: str = "mist",
    destination: list = ["web"],
    group: str = "plugin",
    category: str = "mist",
    alert: str = "event",
    severity: str = "info",
) -> None:
    """
    Send a message to the logging service.

    Args:
        message (str): The message to send.
        url (str): The URL of the logging service API.
        source (str): The source of the log message.
        destination (list): The destinations for the log message.
        group (str): The group to which the log message belongs.
        category (str): The category of the log message.
        alert (str): The alert type for the log message.
        severity (str): The severity level of the log message.
    """

    # Send a log as a webhook to the logging service
    try:
        requests.post(
            url,
            json={
                "source": source,
                "destination": destination,
                "log": {
                    "group": group,
                    "category": category,
                    "alert": alert,
                    "severity": severity,
                    "timestamp": str(datetime.now()),
                    "message": message
                }
            },
            timeout=3
        )
    except Exception as e:
        logging.warning(
            "Failed to send log to logging service. %s",
            e
        )


# Load the configuration file
with open('config.yaml', 'r') as f:
    config_data = yaml.safe_load(f)


def get_event_manager(
    topic: str,
    event: dict,
    config_data: dict,
) -> Optional[object]:
    """
    Return the appropriate event manager class based on topic.

    Args:
        topic (str): The topic of the event.
        event (dict): The event data.
        config_data (dict): The configuration data loaded from config.yaml.

    Returns:
        Optional[object]: An instance of the appropriate event manager class,
                          or None if the topic is unknown.
    """

    if topic in ("nac-events", "nac-accounting"):
        return NacEvent(event, config_data['nac-events'])
    elif topic in ("client-sessions", "client-join", "client-info"):
        return ClientEvent(event, config_data['client-events'])
    elif topic == "device-events":
        return DeviceEvents(event, config_data['device-events'])
    elif topic == "alarms":
        return Alarms(event, config_data['alarms'])
    elif topic == "audits":
        return Audits(event, config_data['audits'])
    elif topic == "device-updowns":
        return DeviceUpdowns(event, config_data['device-updowns'])
    else:
        return None


@app.route('/webhook', methods=['POST'])
def webhook():
    '''
    Handle incoming webhook requests from the Mist plugin.
    Validates the request signature
    Creates an event manager based on the topic of the event
    Processes the event using the event manager.

    Returns:
        str: A response indicating the result of the processing.
    '''

    # Parse the incoming webhook request
    data = request.get_json()
    if not data:
        logging.error("No JSON body received.")
        return jsonify({
            'result': 'error',
            'message': 'No JSON body received.'
        }), 400

    signature = request.headers.get('X-Mist-Signature-v2', None)
    if not signature:
        logging.error(
            "No signature found in the message. Message will not be validated."
        )
        send_log(
            "Received webhook without signature."
        )

    # If the signature is present, validate it
    else:
        # Get the secret from the web-interface
        try:
            secret_resp = requests.get(
                "http://web-interface:5100/api/plugins",
                headers={'X-Plugin-Name': config_data['name']}
            )
            secret_resp.raise_for_status()
            secret = secret_resp.json()['plugin']['webhook']['secret']

        except requests.RequestException as e:
            logging.error(
                "Failed to request plugin secret from web interface:",
                e
            )
            send_log(
                "Failed to retrieve plugin secret from web interface."
            )
            return jsonify({
                'result': 'error',
                'message': 'Could not retrieve plugin secret.'
            }), 502

        # Send to security service for validation
        try:
            sec_resp = requests.post(
                "http://security:5100/api/hash",
                json={
                    "signature": signature,
                    "message": request.get_data().decode('utf-8'),
                    "secret": secret
                }
            )
            sec_resp.raise_for_status()
            result_json = sec_resp.json()

        except requests.RequestException as e:
            logging.error(
                "Failed to send message to security for validation:",
                e
            )
            return jsonify({
                'result': 'error',
                'message': 'Security validation failed.'
            }), 502

    # Check the result from the security service
    if result_json.get('result') != 'success':
        logging.error(
            "Security validation failed: %s",
            result_json.get('result')
        )
        send_log(
            "Received webhook with invalid signature."
        )
        return jsonify(
            {
                'result': 'error',
                'message': 'Invalid signature',
            }, 403
        )

    # Create an object to represent the alert
    topic = data.get("topic")
    event_list = data.get("events")

    if not topic or not event_list:
        logging.error("Missing topic or events in webhook data.")
        return jsonify({
            'result': 'error',
            'message': 'Missing topic or events.'
        }), 400

    if len(event_list) > 1:
        logging.warning(
            "Received webhook with multiple events for topic: %s",
            topic
        )

    for event in event_list:
        event_manager = get_event_manager(topic, event, config_data)
        if event_manager is None:
            logging.error("Received webhook with unknown topic: %s", topic)
            continue
        logging.debug(event_manager)

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
