"""
Module: main.py

The Mist plugin
    Receives and processes webhooks from the Mist plugin.
    Events are grouped by topic and processed by the appropriate event manager.
    Event manager classes are imported from the parser module.

Module Tasks:
    1. Fetch global configuration from the web interface.
    2. Set up logging based on the global configuration.
    3. Create a Flask application instance and register API endpoints.

Usage:
    This is a Flask application that should run behind a WSGI server inside
        a Docker container.
    Build the Docker image and run it with the provided Dockerfile.

Functions:
    - fetch_global_config:
        Fetches the global configuration from the core service.
    - logging_setup:
        Sets up the root logger for the web service.
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
import os
from flask_session import Session

from parser import (
    NacEvent,
    ClientEvent,
    DeviceEvents,
    Alarms,
    Audits,
    DeviceUpdowns,
    Location,
    Occupancy,
    RssiZone,
    SdkClient,
    VirtualBeacon,
    Zone,
)
from systemlog import SystemLog

CONFIG_URL = "http://core:5100/api/config"


def fetch_global_config(
    url: str = CONFIG_URL,
) -> dict:
    """
    Fetch the global configuration from the core service.

    Args:
        None

    Returns:
        dict: The global configuration loaded from the core service.

    Raises:
        RuntimeError: If the global configuration cannot be loaded.
    """

    global_config = None
    try:
        response = requests.get(url, timeout=3)
        response.raise_for_status()
        global_config = response.json()

    except Exception as e:
        logging.critical(
            "Failed to fetch global config from core service."
            f" Error: {e}"
        )

    if global_config is None:
        raise RuntimeError("Could not load global config from core service")

    return global_config['config']


def logging_setup(
    config: dict,
) -> None:
    """
    Set up the root logger for the web service.

    Args:
        config (dict): The global configuration dictionary

    Returns:
        None
    """

    # Get the logging level from the configuration (eg, "INFO")
    log_level_str = config['web']['logging-level'].upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Set up the logging configuration
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logging.info("Logging setup complete with level: %s", log_level)


def create_app(
    config: dict,
    system_log: SystemLog,
) -> Flask:
    """
    Create the Flask application instance and set up the configuration.
    Registers the necessary blueprints for the web service.

    Args:
        config (dict): The global configuration dictionary

    Returns:
        Flask: The Flask application instance.
    """

    # Create the Flask application
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('api_master_pw')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = '/app/flask_session'
    app.config['GLOBAL_CONFIG'] = config
    app.config['SYSTEM_LOG'] = system_log
    Session(app)

    return app


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

    elif topic in ("location", "location-client", "location-unclient"):
        return Location(event, config_data['location'])

    elif topic == "occupancy-alerts":
        logging.info(
            "Received webhook for occupancy alert."
        )
        return Occupancy(event, config_data['occupancy-alerts'])

    elif topic == "rssizone":
        logging.info(
            "Received webhook for RSSI zone event."
        )
        return RssiZone(event, config_data['rssizone'])

    elif topic == "sdkclient-scan-data":
        logging.info(
            "Received webhook for SDK client scan data."
        )
        return SdkClient(event, config_data['sdkclient-scan-data'])

    elif topic == "vbeacon":
        logging.info(
            "Received webhook for Virtual Beacon event."
        )
        return VirtualBeacon(event, config_data['vbeacon'])

    elif topic == "zone":
        return Zone(event, config_data['zone'])

    else:
        logging.error("Unknown topic: %s", topic)
        logging.error("Event data: %s", event)
        return None


# Load the global configuration from the core service
global_config = fetch_global_config()

# Load the plugin configuration file
with open('config.yaml', 'r') as f:
    config_data = yaml.safe_load(f)

# Set up logging
logging_setup(global_config)

# Initialize the SystemLog with default values
#   Values can be overridden when sending a log
system_log = SystemLog(
    logging_url="http://logging:5100/api/log",
    source="mist-plugin",
    destination=["web"],
    group="plugin",
    category="mist",
    alert="system",
    severity="info",
    teams_chat_id=config_data.get('chat-id', None)
)

# Initialize the Flask application
app = create_app(
    config=global_config,
    system_log=system_log
)


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
        system_log.log(
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
            system_log.log(
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
        system_log.log(
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
