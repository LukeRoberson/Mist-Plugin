"""
Module: main.py

The Mist plugin
    Receives and processes webhooks from the Mist platform.
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
    - logging_setup:
        Sets up the root logger for the web service.
    - create_app:
        Creates the Flask application instance and sets up the configuration.
    - get_event_manager:
        Returns the event manager class based on the topic of the event.

Routes:
    - /api/health:
        Health check endpoint to ensure the service is running.
    - webhook:
        Handles webhook requests, validates them, and processes events.

Dependencies:
    - Flask: For creating the web application.
    - Flask-Session: For session management.
    - yaml: For loading configuration files.
    - logging: For logging messages to the terminal.
    - os: For environment variable access.

Custom Dependencies:
    - parser: Contains event manager classes for processing different topics.
    - sdk: Contains the PluginManager and Config classes for managing plugins.
"""

# Standard library imports
from flask import (
    Flask,
    request,
    jsonify,
    make_response
)
from flask_session import Session
import yaml
import logging
import requests
from typing import Optional
import os
from colorama import Fore, Style

# Custom imports
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
from sdk import PluginManager, Config, SystemLog

CONFIG_URL = "http://core:5100/api/config"
LOG_URL = "http://logging:5100/api/log"
PLUGINS_URL = "http://core:5100/api/plugins"
HASH_URL = "http://security:5100/api/hash"
MIST_SIGNATURE_HEADER = 'X-Mist-Signature-v2'


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
    system_log: SystemLog,
    plugin_config: dict,
) -> Flask:
    """
    Create the Flask application instance and set up the configuration.
    Registers the necessary blueprints for the web service.

    Args:
        config (dict): The global configuration dictionary
        system_log (SystemLog): An instance of SystemLog for logging.
        plugin_config (dict): The plugin configuration loaded from config.yaml.

    Returns:
        Flask: The Flask application instance.
    """

    # Create the Flask application
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('api_master_pw')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = '/app/flask_session'
    app.config['SYSTEM_LOG'] = system_log
    app.config['PLUGIN_CONFIG'] = plugin_config
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
global_config = {}
with Config(CONFIG_URL) as config_reader:
    global_config = config_reader.read()

# Load the plugin configuration file
with open('config.yaml', 'r') as f:
    config_data = yaml.safe_load(f)

# Set up logging
logging_setup(global_config)

# Initialize the SystemLog with default values
#   Values can be overridden when sending a log
system_log = SystemLog(
    logging_url=LOG_URL,
    source="mist-plugin",
    destination=["web"],
    group="plugin",
    category="mist",
    alert="system",
    severity="info",
    teams_chat_id=config_data.get('chats', None).get('default', None)
)

# Initialize the Flask application
app = create_app(
    system_log=system_log,
    plugin_config=config_data,
)


@app.route(
    '/api/health',
    methods=['GET']
)
def health():
    """
    Health check endpoint.
    Returns a JSON response indicating the service is running.
    """

    return jsonify({'status': 'ok'})


@app.route('/webhook', methods=['POST'])
def webhook():
    '''
    Handle incoming webhook requests from the Mist platform.
    Validates the request signature
    Creates an event manager based on the topic of the event
    Processes the event using the event manager.

    Returns:
        str: A response indicating the result of the processing.
    '''

    # Parse the incoming webhook request
    result_json = {}
    data = request.get_json()
    if not data:
        logging.error("No JSON body received.")
        return make_response(
            jsonify(
                {
                    'result': 'error',
                    'message': 'No JSON body received.'
                }
            ),
            400
        )

    # TROUBLESHOOTING A SPECIFIC EVENT
    if 'dhcp_failure' in data:
        print(
            Fore.YELLOW + Style.BRIGHT,
            f"Received webhook with dhcp_failure event:\n {data}",
            Style.RESET_ALL
        )
        system_log.log(
            "Received webhook with dhcp_failure event: %s" % data
        )

    signature = request.headers.get(MIST_SIGNATURE_HEADER, None)
    if not signature:
        logging.error(
            "No signature found in the message. Message will not be validated."
        )
        system_log.log(
            "Received webhook without signature."
        )

    # If the signature is present, validate it
    else:
        # Get the secret from the plugin config
        plugin = {}
        secret = ""
        with PluginManager(PLUGINS_URL) as pm:
            plugin = pm.read(
                name=config_data['name']
            )
        if isinstance(plugin, dict) and 'plugin' in plugin:
            secret = plugin['plugin']['webhook']['secret']

        # Send to security service for validation
        try:
            sec_resp = requests.post(
                HASH_URL,
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
            return make_response(
                jsonify(
                    {
                        'result': 'error',
                        'message': 'Security validation failed.'
                    }
                ),
                502
            )

    # Check the result from the security service
    if result_json.get('result') != 'success':
        logging.error(
            "Security validation failed: %s",
            result_json.get('result')
        )
        system_log.log(
            "Received webhook with invalid signature."
        )
        return make_response(
            jsonify(
                {
                    'result': 'error',
                    'message': 'Invalid signature',
                },
                403
            )
        )

    # Create an object to represent the alert
    topic = data.get("topic")
    event_list = data.get("events")

    if not topic or not event_list:
        logging.error("Missing topic or events in webhook data.")
        return make_response(
            jsonify(
                {
                    'result': 'error',
                    'message': 'Missing topic or events.'
                }
            ),
            400
        )

    for event in event_list:
        event_manager = get_event_manager(topic, event, config_data)
        if event_manager is None:
            logging.error("Received webhook with unknown topic: %s", topic)
            continue
        logging.debug(event_manager)

    return "Received", 200
