"""
The Mist plugin

Receives and processes webhooks from the Mist plugin.
"""

from flask import Flask, request
from colorama import Fore, Style
import yaml

from parser import NacEvent


app = Flask(__name__)


# Load the configuration file
with open('config.yaml', 'r') as f:
    config_data = yaml.safe_load(f)


@app.route('/webhook', methods=['POST'])
def webhook():
    # Parse the incoming webhook request
    data = request.get_json()

    # Debug - print the alert
    print(
        Fore.YELLOW,
        "DEBUG: Parsed alert:",
        data,
        Style.RESET_ALL
    )

    # Create an object
    if data.get("topic") == "nac-events":
        for event in data.get("events"):
            # Create a NacEvent object
            nac_event = NacEvent(event)

            # Print unmanaged fields, if any
            if nac_event.raw_event:
                print(
                    Fore.RED,
                    "Unmanaged fields:",
                    nac_event.raw_event,
                    Style.RESET_ALL
                )

    # Send the alert to the logging service
    # response = requests.post(
    #     "http://web-interface:5100/api/webhook",
    #     json=alert
    # )

    return "Received", 200


'''
NOTE: When running in a container, the host and port are set in the
    uWSGI config. uWSGI starts the process, which means the
    Flask app is not run directly.
    This can be uncommented for local testing.
'''
webhook()

# if __name__ == "__main__":
#     app.run(
#         debug=True,
#         port=5000
#     )
