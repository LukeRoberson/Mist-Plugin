# Overview

The Mist plugin

Receives webhooks from Mist, filters, parses, and logs them accordingly.

Uses Flask as the web server to receive the webhooks.

Everything runs from main.py.


## Modules

| Module   | Usage                                 |
| -------- | ------------------------------------- |
| Flask    | Web framework                         |
| Requests | Send API calls to the logging service |



</br></br>
---

# Logging Service
The plugin will send information to the logging service. This is an REST API call:

POST /api/webhook

The body of the POST contains relevant information in a standard format. The logging service receives this, and decides what to do from there.

This is connectionless. The plugin is not concerned if the logging service receives or acknowledges this.
