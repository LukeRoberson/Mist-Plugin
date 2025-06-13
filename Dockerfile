# Use the custom base image
FROM lukerobertson19/base-os:latest

# OCI labels for the image
LABEL description="A Mist plugin for the AI assistant. Receives webhooks from Mist, then filters, parses, and logs them."
LABEL org.opencontainers.image.title="AI Assistant plugin: Mist"
LABEL org.opencontainers.image.description="A plugin to receive alerts from Juniper Mist, filter and parse them, and log them to the AI assistant logging service for handling."
LABEL org.opencontainers.image.base.name="lukerobertson19/base-os:latest"
LABEL org.opencontainers.image.source="https://github.com/LukeRoberson/Mist-Plugin"
LABEL org.opencontainers.image.version="1.0.0"

# Custom Labels for the image
LABEL net.networkdirection.healthz="http://localhost:5100/api/health"
LABEL net.networkdirection.plugin.name="Mist"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . .

# Start the application using uWSGI
CMD ["uwsgi", "--ini", "uwsgi.ini"]
