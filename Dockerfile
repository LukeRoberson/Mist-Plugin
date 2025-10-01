# Use the custom base image
FROM lukerobertson19/base-os:latest

# OCI labels for the image
LABEL description="A Mist plugin for the AI assistant. Receives webhooks from Mist, then filters, parses, and logs them."
LABEL org.opencontainers.image.title="AI Assistant plugin: Mist"
LABEL org.opencontainers.image.description="A plugin to receive alerts from Juniper Mist, filter and parse them, and log them to the AI assistant logging service for handling."
LABEL org.opencontainers.image.base.name="lukerobertson19/base-os:latest"
LABEL org.opencontainers.image.source="https://github.com/LukeRoberson/Mist-Plugin"

# Custom Labels for the image
LABEL net.networkdirection.healthz="http://localhost:5100/api/health"
LABEL net.networkdirection.plugin.name="mist"

# Copy the requirements file and install dependencies
COPY pyproject.toml ./

# Install dependencies
RUN pip install --upgrade pip && \
    pip install "python-sdk @ git+https://github.com/LukeRoberson/python-sdk.git@89397b4a0004f613510a55a4117a67838f6511f7" && \
    pip install .

# Copy the rest of the application code
COPY . .

# Start the application using uWSGI
CMD ["uwsgi", "--ini", "uwsgi.ini"]

# Set the version of the image in metadata
ARG VERSION
LABEL org.opencontainers.image.version="${VERSION}"
