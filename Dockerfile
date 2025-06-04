# Use the custom base image
FROM lukerobertson19/base-os:latest
LABEL description="A Mist plugin for the AI assistant. Receives webhooks from Mist, then filters, parses, and logs them."
LABEL version="1.0.0"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . .

# Start the application using uWSGI
CMD ["uwsgi", "--ini", "uwsgi.ini"]
