# Eoolii Camera Local Relay - Docker Image
FROM python:3.11-slim

WORKDIR /app

# No external dependencies needed - all stdlib!
# If you add dependencies later, uncomment:
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY local_relay_server.py .
COPY mock_api_server.py .
COPY stream_server.py .
COPY relay_cli.py .

# Copy certificates (will be mounted as volume in production)
# These are placeholders - mount your real certs at runtime
COPY server.crt .
COPY server.key .

# Default environment variables (override in docker-compose or .env)
ENV RELAY_HOST=0.0.0.0
ENV LOCAL_IP=192.168.1.100
ENV RELAY_PORT=50721
ENV MGMT_PORT=50722
ENV HTTP_PORT=8080
ENV API_PORT=443
ENV DEBUG_MODE=false

# Expose ports
# 443 - Mock API Server (HTTPS)
# 50721 - Relay Server (TLS)
# 50722 - Management Interface
# 8080+ - Stream Server(s)
EXPOSE 443 50721 50722 8080

# Default command (override in docker-compose for each service)
CMD ["python3", "local_relay_server.py"]
