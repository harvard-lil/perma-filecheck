FROM python:3.13-bookworm

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies and ClamAV
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clamav \
        clamdscan \
        clamav-daemon \
        clamav-freshclam \
        curl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create necessary directories and set permissions
RUN mkdir -p /var/run/clamav /var/log/clamav \
    && chown -R clamav:clamav /var/run/clamav /var/log/clamav \
    && chmod 750 /var/run/clamav

# Configure ClamAV - disable some features that might cause issues
RUN sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf \
    && sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamav/clamd.conf \
    && sed -i 's/^#TCPSocket/TCPSocket/' /etc/clamav/clamd.conf \
    && sed -i 's/^#TCPAddr/TCPAddr/' /etc/clamav/clamd.conf

# Update ClamAV virus definitions
RUN freshclam

# Set up application directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip==25.2 \
    && pip install --no-cache-dir -r requirements.txt --src /usr/local/src \
    && rm requirements.txt

# Copy application files
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY main.py .

# Make entrypoint executable
RUN chmod +x /docker-entrypoint.sh

# Expose port
EXPOSE 8000

# Entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Start application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--log-level", "info"]