# RotaryShield Test Environment
# Ubuntu 22.04 with Python 3.10 and all dependencies

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

# Install system packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    sudo \
    vim \
    less \
    curl \
    iputils-ping \
    net-tools \
    iptables \
    ufw \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create rotaryshield user
RUN useradd -m -s /bin/bash rotaryshield && \
    echo "rotaryshield ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create necessary directories
RUN mkdir -p /etc/rotaryshield \
    /var/lib/rotaryshield \
    /var/log/rotaryshield \
    /run/rotaryshield && \
    chown -R rotaryshield:rotaryshield /var/lib/rotaryshield /var/log/rotaryshield /run/rotaryshield

# Set working directory
WORKDIR /app

# Copy requirements first (for Docker cache optimization)
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/
COPY configs/ ./configs/
COPY setup.py .
COPY Readme.md .

# Install RotaryShield in development mode
RUN pip3 install -e .

# Copy example config to /etc/rotaryshield
RUN if [ -f configs/config.example.yml ]; then \
    cp configs/config.example.yml /etc/rotaryshield/config.yml; \
    fi

# Create a simple test config if none exists
RUN if [ ! -f /etc/rotaryshield/config.yml ]; then \
    echo "detection:\n  enabled: true\n  log_files:\n    - /var/log/auth.log\nblocking:\n  ban_time: 3600\n  firewall: auto" > /etc/rotaryshield/config.yml; \
    fi

# Set permissions
RUN chown -R rotaryshield:rotaryshield /app /etc/rotaryshield

# Switch to rotaryshield user
USER rotaryshield

# Set PATH to include local bin
ENV PATH="/home/rotaryshield/.local/bin:${PATH}"

# Default command - keep container running
CMD ["bash"]
