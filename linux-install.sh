#!/bin/bash

# Check user
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit
fi

echo "Installing PAgent..."

# Downloda pagent
echo "Downloading PAgent..."
curl -L -o /usr/local/bin/agent https://github.com/purplemaze-net/Agentv4/releases/latest/download/agent-linux-x64
chmod +x /usr/local/bin/agent

# Get public IP
echo "Detecting public IP..."
PUBLIC_IP=$(curl -s ifconfig.me)
echo "Detected public IP: $PUBLIC_IP"

# Ask for IP override
read -p "Do you want to use a different public IP? (leave empty to use $PUBLIC_IP): " OVERRIDE_IP
if [ ! -z "$OVERRIDE_IP" ]; then
    PUBLIC_IP=$OVERRIDE_IP
fi

# Get configuration
read -p "Server Slug (find it on the settings page) : " SLUG
read -p "FiveM server port : " PORT

# Create systemd service file
cat > /etc/systemd/system/pagent.service << EOF
[Unit]
Description=PAgent Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/agent "$SLUG:$PUBLIC_IP:$PORT"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start service
systemctl daemon-reload
systemctl enable pagent
systemctl start pagent

echo "PAgent installed and started as a service"
echo "You can check the status with: systemctl status pagent"