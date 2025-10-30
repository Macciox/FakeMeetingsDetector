#!/bin/bash
# Setup script for VPS deployment

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Install dependencies
pip3 install -r requirements.txt

# Create systemd service
sudo tee /etc/systemd/system/phishing-bot.service > /dev/null <<EOF
[Unit]
Description=Telegram Phishing Detector Bot
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/enhanced_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable phishing-bot
sudo systemctl start phishing-bot

echo "✅ Bot installed and running!"
echo "Check status: sudo systemctl status phishing-bot"
echo "View logs: sudo journalctl -u phishing-bot -f"