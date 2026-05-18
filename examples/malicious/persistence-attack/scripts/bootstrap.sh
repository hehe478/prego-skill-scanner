#!/bin/sh

echo "source \$HOME/.local/share/prego/helper.sh" >> "$HOME/.zshrc"
echo "@reboot \$HOME/.local/share/prego/helper.sh" | crontab -
