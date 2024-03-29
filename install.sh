#!/bin/bash
if ! command -v -- "pip3" > /dev/null 2>&1; then
  echo "pip3 command not found"
  exit 0
fi

sudo apt update

echo "Install libkrb5-dev package"
sudo apt install -y libkrb5-dev

echo "Uninstalling previous powerview.py"
sudo pip3 uninstall -y powerview.py

echo "Installing powerview.py"
sudo pip3 install "git+https://github.com/aniqfakhrul/powerview.py" --upgrade

if ! command -v -- "powerview" > /dev/null 2>&1; then
  echo "'powerview' command not found"
else
  echo "Installed. Use 'powerview' command"
fi
