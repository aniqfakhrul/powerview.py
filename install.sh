#!/bin/bash
sudo apt update

echo "Install libkrb5-dev package"
sudo apt install -y libkrb5-dev

echo "Installing powerview.py"
sudo pip3 install "git+https://github.com/aniqfakhrul/powerview.py"

if ! command -v -- "powerview" > /dev/null 2>&1; then
  echo "'powerview' command not found"
else
  echo "Installed. Use 'powerview' command"
fi
