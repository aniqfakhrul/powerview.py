#!/bin/bash
echo "Install libkrb5-dev package"
sudo apt install libkrb5-dev

echo "Installing powerview.py"
pip3 install "git+https://github.com/aniqfakhrul/powerview.py"

echo "Installed. Use 'powerview' command"
