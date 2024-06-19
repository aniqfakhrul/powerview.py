#!/bin/bash
PKG_MGR=""
if ! command -v -- "pip3" > /dev/null 2>&1; then
	echo "pip3 command not found"
	exit 0
fi

# checking available package manager, other than apt and yum, i have no idea
if command -v -- "apt" > /dev/null 2>&1; then
	PKG_MGR="apt"
elif command -v -- "yum" > /dev/null 2>&1; then
	PKG_MGR="yum"
else
	echo "Package manager could not be recognized"
	exit 0
fi

# installing required package that is required by gssapi-python
if [ $PKG_MGR == "yum" ] ; then
	sudo yum check-update
	echo "Installing krb5-devel package"
	sudo yum -y install krb5-devel
elif [ $PKG_MGR == "apt" ] ; then
	sudo apt update
	echo "Installing libkrb5-dev package"
	sudo apt install -y libkrb5-dev
fi

# finally, he comes the real thing

echo "Uninstalling previous powerview.py"
sudo pip3 uninstall -y powerview.py

echo "Installing powerview.py"
sudo pip3 install "git+https://github.com/aniqfakhrul/powerview.py"

if ! command -v -- "powerview" > /dev/null 2>&1; then
	echo "Installation failed"
else
	echo "Installed. Use 'powerview' command"
fi