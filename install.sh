#!/bin/bash
if [ "$(id -u)" != "0" ]; then
  echo '[Error]: You must run this setup script with root privileges.'
  echo
  exit 1
fi
chmod +x start.sh
chmod +x install.sh
mkdir /opt/amon-eye/
mv .off.c /opt/amon-eye/
apt-get -y install python3-pip
apt-get -y install default-jre
rm -rf install.sh
