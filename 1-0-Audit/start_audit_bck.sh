#!/bin/bash

sudo rm /var/log/audit/audit.log
sudo systemctl stop auditd

chown root:root audit.rules
chmod 0600 audit.rules

auditctl -D
auditctl -R audit.rules
auditctl -l

sudo systemctl start auditd
