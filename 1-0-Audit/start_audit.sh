#!/bin/bash
sudo rm /var/log/audit/audit.log
sudo systemctl restart auditd
sudo auditctl -R audit.rules
sudo auditctl -l
