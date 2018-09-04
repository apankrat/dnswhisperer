#!/bin/bash
sudo killall dnswhisperer
sudo ./dnswhisperer -d -l /var/log/dnswhisperer.log -s 1.1.1.1
