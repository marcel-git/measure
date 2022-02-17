#!/usr/bin/env bash
sh -c 'exec python3 script.py'
sh -c 'exec python3 tcpClient.py &'
sh -c 'exec python3 script.py'
