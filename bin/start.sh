#!/bin/bash

cd `dirname $0`/..
if type "python3" > /dev/null 2>&1; then
    python3 wowhoneypot.py
elif type "python" > /dev/null 2>&1; then
    python wowhoneypot.py
else
    echo 'no python'
fi
