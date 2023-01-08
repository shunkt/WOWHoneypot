#!/bin/bash

cd `dirname $0`
cd ..
gunicorn -w 1 -b :8080 wowhoneypot:app