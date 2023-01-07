#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Welcome to Omotenashi Web Honeypot(WOWHoneypot)
# author @morihi_soc
# (c) 2017 @morihi_soc

import os
import sys
import traceback
import re
import random
import base64
import logging
import logging.handlers
import socket
import select
import urllib.parse
from flask import Flask, request, Response
from http.server import HTTPServer, BaseHTTPRequestHandler
from mrr_checker import parse_mrr
from datetime import datetime, timedelta, timezone

WOWHONEYPOT_VERSION = "1.3"

app = Flask(__name__)

JST = timezone(timedelta(hours=+9), 'JST')
logger = logging.getLogger('SyslogLogger')
logger.setLevel(logging.INFO)
syslog_enable = False
hunt_enable = False
ip = "0.0.0.0"
port = 8000
serverheader = "test"
artpath = "./art/"
accesslogfile = ""
wowhoneypotlogfile = ""
huntrulelogfile = ""
hunt_rules = []
default_content = []
mrrdata = {}
mrrids = []
timeout = 3.0
blocklist = {}
separator = " "
ipmasking = False


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>')
def index(path):
    if ipmasking:
        client_ip = ip
    else:
        client_ip = request.remote_addr

    if not ipmasking and client_ip in blocklist and blocklist[client_ip] > 3:
        logging_system(f"Access from blocklist ip({client_ip})", True, False)
        return "Internal Server Error", 500

    match = False
    for id in mrrids:
        if match:
            break

        if "method" in mrrdata[id]['trigger']:
            if not request.method == mrrdata[id]['trigger']['method']:
                continue

        uricontinue = False
        if "uri" in mrrdata[id]['trigger']:
            for u in mrrdata[id]['trigger']['uri']:
                if re.search(u, path) is None:
                    uricontinue = True
        if uricontinue:
            continue

        headercontinue = False
        if "header" in mrrdata[id]['trigger']:
            for h in mrrdata[id]['trigger']['header']:
                if re.search(h, str(request.headers)) is None:
                    headercontinue = True
        if headercontinue:
            continue

        bodycontinue = False
        body = request.get_data(as_text=True)
        if "body" in mrrdata[id]['trigger']:
            if len(body) == 0:
                continue
            for b in mrrdata[id]['trigger']['body']:
                if re.search(b, body) is None:
                    bodycontinue = True
        if bodycontinue:
            continue
        match = id

    status = 200
    if not match:
        resp = Response()
        resp.status_code = status
        resp.headers['Server'] = serverheader
        resp.content_type = "text/html"
        r = default_content[random.randint(0, len(default_content)-1)]
        resp.content_length = len(r)
        resp.content_encoding = 'utf-8'
        resp.set_data(r)
        return resp
    else:
        status = mrrdata[match]['response']['status']
        resp = Response()
        header_server_flag = False
        header_content_type_flag = False
        for name, value in mrrdata[match]['resnpose']['header'].items():
            resp.headers[name] = value
            if name == "Server":
                header_server_flag = True
            if name == 'Content-Type':
                header_content_type_flag = True

        if not header_server_flag:
            resp.headers["Server"] = serverheader
        if not header_content_type_flag:
            resp.headers["Content-Type"] = "text/html"
            r = mrrdata[match]['response']['body']
            resp.content_length = len(r)
            resp.content_encoding = 'utf-8'
            resp.set_data(r)
            return resp


@app.after_request
def before_req(response: Response):
    if 'host' in request.headers:
        hostname = request.headers['host']
    else:
        hostname = "blank:80"
    full_path = request.path
    if request.query_string != b'':
        full_path += f"?{request.query_string!s}"
    requet_line = f"{request.method} {full_path} {request.environ.get('SERVER_PROTOCOL')}"
    request_all = "{}\n{!s}{}".format(
        requet_line,
        request.headers,
        request.get_data(as_text=True))
    logging_access("[{time}]{s}{clientip}{s}{hostname}{s}\"{requestline}\"{s}{status_code}{s}{match_result}{s}{requestall}\n".format(
        time=get_time(),
        clientip=request.remote_addr,
        hostname=hostname,
        requestline=requet_line,
        status_code=response.status_code,
        match_result=1,
        requestall=base64.b64encode(
            request_all.encode('utf-8')).decode('utf-8'),
        s=separator
    ))
    return response


def logging_access(log):
    with open(accesslogfile, 'a') as f:
        f.write(log)
    if syslog_enable:
        logger.log(msg="{0} {1}".format(__file__, log), level=logging.INFO)


def logging_system(message, is_error, is_exit):
    if not is_error:  # CYAN
        print("\u001b[36m[INFO]{0}\u001b[0m".format(message))
        file = open(wowhoneypotlogfile, "a")
        file.write("[{0}][INFO]{1}\n".format(get_time(), message))
        file.close()

    else:  # RED
        print("\u001b[31m[ERROR]{0}\u001b[0m".format(message))
        file = open(wowhoneypotlogfile, "a")
        file.write("[{0}][ERROR]{1}\n".format(get_time(), message))
        file.close()

    if is_exit:
        sys.exit(1)

# Hunt


def logging_hunt(message):
    with open(huntrulelogfile, 'a') as f:
        f.write(message)


def get_time():
    return "{0:%Y-%m-%d %H:%M:%S%z}".format(datetime.now(JST))


def config_load():
    configfile = "./config.txt"
    if not os.path.exists(configfile):
        print(
            "\u001b[31m[ERROR]{0} dose not exist...\u001b[0m".format(configfile))
        sys.exit(1)
    with open(configfile, 'r') as f:
        logpath = "./"
        accesslogfile_name = "access_log"
        wowhoneypotlogfile_name = "wowhoneypot.log"
        huntlog_name = "hunting.log"
        syslogport = 514

        for line in f:
            if line.startswith("#") or line.find("=") == -1:
                continue
            if line.startswith("serverheader"):
                global serverheader
                serverheader = line.split('=')[1].strip()
            if line.startswith("port"):
                global port
                port = int(line.split('=')[1].strip())
            if line.startswith("artpath"):
                artpath = line.split('=')[1].strip()
            if line.startswith("logpath"):
                logpath = line.split('=')[1].strip()
            if line.startswith("accesslog"):
                accesslogfile_name = line.split('=')[1].strip()
            if line.startswith("separator"):
                global separator
                separator = line.strip().split('=')[1].split('"')[1]
                if len(separator) < 1:
                    separator = " "
            if line.startswith("wowhoneypotlog"):
                wowhoneypotlogfile_name = line.split('=')[1].strip()
            if line.startswith("syslog_enable"):
                global syslog_enable
                if line.split('=')[1].strip() == "True":
                    syslog_enable = True
                else:
                    syslog_enable = False
            if line.startswith("syslogserver"):
                syslogserver = line.split('=')[1].strip()
            if line.startswith("syslogport"):
                syslogport = line.split('=')[1].strip()
            if line.startswith("hunt_enable"):
                global hunt_enable
                if line.split('=')[1].strip() == "True":
                    hunt_enable = True
                else:
                    hunt_enable = False
            if line.startswith("huntlog"):
                huntlog_name = line.split('=')[1].strip()
            if line.startswith("ipmasking"):
                global ipmasking
                if line.split('=')[1].strip() == "True":
                    ipmasking = True
                else:
                    ipmasking = False

        global accesslogfile
        accesslogfile = os.path.join(logpath, accesslogfile_name)

        global wowhoneypotlogfile
        wowhoneypotlogfile = os.path.join(logpath, wowhoneypotlogfile_name)

        global huntrulelogfile
        huntrulelogfile = os.path.join(logpath, huntlog_name)

    # art directory Load
    if not os.path.exists(artpath) or not os.path.isdir(artpath):
        logging_system("{0} directory load error.".format(
            arttpath), True, True)

    defaultfile = os.path.join(artpath, "mrrules.xml")
    if not os.path.exists(defaultfile) or not os.path.isfile(defaultfile):
        logging_system("{0} file load error.".format(defaultfile), True, True)

    logging_system("mrrules.xml reading start.", False, False)

    global mrrdata
    mrrdata = parse_mrr(defaultfile, os.path.split(defaultfile)[0])

    global mrrids
    mrrids = sorted(list(mrrdata.keys()), reverse=True)

    if mrrdata:
        logging_system("mrrules.xml reading complete.", False, False)
    else:
        logging_system("mrrules.xml reading error.", True, True)

    defaultlocal_file = os.path.join(artpath, "mrrules_local.xml")
    if os.path.exists(defaultlocal_file) and os.path.isfile(defaultlocal_file):
        logging_system("mrrules_local.xml reading start.", False, False)
        mrrdata2 = parse_mrr(defaultlocal_file, os.path.split(defaultfile)[0])

        if mrrdata2:
            logging_system("mrrules_local.xml reading complete.", False, False)
        else:
            logging_system("mrrules_local.xml reading error.", True, True)

        mrrdata.update(mrrdata2)
        mrrids = sorted(list(mrrdata.keys()), reverse=True)

    artdefaultpath = os.path.join(artpath, "default")
    if not os.path.exists(artdefaultpath) or not os.path.isdir(artdefaultpath):
        logging_system("{0} directory load error.".format(
            artdefaultpath), True, True)

    global default_content
    for root, dirs, files in os.walk(artdefaultpath):
        for file in files:
            if not file.startswith(".") and file.endswith(".html"):
                tmp = open(os.path.join(artdefaultpath, file), 'r')
                default_content.append(tmp.read().strip())
                tmp.close()

    if len(default_content) == 0:
        logging_system("default html content not exist.", True, True)

    # Hunting
    if hunt_enable:
        huntrulefile = os.path.join(artpath, "huntrules.txt")
        if not os.path.exists(huntrulefile) or not os.path.isfile(huntrulefile):
            logging_system("{0} file load error.".format(
                huntrulefile), True, True)

        with open(huntrulefile, 'r') as f:
            for line in f:
                line = line.rstrip()
                if len(line) > 0:
                    hunt_rules.append(line)

    # Syslog
    if syslog_enable:
        try:
            sport = int(syslogport)
        except ValueError:
            logging_system("syslogport({0}) not valid.".format(
                syslogport), True, True)
        try:
            handler = logging.handlers.SysLogHandler(address=(syslogserver, int(sport)),
                                                     facility=16,  # facility 16: local0
                                                     socktype=socket.SOCK_STREAM)
            logger.addHandler(handler)
        except TimeoutError:
            logging_system(
                "syslog tcp connection timed out. Wrong hostname/port? ({0}:{1})".format(syslogserver, sport), True, True)


if __name__ == 'wowhoneypot':
    random.seed(datetime.now())

    try:
        config_load()
    except Exception:
        print(traceback.format_exc())
        sys.exit(1)
    logging_system("WOWHoneypot(version {0}) start. {1}:{2} at {3}".format(
        WOWHONEYPOT_VERSION, ip, port, get_time()), False, False)
    logging_system("Hunting: {0}".format(hunt_enable), False, False)
    logging_system("IP Masking: {0}".format(ipmasking), False, False)
