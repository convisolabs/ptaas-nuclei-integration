#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cli

service_exposition_items = [ 
  {
    "ip": "10.50.20.105",
    "port":80,
    "protocol": "http",
    "service":"Apache httpd 2.2.22 (Ubuntu)"
  },

  {
    "ip": "10.50.20.105",
    "port":443,
    "protocol": "ssl/http",
    "service":"Apache httpd 2.2.22 (Ubuntu)"
  },

  {
    "ip": "10.50.20.111",
    "port":80,
    "protocol": "http",
    "service":"Apache httpd 2.4.18 (Ubuntu)"
  },

  {
    "ip": "10.50.20.111",
    "port":443,
    "protocol": "ssl/http",
    "service":"Apache httpd 2.4.18 (Ubuntu)"
  },

  {
    "ip": "10.50.40.20",
    "port":80,
    "protocol": "http",
    "service":"Indy httpd 19.1.48.2891 Paessler PRTG bandwidth monitor"
  },

  {
    "ip": "10.50.40.20",
    "port":8080,
    "protocol": "http",
    "service":"Microsoft HTTPAPI httpd 2.0 SSDP/UPnP"
  },

  {
    "ip": "10.50.10.160",
    "port":80,
    "protocol": "http",
    "service":"Microsoft IIS httpd 7.5"},

  {
    "ip": "10.50.42.164",
    "port":80,
    "protocol": "http",
    "service":"Microsoft IIS httpd 7.5"},

  {
    "ip": "10.50.10.161",
    "port":80,
    "protocol": "http",
    "service":"Microsoft IIS httpd 7.5"},

  {
    "ip": "10.50.10.161",
    "port":443,
    "protocol": "ssl/http",
    "service":"Microsoft IIS httpd 7.5"},

  {
    "ip": "10.50.10.165",
    "port":80,
    "protocol": "http",
    "service":"Microsoft IIS httpd 8.5"},

  {
    "ip": "10.50.40.20",
    "port":135,
    "protocol": "msrpc",
    "service":"Microsoft Windows RPC"
  },
  {
    "ip": "10.50.40.20",
    "port":49152,
    "protocol": "msrpc",
    "service":"Microsoft Windows RPC"
  },
  {
    "ip": "10.50.40.20",
    "port":49153,
    "protocol": "msrpc",
    "service":"Microsoft Windows RPC"
  },
  {
    "ip": "10.50.40.20",
    "port":49154,
    "protocol": "msrpc",
    "service":"Microsoft Windows RPC"
  },
  {
    "ip": "10.50.40.20",
    "port":49155,
    "protocol": "msrpc",
    "service":"Microsoft Windows RPC"
  },
  {
    "ip": "10.50.40.20",
    "port":445,
    "protocol": "microsoft-ds",
    "service":"Microsoft Windows Server 2008 R2 - 2012 microsoft-ds"
  },
  {
    "ip": "10.50.40.20",
    "port":139,
    "protocol": "netbios-ssn",
    "service":"Microsoft Windows netbios-ssn"
  },
  {
    "ip": "10.50.20.105",
    "port":22,
    "protocol": "ssh",
    "service":"OpenSSH 5.9p1 Debian 5ubuntu1.10 Ubuntu Linux; protocol 2.0"
  },
  {
    "ip": "10.50.20.111",
    "port":22,
    "protocol": "ssh",
    "service":"OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 Ubuntu Linux; protocol 2.0"
  },
  {
    "ip": "10.50.40.224",
    "port":22,
    "protocol": "ssh",
    "service":"OpenSSH 7.4 protocol 2.0"
  },
  {
    "ip": "10.50.20.115",
    "port":22,
    "protocol": "ssh",
    "service":"OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0"
  }
]
