#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections import OrderedDict

from lib import ConvisoNucleiIntegration

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

def parse_nmap_scriptname(string):
  strings = string.split(".")
  if not len(strings)>2:
    return None
  return strings[2]

def get_reports_1(integration_interface):
  reports = []
  for item in service_exposition_items:
    report = ConvisoNucleiIntegration.ReportService.OtherVulnerabilityReport(
      projectId=integration_interface.report_service.project_id,
      vulnerabilityTemplateId=f"628",
      evidenceArchives=integration_interface.report_service.parse_evidences([ f"""{item}""" ]),
      probability=f"low",
      impact=f"low",
      impactResume=f"Um usuário malicioso pode usar o conhecimento sobre o serviço {item.get('service')} para explorar o sistema.",
      description=f"Interagindo com a aplicação {item.get('ip')}",
      host=f"{item.get('ip')}",
      protocol=f"{item.get('protocol')}",
      steps=f"1- Realizar conexão com o serviço no endereço: {item.get('protocol')}://{item.get('service')}:{item.get('port')}\n2- Observar o banner da resposta.",
      vector=f"Conexão ao dispositivo {item.get('ip')} através do protocolo {item.get('protocol')}",
    )
    reports.append(report)
  return reports


if __name__ == "__main__":
  print("[+] Programmatic report generation...")

  integration_interface = ConvisoNucleiIntegration.IntegrationInterface(OrderedDict({
    "project_id": "10319",
    "api_key": "Np59TzYlk6qy3y0Gl_UGkEg5Q9Nc7YZAjUIXyOKqSiE"
  }))

  reports_1 = get_reports_1(integration_interface)

  if len(reports_1):
    print(f"[+] Deploying {len(reports_1)} reports...")
    integration_interface.gql_service.deploy_reports(reports_1)
  else:
    print("[-] Something wrong on deploy.")    
    print(f"[+] Generated {len(reports_1)} reports...")
    
