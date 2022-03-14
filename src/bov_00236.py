#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib import ConvisoNucleiIntegration, GQLService, ReportService

PROJECT_ID = '10454'
API_KEY = "YxAi8_3FasfDwWKQ-nAENAPbwlpsA-z9E80rksG6bMg"

report_service = ReportService.ReportInterface(PROJECT_ID, False)
gql_service = GQLService.GQLInterface(API_KEY, PROJECT_ID)

co
if __name__ == "__main__":
  print("[+] Programmatic report generation...")
