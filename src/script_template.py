#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib import GQLService, ReportService

PROJECT_ID = 'PROJECT_ID'
API_KEY = "API_KEY"

report_service = ReportService.ReportInterface(PROJECT_ID, False)
gql_service = GQLService.GQLInterface(API_KEY, PROJECT_ID)


if __name__ == "__main__":
  print("[+] Programmatic report generation...")
