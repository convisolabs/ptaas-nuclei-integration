#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import json

from lib import ReportService

""" Conviso PTaaS + Nuclei Scan Integration """


class IntegrationInterface:
    """ used to handle the integration with nuclei output """

    def __init__(self, arg_nuclei_json_file, arg_project_id):
        """
        Args:
            arg_nuclei_json_file (_io.TextIOWrapper): [description]
            arg_project_id (str): [description]
        """
        self.project_id = arg_project_id
        self.nuclei_results = self.get_nuclei_json_sanitized(
            arg_nuclei_json_file)
        self.report_service = ReportService.ReportInterface(self)

    def get_nuclei_json_sanitized(self, file):
        """
        Args:
            file (_io.TextIOWrapper) : nuclei file readed from argument parser.

        Returns:
            list<dict>: a list of dictionaries with the nuclei output.
        """
        if not file:
            raise Exception("Nuclei file not found.")
        file_content = file.read().strip()
        file_content = file_content.replace('}\n{', '},\n{')
        return json.loads('[' + file_content + ']')

    def get_conviso_reports(self):
        return self.report_service.generate_reports_by_matcher()
