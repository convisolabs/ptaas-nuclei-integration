#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import json
from functools import reduce

""" Conviso PTaaS + Nuclei Scan Integration """


class ReportInterface:
    def __init__(self, integration_interface):
        self.integration_interface = integration_interface
        self.report_reference_by_matcher_name = {
            'content-security-policy': {
                'template-id': 598,
                'report': lambda nuclei_output: self.report_598(nuclei_output),
            },
            'strict-transport-security': {
                'template-id': 599,
                'report': lambda nuclei_output: self.report_599(nuclei_output),
            },
            'x-content-type-options': {
                'template-id': 597,
                'report': lambda nuclei_output: self.report_597(nuclei_output),
            },
            'x-frame-options': {
                'template-id': 596,
                'report': lambda nuclei_output: self.report_596(nuclei_output),
            },
        }

    def is_reportable(self, matcher_name):
        """ Verifies if there is a report template reference configured to be issued.
        """
        return bool(self.report_reference_by_matcher_name.get(matcher_name))

    def get_report_template_by_matcher_name(self, nuclei_output):
        return self.report_reference_by_matcher_name[nuclei_output['matcher-name']]

    def generate_conviso_report(self, nuclei_output):
        """ Creates a new JSON from Nuclei JSON, crossing with preconfigured templates to write each report. 
        Takes the template reference for the current 'matcher-name'.
        Invokes its reference function to generate the its configured report.
        """
        report_template = self.get_report_template_by_matcher_name(
            nuclei_output)
        return report_template['report'](nuclei_output)

    def parse_nuclei_output_by_matcher(self, conviso_reports, nuclei_output):
        if self.is_reportable(nuclei_output['matcher-name']):
            report = self.generate_conviso_report(nuclei_output)
            conviso_reports.append(report)
        return conviso_reports

    def generate_reports(self):
        """ Itera over self.integration_interface.json_dict to generate Conviso reports. 
        """
        return reduce(self.parse_nuclei_output_by_matcher, self.integration_interface.JSON_DICT, [])

    def report_598(self, nuclei_output):
        return 'return:report_598'

    def report_599(self, nuclei_output):
        return 'return:report_599'

    def report_597(self, nuclei_output):
        return 'return:report_597'

    def report_596(self, nuclei_output):
        return 'return:report_596'


class IntegrationInterface:
    def __init__(self, arg_nuclei_json_file):
        self.JSON_DICT = self.get_nuclei_json_sanitized(arg_nuclei_json_file)
        self.report_interface = ReportInterface(self)

    def get_nuclei_json_sanitized(self, file):
        """Read the nuclei file.

        Args:
            file (<class '_io.TextIOWrapper'>) : nuclei file readed from argument parser.

        Returns:
            list<dict>: a list of dictionaries with the nuclei output.
        """
        file_content = file.read().strip()
        file_content = file_content.replace('}\n{', '},\n{')
        return json.loads('[' + file_content + ']')

    def get_conviso_reports(self):
        return self.report_interface.generate_reports()
