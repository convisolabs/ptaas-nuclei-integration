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
from lib import FlowNotificationBodyParser

""" Conviso PTaaS + Nuclei Scan Integration """


class ReportInterface:
    def __init__(self, integration_interface):
        self.integration_interface_inheritance = integration_interface
        self.flow_body_parser_inheritance = FlowNotificationBodyParser.FlowNotificationBodyParser(
            self.integration_interface_inheritance.project_id)
        self.report_reference_by_matcher_name = {
            'content-security-policy': {
                'report': lambda nuclei_output: self.report_598(nuclei_output),
            },
            'strict-transport-security': {
                'report': lambda nuclei_output: self.report_599(nuclei_output),
            },
            'x-content-type-options': {
                'report': lambda nuclei_output: self.report_597(nuclei_output),
            },
            'x-frame-options': {
                'report': lambda nuclei_output: self.report_596(nuclei_output),
            },
        }

    def is_reportable(self, matcher_name):
        return bool(self.report_reference_by_matcher_name.get(matcher_name))

    def get_report_template_by_matcher_name(self, nuclei_output):
        return self.report_reference_by_matcher_name[nuclei_output['matcher-name']]

    def generate_conviso_report(self, nuclei_item):
        report_template = self.get_report_template_by_matcher_name(
            nuclei_item)
        return report_template['report'](nuclei_item)

    def parse_nuclei_output_by_matcher(self, conviso_reports, nuclei_item):
        if self.is_reportable(nuclei_item['matcher-name']):
            report = self.generate_conviso_report(nuclei_item)
            conviso_reports.append(report)
        return conviso_reports

    def generate_reports_by_matcher(self):
        return reduce(self.parse_nuclei_output_by_matcher, self.integration_interface_inheritance.JSON_DICT, [])

    def report_598(self, nuclei_output):
        description = """A aplicação "{host}" não possui o cabeçalho de resposta "content-security-policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""".format(
            host=nuclei_output['host']
        )
        return self.flow_body_parser_inheritance.create_mutation_body(
            nuclei_output,
            598,
            description
        )

    def report_599(self, nuclei_output):
        description = """A aplicação "{host}" não possui o cabeçalho de resposta "strict-transport-security" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""".format(
            host=nuclei_output['host']
        )
        return self.flow_body_parser_inheritance.create_mutation_body(
            nuclei_output,
            599,
            description
        )

    def report_597(self, nuclei_output):
        description = """A aplicação "{host}" não possui o cabeçalho de resposta "x-content-type-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""".format(
            host=nuclei_output['host']
        )
        return self.flow_body_parser_inheritance.create_mutation_body(
            nuclei_output,
            597,
            description
        )

    def report_596(self, nuclei_output):
        description = """A aplicação "{host}" não possui o cabeçalho de resposta "x-frame-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""".format(
            host=nuclei_output['host']
        )
        return self.flow_body_parser_inheritance.create_mutation_body(
            nuclei_output,
            596,
            description
        )


class IntegrationInterface:
    def __init__(self, arg_nuclei_json_file, arg_project_id):
        self.JSON_DICT = self.get_nuclei_json_sanitized(arg_nuclei_json_file)
        self.project_id = arg_project_id
        self.report_interface = ReportInterface(self)

    def get_nuclei_json_sanitized(self, file):
        """Read the nuclei file.

        Args:
            file (<class '_io.TextIOWrapper'>) : nuclei file readed from argument parser.

        Returns:
            list<dict>: a list of dictionaries with the nuclei output.
        """
        if not file:
            raise Exception("Nuclei file not found.")
        file_content = file.read().strip()
        file_content = file_content.replace('}\n{', '},\n{')
        return json.loads('[' + file_content + ']')

    def get_conviso_reports(self):
        return self.report_interface.generate_reports_by_matcher()
