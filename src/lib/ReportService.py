#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

from functools import reduce

from lib import FlowNotificationParser


class ReportInterface:
    """ used to handle the report generation """

    def __init__(self, integration_interface):
        self.integration_interface_inheritance = integration_interface
        self.flow_parser_inheritance = FlowNotificationParser.ParserInterface(
            self.integration_interface_inheritance.project_id)
        self.report_reference_by_matcher_name = {
            'permission-policy': {
                'generator': lambda nuclei_output: self.__report_1048(nuclei_output),
            },
            'content-security-policy': {
                'generator': lambda nuclei_output: self.__report_598(nuclei_output),
            },
            'strict-transport-security': {
                'generator': lambda nuclei_output: self.__report_599(nuclei_output),
            },
            'x-content-type-options': {
                'generator': lambda nuclei_output: self.__report_597(nuclei_output),
            },
            'x-frame-options': {
                'generator': lambda nuclei_output: self.__report_596(nuclei_output),
            },
        }

    def __report_1048(self, nuclei_item):
        description = f"""A aplicação <a href="{nuclei_item['host']}">{nuclei_item['host']}</a> não possui o cabeçalho de resposta "permissions policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        return self.flow_parser_inheritance.create_mutation_body(
            nuclei_item,
            1048,
            description
        )
    
    def __report_598(self, nuclei_item):
        description = f"""A aplicação <a href="{nuclei_item['host']}">{nuclei_item['host']}</a> não possui o cabeçalho de resposta "content-security-policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        return self.flow_parser_inheritance.create_mutation_body(
            nuclei_item,
            598,
            description
        )

    def __report_599(self, nuclei_item):
        description = f"""A aplicação <a href="{nuclei_item['host']}">{nuclei_item['host']}</a> não possui o cabeçalho de resposta "strict-transport-security" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        return self.flow_parser_inheritance.create_mutation_body(
            nuclei_item,
            599,
            description
        )

    def __report_597(self, nuclei_item):
        description = f"""A aplicação <a href="{nuclei_item['host']}">{nuclei_item['host']}</a> não possui o cabeçalho de resposta "x-content-type-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        return self.flow_parser_inheritance.create_mutation_body(
            nuclei_item,
            597,
            description
        )

    def __report_596(self, nuclei_item):
        description = f"""A aplicação <a href="{nuclei_item['host']}">{nuclei_item['host']}</a> não possui o cabeçalho de resposta "x-frame-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        return self.flow_parser_inheritance.create_mutation_body(
            nuclei_item,
            596,
            description
        )

    def is_reportable(self, matcher_name):
        return bool(self.report_reference_by_matcher_name.get(matcher_name))

    def get_report_template_by_matcher_name(self, nuclei_output):
        return self.report_reference_by_matcher_name[nuclei_output['matcher-name']]

    def generate_conviso_report(self, nuclei_item):
        report_template = self.get_report_template_by_matcher_name(
            nuclei_item)
        return report_template['generator'](nuclei_item)

    def parse_nuclei_output_by_matcher(self, conviso_reports, nuclei_item):
        if self.is_reportable(nuclei_item['matcher-name']):
            report = self.generate_conviso_report(nuclei_item)
            conviso_reports.append(report)
        return conviso_reports

    def generate_reports_by_matcher(self):
        return reduce(
            self.parse_nuclei_output_by_matcher,
            self.integration_interface_inheritance.nuclei_results,
            [])