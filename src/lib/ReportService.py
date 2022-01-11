#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.


import base64
import logging
import os
from codecs import encode
from datetime import datetime
from shutil import rmtree

UTF8 = "utf-8"


class NotificationReport:
    """Handler to manipulate Conviso Notification Report.

    Properties:
        projectId (int): Conviso Project ID.
        vulnerabilityTemplateId (int): Conviso Template ID
        description (str): Report description.
        evidenceArchives (list<_io.TextIOWrapper>): List with binary evidences.
        nucleiReference (dict): Nuclei test reference.
        gql_reference (string): Reference identifier for which to see in GQL.
    """

    def __init__(
        self,
        projectId,
        vulnerabilityTemplateId,
        description,
        evidenceArchives,
        nucleiReference,
    ):
        self.projectId = int(projectId)
        self.vulnerabilityTemplateId = int(vulnerabilityTemplateId)
        self.description = description
        self.evidenceArchives = evidenceArchives  # todo: create binary evidence
        self.nucleiReference = nucleiReference
        self.gql_reference = "notification"


class VulnerabilityReport:
    """Handler to manipulate Conviso Vulnerability Report.

    Properties:
        projectId (int): Conviso Project ID.
        vulnerabilityTemplateId (int): Conviso Template ID
        description (str): Report description.
        evidenceArchives (list<_io.TextIOWrapper>): List with binary evidences.
        nucleiReference (dict): Nuclei test reference.
        gql_reference (string): Reference identifier for which to see in GQL.
    """

    def __init__(
        self,
        projectId,
        vulnerabilityTemplateId,
        description,
        evidenceArchives,
        nucleiReference,
    ):
        self.projectId = int(projectId)
        self.vulnerabilityTemplateId = int(vulnerabilityTemplateId)
        self.description = description
        self.evidenceArchives = evidenceArchives  # todo: create binary evidence
        self.nucleiReference = nucleiReference
        self.gql_reference = "vulnerability"


class ReportInterface:
    """Handler to parsing and creating Conviso Platform reports."""

    def __init__(self, project_id):
        self.__evidences_tmp_dir = "./tmp"
        self.project_id = project_id
        self.reports = []
        self.reference_reports = [
            {
                "matcher-name": "test-8ff55be1-4ed4-5df2-9aa4-970d78b0437e",
                "generator": lambda nuclei_reference: self.__report_test(
                    nuclei_reference
                ),
            },
            {
                "matcher-name": "x-content-type-options",
                "generator": lambda nuclei_reference: self.__report_597(
                    nuclei_reference
                ),
            },
            {
                "matcher-name": "x-frame-options",
                "generator": lambda nuclei_reference: self.__report_596(
                    nuclei_reference
                ),
            },
            {
                "matcher-name": "content-security-policy",
                "generator": lambda nuclei_reference: self.__report_598(
                    nuclei_reference
                ),
            },
            {
                "matcher-name": "strict-transport-security",
                "generator": lambda nuclei_reference: self.__report_599(
                    nuclei_reference
                ),
            },
            {
                "matcher-name": "permission-policy",
                "generator": lambda nuclei_reference: self.__report_1048(
                    nuclei_reference
                ),
            },
        ]
        self.__setup_tmp_directory()

    def __report_test(self, nuclei_reference):
        impact = f"""impact test in {nuclei_reference['host']} """
        description = f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "content-security-policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        evidenceArchives = self.__parse_evidences(
            [
                self.__mount_default_evidence(nuclei_reference),
                f"""Et in do consequat \n\r\t # in excepteur aute labore est culpa sint laborum: 
                \n\r{nuclei_reference['host']} - {description}""",
                f""" {impact}""",
                f""" test-8ff55be1-4ed4-5df2-9aa4-970d78b0437e """,
            ]
        )
        return VulnerabilityReport(
            self.project_id, 257, description, evidenceArchives, nuclei_reference
        )

    def __report_1048(self, nuclei_reference):
        description = f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "permissions policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        evidenceArchives = self.__parse_evidences(nuclei_reference)
        return NotificationReport(
            self.project_id, 1048, description, evidenceArchives, nuclei_reference
        )

    def __report_598(self, nuclei_reference):
        description = f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "content-security-policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        evidenceArchives = self.__parse_evidences(nuclei_reference)
        return NotificationReport(
            self.project_id, 598, description, evidenceArchives, nuclei_reference
        )

    def __report_599(self, nuclei_reference):
        description = f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "strict-transport-security" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        evidenceArchives = self.__parse_evidences(nuclei_reference)
        return NotificationReport(
            self.project_id, 599, description, evidenceArchives, nuclei_reference
        )

    def __report_596(self, nuclei_reference):
        description = f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "x-frame-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        evidenceArchives = self.__parse_evidences(nuclei_reference)
        return NotificationReport(
            self.project_id, 596, description, evidenceArchives, nuclei_reference
        )

    def __report_597(self, nuclei_reference):
        description = f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "x-content-type-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta."""
        evidenceArchives = self.__parse_evidences(
            [
                f""" 0: test """,
                f""" 1: {nuclei_reference['host']} """,
                f""" 2: {nuclei_reference['matcher-name']} """,
            ],
        )
        return NotificationReport(
            self.project_id, 597, description, evidenceArchives, nuclei_reference
        )

    def __setup_tmp_directory(self):
        if os.path.isdir(self.__evidences_tmp_dir):
            rmtree(self.__evidences_tmp_dir)
        os.makedirs(self.__evidences_tmp_dir, exist_ok=True)

    def __generate_token_stamp(self):
        bin_timestamp = str(datetime.now().timestamp()).encode(UTF8)
        token = base64.b64encode(bin_timestamp).decode(UTF8)
        token = token.rstrip("=")
        return encode(token, "rot_13")

    def open_token_stamp(self, token):
        token = encode(token, "rot_13")
        token += "="
        return base64.b64decode(token.encode(UTF8)).decode(UTF8)

    def __close_reader(self, evidenceArchives):
        """Memory leak protection."""
        for evidence in evidenceArchives:
            evidence.close()

    def __mount_default_evidence(self, nuclei_reference):
        return f"""
        \r# REQUEST
        \r{nuclei_reference['request']} 
        \r# RESPONSE
        \r{nuclei_reference['response']}
        """

    def __mount_binary_evidence(self, evidence_data):
        token = self.__generate_token_stamp()
        tmp_filepath = "{}/evidence-{}.txt".format(self.__evidences_tmp_dir, token)
        tmp_file = open(tmp_filepath, "w")
        created_evidences = []
        if evidence_data:
            evidence_data = evidence_data.strip()
            tmp_file.write(evidence_data)
        tmp_file.close()
        return open(tmp_filepath, "rb")

    def __parse_evidences(self, evidences=list):
        """Used to write the evidences in files on the disk to store it as binary to GQL API

        Args:
            evidences (list<FormatedString>): A list of messages to create each evidence. FormatedString means f""" """

        Returns:
            list<_io.TextIOWrapper>: A list of parsed evidences
        """
        if not evidences:
            return []

        parsed_evidences = []
        for evidences in evidences:
            mounted_evidence = self.__mount_binary_evidence(evidences)
            parsed_evidences.append(mounted_evidence)
        return parsed_evidences

    def __get_reference_by_matcher_name(self, nuclei_item):
        for ref in self.reference_reports:
            if ref["matcher-name"] == nuclei_item["matcher-name"]:
                return ref

    def __get_reference_report(self, nuclei_item):
        ref_by_matcher_name = self.__get_reference_by_matcher_name(nuclei_item)
        if ref_by_matcher_name:
            return ref_by_matcher_name

    def __parse_reports(self, nuclei_scan_results):
        """Generate Conviso Platform reports by parsing nuclei results and crossing with preconfigured reports.

        Args:
            nuclei_scan_results (list<dict>): nuclei scan results

        Returns:
            list<dict>: parsed Conviso Platform reports
        """
        parsed_reports = []
        for nuclei_item in nuclei_scan_results:
            reference = self.__get_reference_report(nuclei_item)
            if bool(reference):
                report = reference["generator"](nuclei_item)
                logging.debug(
                    f"""[DBG] Generated report: {report.gql_reference} - {report.vulnerabilityTemplateId} - {report.nucleiReference["host"]} - {report.nucleiReference["matcher-name"]}"""
                )
                parsed_reports.append(report)
        return parsed_reports

    def create_reports(self, nuclei_scan_results):
        """Consume the nuclei results and create a report for each one that exists preconfigured.

        Returns:
            list<NotificationReport>: see src/lib/ReportService.py for further details.
        """
        self.reports = self.__parse_reports(nuclei_scan_results)
        return self.reports
