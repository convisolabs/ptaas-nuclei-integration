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
from random import randint
from shutil import rmtree

UTF8 = "utf-8"


def base64encode(string=""):
    return base64.b64encode(str(string).encode(UTF8)).decode(UTF8)


def base64decode(string=""):
    return base64.b64decode(str(string).encode(UTF8)).decode(UTF8)


def get_random_string():
    return base64encode(randint(0, 9)).rstrip("=")


class NotificationReport:
    """Handler to manipulate Conviso Notification Report.  Further information: https://docs.convisoappsec.com/api/graphql/documentation/mutations/create-notification

    Properties:
        vulnerabilityTemplateId (int): Conviso Template ID
        projectId (int): Conviso Project ID.
        gqlReference (string): Its a constant. Reference identifier for which to see in GQL.
        evidenceArchives (list<_io.TextIOWrapper>): List with binary evidences.
        description (str): Report description.
        [nucleiReference] (dict): Nuclei test reference.
    """

    def __init__(
        self,
        projectId,
        vulnerabilityTemplateId,
        description,
        evidenceArchives,
        nucleiReference,
    ):
        self.gqlReference = "createNotification"
        self.clientMutationId = "ptani-78f6a7b4-154e-5e5a-b7cc-079ce31acd86"
        self.projectId = int(projectId)
        self.vulnerabilityTemplateId = int(vulnerabilityTemplateId)
        self.description = description
        self.evidenceArchives = evidenceArchives  # todo: create binary evidence
        self.nucleiReference = nucleiReference if nucleiReference else None


class WebVulnerabilityReport:
    """Handler to manipulate Conviso Vulnerability Report. Further information: https://docs.convisoappsec.com/api/graphql/documentation/inputs/create-web-vulnerability-input/

    Properties:
        clientMutationId ("ptani-78f6a7b4-154e-5e5a-b7cc-079ce31acd86"): Used to identify the requests done from this tool to Conviso GQL API.
        projectId (int):                          Conviso Project ID.
        vulnerabilityTemplateId (int):            Conviso Template ID
        evidenceArchives ([_io.TextIOWrapper]):   List with binary evidences.
        probability (["high", "medium", "low"]):  Vulnerability probability.
        impact (["high", "medium", "low"]):       Impact of the vulnerability.
        impactResume (str):                       Description of the impact.
        description (str):                        Description of the vulnerability.
        webMethod (["GET", "POST", "DELETE", "PUT", "PATCH", "HEAD", "CONNECT", "OPTIONS", "TRACE"]):
        webParameters (str):                      Parameters used in the web request.
        webProtocol (str):                        Protocol used in the web request.
        webRequest (str):                         Reported request
        webResponse (str):                        Reported response
        webSteps (str):                           Steps to reproduce the vulnerability.
        webUrl (str):                             The vulnerable target.
        invaded (bool[default=False]):            True if the environment was compromised.
        invadedEnvironmentDescription (str):      Required if invaded is True.

    Returns:
        WebVulnerabilityReport:
    """

    def __init__(
        self,
        projectId,
        vulnerabilityTemplateId,
        probability,
        impact,
        impactResume,
        description,
        evidenceArchives,
        webMethod,
        webParameters,
        webProtocol,
        webRequest,
        webResponse,
        webSteps,
        webUrl,
        nucleiReference,
        invaded=False,
        invadedEnvironmentDescription="",
    ):
        self.gqlReference = "createWebVulnerability"
        self.clientMutationId = "ptani-78f6a7b4-154e-5e5a-b7cc-079ce31acd86"
        self.projectId = int(projectId)
        self.vulnerabilityTemplateId = int(vulnerabilityTemplateId)
        self.probability = probability
        self.impact = impact
        self.impactResume = impactResume
        self.description = description
        self.evidenceArchives = evidenceArchives
        self.webMethod = webMethod
        self.webParameters = webParameters
        self.webProtocol = webProtocol
        self.webRequest = webRequest
        self.webResponse = webResponse
        self.webSteps = webSteps
        self.webUrl = webUrl
        self.nucleiReference = nucleiReference
        self.invaded = invaded
        self.invadedEnvironmentDescription = invadedEnvironmentDescription

class OtherVulnerabilityReport:
    """Handler to manipulate Conviso Vulnerability Report. Further information: https://docs.convisoappsec.com/api/graphql/documentation/inputs/create-web-vulnerability-input/

    Properties:
        clientMutationId ("ptani-78f6a7b4-154e-5e5a-b7cc-079ce31acd86"): Used to identify the requests done from this tool to Conviso GQL API.
        projectId (int):                          Conviso Project ID.
        vulnerabilityTemplateId (int):            Conviso Template ID
        evidenceArchives ([_io.TextIOWrapper]):   List with binary evidences.
        probability (["high", "medium", "low"]):  Vulnerability probability.
        impact (["high", "medium", "low"]):       Impact of the vulnerability.
        impactResume (str):                       Description of the impact.
        description (str):                        Description of the vulnerability.
        invaded (bool[default=False]):            True if the environment was compromised.
        invadedEnvironmentDescription (str):      Required if invaded is True.
        host (str):                               Host of the vulnerability.
        protocol (str):                           Protocol used in the web request.
        steps (str):                              Steps to reproduce the vulnerability.                                
        vector (str):                             Vector used in the web request.

    Returns:
        OtherVulnerabilityReport:
    """

    def __init__(
        self,
        projectId,
        vulnerabilityTemplateId,
        evidenceArchives,
        probability,
        impact,
        impactResume,
        description,
        host,
        protocol,
        steps,
        vector,
        nucleiReference=None,
        invaded=False,
        invadedEnvironmentDescription="",
    ):
        self.gqlReference = "createWebVulnerability"
        self.clientMutationId = "ptani-78f6a7b4-154e-5e5a-b7cc-079ce31acd86"
        self.projectId = int(projectId)
        self.vulnerabilityTemplateId = int(vulnerabilityTemplateId)
        self.probability = probability
        self.impact = impact
        self.impactResume = impactResume
        self.description = description
        self.evidenceArchives = evidenceArchives
        self.nucleiReference = nucleiReference
        self.invaded = invaded
        self.invadedEnvironmentDescription = invadedEnvironmentDescription
        self.host = host
        self.protocol = protocol
        self.steps = steps
        self.vector = vector


class ReportInterface:
    """Handler to parsing and creating Conviso Platform reports."""

    def __init__(self, project_id, is_english):
        self.evidences_tmp_dir = "./tmp"
        self.project_id = project_id
        self.is_english = is_english
        self.reports = []
        self.reference_reports = [
            {
                "matcher-name": "x-content-type-options",
                "parser": lambda nuclei_reference: self.report_597(nuclei_reference),
            },
            {
                "matcher-name": "x-frame-options",
                "parser": lambda nuclei_reference: self.report_596(nuclei_reference),
            },
            {
                "matcher-name": "content-security-policy",
                "parser": lambda nuclei_reference: self.report_598(nuclei_reference),
            },
            {
                "matcher-name": "strict-transport-security",
                "parser": lambda nuclei_reference: self.report_599(nuclei_reference),
            },
            {
                "matcher-name": "permission-policy",
                "parser": lambda nuclei_reference: self.report_1048(nuclei_reference),
            },
        ]
        self.setup_tmp_directory()

    def report_web(self, nuclei_reference):
        return WebVulnerabilityReport(
            projectId=self.project_id,
            vulnerabilityTemplateId=662,
            probability="low",
            impact="low",
            impactResume=f"""impact test in {nuclei_reference['host']} """,
            description=f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "content-security-policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""",
            evidenceArchives=self.parse_evidences(
                [self.mount_default_evidence(nuclei_reference)]
            ),
            nucleiReference=nuclei_reference,
            webMethod="POST",
            webParameters="param=value",
            webProtocol="HTTPS",
            webRequest=f"{nuclei_reference['request']}",
            webResponse=f"{nuclei_reference['response']}",
            webSteps=f"1-{nuclei_reference['host']} \n\r2-bbbbbbbbbbbbbbbbbbbb \n\r3-cccccccccccccccccccc \n\r4-ddddddddddddddddddddd.",
            webUrl=f"{nuclei_reference['host']}",
        )

    def report_1048(self, nuclei_reference):
        if self.is_english is True:
            return NotificationReport(
                projectId=self.project_id,
                vulnerabilityTemplateId=776,
                description=f"""The application <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> does not have the response header "Permissions-Policy" as shown in evidence. This can be validated by making a request to the application quoted above and observing its response.""",
                evidenceArchives=self.parse_evidences(
                    [
                        self.mount_default_evidence(nuclei_reference),
                    ]
                ),
                nucleiReference=nuclei_reference,
            )
        return NotificationReport(
            projectId=self.project_id,
            vulnerabilityTemplateId=1048,
            description=f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "Permissions-Policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""",
            evidenceArchives=self.parse_evidences(
                [
                    self.mount_default_evidence(nuclei_reference),
                ]
            ),
            nucleiReference=nuclei_reference,
        )

    def report_598(self, nuclei_reference):
        if self.is_english is True:
            return NotificationReport(
                projectId=self.project_id,
                vulnerabilityTemplateId=684,
                description=f"""The application <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> does not have the response header "Content-Security-Policy" as shown in evidence. This can be validated by making a request to the application quoted above and observing its response.""",
                evidenceArchives=self.parse_evidences(
                    [
                        self.mount_default_evidence(nuclei_reference),
                    ]
                ),
                nucleiReference=nuclei_reference,
            )
        return NotificationReport(
            projectId=self.project_id,
            vulnerabilityTemplateId=598,
            description=f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "Content-Security-Policy" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""",
            evidenceArchives=self.parse_evidences(
                [
                    self.mount_default_evidence(nuclei_reference),
                ]
            ),
            nucleiReference=nuclei_reference,
        )

    def report_599(self, nuclei_reference):
        if self.is_english is True:
            return NotificationReport(
                projectId=self.project_id,
                vulnerabilityTemplateId=685,
                description=f"""The application <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> does not have the response header "Strict-Transport-Security" as shown in evidence. This can be validated by making a request to the application quoted above and observing its response.""",
                evidenceArchives=self.parse_evidences(
                    [
                        self.mount_default_evidence(nuclei_reference),
                    ]
                ),
                nucleiReference=nuclei_reference,
            )
        return NotificationReport(
            projectId=self.project_id,
            vulnerabilityTemplateId=599,
            description=f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "Strict-Transport-Security" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""",
            evidenceArchives=self.parse_evidences(
                [
                    self.mount_default_evidence(nuclei_reference),
                ]
            ),
            nucleiReference=nuclei_reference,
        )

    def report_596(self, nuclei_reference):
        if self.is_english is True:
            return NotificationReport(
                projectId=self.project_id,
                vulnerabilityTemplateId=759,
                description=f"""The application <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> does not have the response header "X-Frame-Options" as shown in evidence. This can be validated by making a request to the application quoted above and observing its response.""",
                evidenceArchives=self.parse_evidences(
                    [
                        self.mount_default_evidence(nuclei_reference),
                    ]
                ),
                nucleiReference=nuclei_reference,
            )

        return NotificationReport(
            projectId=self.project_id,
            vulnerabilityTemplateId=596,
            description=f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "X-Frame-Options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""",
            evidenceArchives=self.parse_evidences(
                [
                    self.mount_default_evidence(nuclei_reference),
                ]
            ),
            nucleiReference=nuclei_reference,
        )

    def report_597(self, nuclei_reference):
        if self.is_english is True:
            return NotificationReport(
                projectId=self.project_id,
                vulnerabilityTemplateId=683,
                description=f"""The application <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> does not have the response header "X-Content-Type-Options" as shown in evidence. This can be validated by making a request to the application quoted above and observing its response.""",
                evidenceArchives=self.parse_evidences(
                    [
                        self.mount_default_evidence(nuclei_reference),
                    ]
                ),
                nucleiReference=nuclei_reference,
            )
        return NotificationReport(
            projectId=self.project_id,
            vulnerabilityTemplateId=597,
            description=f"""A aplicação <a href="{nuclei_reference['host']}">{nuclei_reference['host']}</a> não possui o cabeçalho de resposta "x-content-type-options" conforme demonstrado na evidência. Isso pode ser validado fazendo uma requisição à aplicação citada acima e observando sua resposta.""",
            evidenceArchives=self.parse_evidences(
                [
                    self.mount_default_evidence(nuclei_reference),
                ]
            ),
            nucleiReference=nuclei_reference,
        )

    def setup_tmp_directory(self):
        if os.path.isdir(self.evidences_tmp_dir):
            rmtree(self.evidences_tmp_dir)
        os.makedirs(self.evidences_tmp_dir, exist_ok=True)

    def generate_token_stamp(self):
        token = datetime.now().timestamp()
        token = base64encode(token)
        token = token.rstrip("=")
        return encode(token, "rot_13")

    def open_token_stamp(self, token):
        token = encode(token, "rot_13")
        token += "="
        return base64decode(token)

    def __close_reader(self, evidenceArchives):
        """Memory leak protection."""
        for evidence in evidenceArchives:
            evidence.close()

    def mount_default_evidence(self, nuclei_reference):
        return f"""
        \r# REQUEST
        \r{nuclei_reference['request']} 
        \r# RESPONSE
        \r{nuclei_reference['response']}
        """

    def mount_binary_evidence(self, evidence_data):
        token = self.generate_token_stamp()
        tmp_filepath = f"""{self.evidences_tmp_dir}/evidence-{get_random_string()}-{token}.txt""".strip()
        tmp_file = open(tmp_filepath, "w")
        created_evidences = []
        if evidence_data:
            evidence_data = evidence_data.strip()
            tmp_file.write(evidence_data)
        tmp_file.close()
        return open(tmp_filepath, "rb")

    def parse_evidences(self, evidences=list):
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
            mounted_evidence = self.mount_binary_evidence(evidences)
            parsed_evidences.append(mounted_evidence)
        return parsed_evidences

    def get_reference_by_matcher_name(self, nuclei_item):
        for ref in self.reference_reports:
            if ref["matcher-name"] == nuclei_item["matcher-name"]:
                return ref

    def get_reference_report(self, nuclei_item):
        reference = None
        reference = self.get_reference_by_matcher_name(nuclei_item)
        return reference

    def parse_reports(self, nuclei_scan_results):
        """Generate Conviso Platform reports by parsing nuclei results and crossing with preconfigured reports.

        Args:
            nuclei_scan_results (list<dict>): nuclei scan results

        Returns:
            list<dict>: parsed Conviso Platform reports
        """
        parsed_reports = []
        for nuclei_item in nuclei_scan_results:
            reference = self.get_reference_report(nuclei_item)
            if bool(reference):
                report = reference.get("parser")(nuclei_item)
                parsed_reports.append(report)
                logging.debug(
                    f"""[DBG] Generated report: {report.gqlReference} - {report.vulnerabilityTemplateId} - {report.nucleiReference["host"]} - {report.nucleiReference["matcher-name"]}"""
                )
        return parsed_reports

    def create_nuclei_reports(self, nuclei_scan_results = []):
        """Consume the nuclei results and create a report for each one that exists preconfigured.

        Returns:
            list<NotificationReport|WebVulnerabilityReport|OtherVulnerabilityReport>: see src/lib/ReportService.py for further details.
        """
        self.reports = self.parse_reports(nuclei_scan_results)
        print(f"[INF] Generated reports from Nuclei scan output: {len(self.reports)} ")
        return self.reports
