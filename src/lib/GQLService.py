#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.


import logging
from urllib.parse import quote as encode_url

from dotenv import dotenv_values
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport

__ENV__ = dotenv_values()

CLIENT_MUTATION_ID = "ptani-65b42cf9-8e21-5c31-8d8e-1596c806c83b"

class GQLInterface:
    """Handler to interate with Conviso GraphQL API"""

    def __init__(self, api_key, project_id, environment="production"):
        self.gql_queries_map = {
            "allocatedProjects": """ query allocatedProjects { allocatedProjects(page: 0) { collection { id companyId pid} } } """,
            "createNotification": """ mutation createNotification( $projectId: Int! $vulnerabilityTemplateId: Int! $description: String! $evidenceArchives: [Upload!]! ) { createNotification( input: { clientMutationId: {clientMutationId} projectId: $projectId vulnerabilityTemplateId: $vulnerabilityTemplateId description: $description evidenceArchives: $evidenceArchives } ) { clientMutationId errors notification { description } } } """.format(clientMutationId=CLIENT_MUTATION_ID),
            "createWebVulnerability": """ mutation createWebVulnerability( $projectId: Int! $vulnerabilityTemplateId: Int! $impact: String! $probability: String! $description: String! $impactResume: String! $webProtocol: String! $webMethod: String! $webUrl: String! $webParameters: String! $webSteps: String! $webRequest: String! $webResponse: String! $evidenceArchives: [Upload!]! ) { createWebVulnerability( input: { clientMutationId: {clientMutationId} projectId: $projectId vulnerabilityTemplateId: $vulnerabilityTemplateId impact: $impact probability: $probability description: $description impactResume: $impactResume webProtocol: $webProtocol webMethod: $webMethod webUrl: $webUrl webParameters: $webParameters webSteps: $webSteps webRequest: $webRequest webResponse: $webResponse evidenceArchives: $evidenceArchives invaded: false } ) { clientMutationId errors vulnerability { id vid title } } } """.format(clientMutationId=CLIENT_MUTATION_ID),
        }
        self.api_key = api_key
        self.project_id = project_id
        self.environment = environment
        self.gql_client = Client(
            transport=AIOHTTPTransport(
                url=self.__get_graphql_endpoint(),
                headers={"x-api-key": self.api_key},
            )
        )
        self.project_url = self.get_project_url()

    def get_project_url(self):
        try:
            gql_response = self.execute_query("allocatedProjects")
            projects = gql_response.get("allocatedProjects")
            projects = projects.get("collection")
            if not projects:
                raise Exception("No projects found.")
            for project in projects:
                found_current_project = self.project_id == project.get("id")
                if found_current_project:
                    base_url = self.gql_client.transport.url.replace(
                        "/graphql", "")
                    url = encode_url(f"""{base_url}/scopes/{project.get('companyId')}/vulnerabilities_dashboard?q[project_id_eq]={project.get("id")}""")
                    logging.debug(
                        f"[DBG] Connection established with project: {url}")
                    return url
            else:
                msg = f"[ERR] Project '{self.project_id}' not found."
                logging.error(msg)
                raise msg

        except BaseException as err:
            msg = f"[ERR] Something wrong in #get_project_url: {err}"
            logging.error(msg)
            raise msg

    def __get_graphql_endpoint(self):
        if self.environment == "homologation":
            return "https://homologa.conviso.com.br/graphql"

        if bool(__ENV__.get("CONVISO_PLATFORM_GRAPHQL_API")):
            return __ENV__.get("CONVISO_PLATFORM_GRAPHQL_API")

        return "https://app.conviso.com.br/graphql"

    def execute_query(self, query_reference):
        query = self.gql_queries_map.get(query_reference)
        if not query:
            msg = f"Query '{query_reference}' not found."
            logging.error(msg)
            raise Exception(msg)
        return self.gql_client.execute(gql(query))

    def from_reference_mount_gql_query(self, gqlReference):
        return gql(self.gql_queries_map.get(gqlReference))

    def from_reference_mount_gql_variables(self, report):
        if report.gqlReference == "createNotification":
            return {
                "projectId": report.projectId,
                "vulnerabilityTemplateId": report.vulnerabilityTemplateId,
                "description": report.description,
                "evidenceArchives": report.evidenceArchives,
                "nucleiReference": report.nucleiReference,
            }

        elif report.gqlReference == "createWebVulnerability":
            return {
                "projectId": report.projectId,
                "vulnerabilityTemplateId": report.vulnerabilityTemplateId,
                "impact": report.impact,
                "probability": report.probability,
                "description": report.description,
                "impactResume": report.impactResume,
                "webProtocol": report.webProtocol,
                "webMethod": report.webMethod,
                "webUrl": report.webUrl,
                "webParameters": report.webParameters,
                "webSteps": report.webSteps,
                "webRequest": report.webRequest,
                "webResponse": report.webResponse,
                "evidenceArchives": report.evidenceArchives,
            }

        raise BaseException("GQL Reference not found.")

    def deploy_report(self, report):
        """Creates the specified report on the project provided using the Graphql API

        Args:
            report (NotificationReport): Report object to be deployed on Conviso Platform

        Returns:
            gql_respoinse (dict): Response from Conviso GraphQL API
        """
        try:
            logging.debug(
                f"""[DBG] Deploying report: {report.gqlReference} - {report.vulnerabilityTemplateId} - {report.nucleiReference["host"]} - {report.nucleiReference["matcher-name"]}"""
            )
            query = self.from_reference_mount_gql_query(report.gqlReference)
            vars = self.from_reference_mount_gql_variables(report)
            return self.gql_client.execute(
                query,
                variable_values=vars,
                upload_files=True,
            )
        except BaseException as err:
            logging.debug(
                f"""[ERR] Error deploying report: {report.gqlReference} - {report.vulnerabilityTemplateId} - {report.nucleiReference["host"]} - {report.nucleiReference["matcher-name"]} - {err}"""
            )
            raise err

    def deploy_reports(self, reports):
        if not len(reports):
            logging.error("[DBG] No reports to deploy.")
            return

        i = 0
        for report in reports:
            response = self.deploy_report(report)
            logging.info(f"[DBG] Report deployed: {response}")
            i += 1

        print(
            f"""[INF] {i} Reports deployed! Review them in Conviso Platform: \"{self.project_url}\""""
        )
