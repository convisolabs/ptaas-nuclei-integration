#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.


from shutil import Error
from dotenv import dotenv_values
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport

__ENV__ = dotenv_values()


class GQLInterface:
    """Handler to interate with Conviso GraphQL API"""

    def __init__(self, api_key, project_id, environment="production"):
        self.gql_queries_map = {
            "allocatedProjects": """ query { allocatedProjects(page: 0) { collection { id companyId pid} } } """,
            "notification": """mutation createNotification ($evidenceArchives: [Upload!]!, $vulnerabilityTemplateId: Int!, $description: String!, $project_id: Int!) { createNotification(input: { evidenceArchives: $evidenceArchives vulnerabilityTemplateId: $vulnerabilityTemplateId projectId: $project_id description: $description }){ clientMutationId errors notification{ description } } }""",
            "vulnerability": """mutation createVulnerability """,
        }
        self.api_key = api_key
        self.project_id = project_id
        self.environment = environment
        self.__gql_client = Client(
            transport=AIOHTTPTransport(
                url=self.__get_graphql_endpoint(),
                headers={"x-api-key": self.api_key},
            )
        )
        self.project_url = self.__get_project_url()

    def __get_project_url(self):
        try:
            gql_response = self.execute_query("allocatedProjects")
            projects = gql_response.get("allocatedProjects").get("collection")
            if not projects:
                raise Exception("No projects found.")
            for project in projects:
                is_current_project = self.project_id == project.get("id")
                if is_current_project:
                    print("[DBG] Connection established!")
                    base_url = self.__gql_client.transport.url.replace("/graphql", "")
                    return f"""{base_url}/scopes/{project.get('companyId')}/vulnerabilities_dashboard?q[project_id_eq]={project.get("id")}"""
            else:
                raise Error(f"[ERR] Project '{self.project_id}' not found.")

        except BaseException as err:
            print(f"[ERR] Something wrong in #__get_project_url.")
            raise err

    def __get_graphql_endpoint(self):
        if self.environment == "homologation":
            return "https://homologa.conviso.com.br/graphql"

        if bool(__ENV__.get("CONVISO_PLATFORM_GRAPHQL_API")):
            return __ENV__.get("CONVISO_PLATFORM_GRAPHQL_API")

        return "https://app.conviso.com.br/graphql"

    def execute_query(self, query_reference):
        query = self.gql_queries_map.get(query_reference)
        if not query:
            raise Exception(f"Query '{query_reference}' not found.")
        return self.__gql_client.execute(gql(query))

    def __get_gql_query_from_reference(self, gql_reference):
        return gql(self.gql_queries_map.get(gql_reference))

    def __deploy_report(self, report):
        """Creates the specified report on the project provided using the Graphql API

        Args:
            report (NotificationReport): Report object to be deployed on Conviso Platform

        Returns:
            gql_respoinse (dict): Response from Conviso GraphQL API
        """
        try:
            print(
                f"""[DBG] Deploying report: {report.gql_reference} - {report.vulnerabilityTemplateId} - {report.nucleiReference["host"]} - {report.nucleiReference["matcher-name"]}"""
            )
            gql_query = self.__get_gql_query_from_reference(report.gql_reference)
            # gql_response = self.__gql_client.execute( gql_query, variable_values=report, upload_files=True)
            # return gql_response
            return {}
        except BaseException as err:
            print(
                f"""[ERR] Error deploying report: {report.gql_reference} - {report.vulnerabilityTemplateId} - {report.nucleiReference["host"]} - {report.nucleiReference["matcher-name"]}"""
            )
            raise err

        finally:
            pass
            # report_buffer = report["evidenceArchives"]
            # if not report['evidenceArchives'].closed():
            #     self.__close_reader(report['evidenceArchives'])

    def deploy_reports(self, reports):
        i = 0
        for report in reports:
            self.__deploy_report(report)
            i += 1
