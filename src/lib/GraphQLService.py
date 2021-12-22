#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.


from dotenv import dotenv_values
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport

from lib.utils import progressBar as animation

__env__ = dotenv_values()


class Interface:
    """ used to handle the interaction with Conviso GraphQL API """

    def __init__(self, arg_api_key):
        self.__api_key = arg_api_key
        self.__gql_client = Client(
            transport=AIOHTTPTransport(
                url=self.__get_graphql_endpoint(),
                headers={
                    'x-api-key': self.__get_flow_apikey()
                }
            )
        )
        self.__gql_queries_map = {
            "test_connectivity": """ query { allocatedProjects(page: 0) { collection { id } } } """,
            "create_vulnerability": """  """,
            "create_notification": '''mutation($evidenceArchives: [Upload!]!, $vulnerabilityTemplateId: Int!, $description: String!, $project_id: Int!) {
                createNotification(input: {
                    evidenceArchives: $evidenceArchives
                    vulnerabilityTemplateId: $vulnerabilityTemplateId
                    projectId: $project_id
                    description: $description
                    }){
                    clientMutationId
                    errors
                    notification{
                        description
                    }
                }
            }'''
        }
        self.__test_connectivity()

    def __get_flow_apikey(self):

        env_apikey = __env__['APPSECFLOW_APIKEY']
        if bool(env_apikey):
            return env_apikey
        if self.__api_key:
            return self.__api_key
        raise('[ERR] Missing API key: check --help or use .env file.')

    def __get_graphql_endpoint(self):
        if bool(__env__.get('APPSECFLOW_GRAPHQL_API')) is True:
            return __env__.get('APPSECFLOW_GRAPHQL_API')
        return 'https://app.conviso.com.br/graphql'

    def __test_connectivity(self):
        try:
            query = gql(self.__gql_queries_map['test_connectivity'])
            result = self.__gql_client.execute(query)
        except Exception as er:
            print("[ERR] Don't get connectivity with GraphQL ")
            raise (str(er))
        finally:
            pass

    def __close_reader(self, evidenceArchives):
        """ Memory leak protection. """
        for evidence in evidenceArchives:
            evidence.close()

    def create_flow_notifications(self, reports):
        i = 0
        for report in reports:
            report['project_id'] = int(report['project_id'])

            query = gql(self.__gql_queries_map['create_notification'])

            try:
                result = self.__gql_client.execute(
                    query, variable_values=report, upload_files=True)
                animation.progressBar(
                    int(i * 100 / len(reports)),
                    int((i + 1) * 100 / len(reports)))
                i += 1
            except Exception as err:
                print('[ERR] Error on create_notification')
                raise (str(err))
            finally:
                report_buffer = report['evidenceArchives']
                # if not report['evidenceArchives'].closed():
                #     self.__close_reader(report['evidenceArchives'])
