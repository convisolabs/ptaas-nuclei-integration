#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import json
import logging

from lib import GQLService, ReportService


class IntegrationInterface:
    """Handler to Nuclei and Conviso Platform integration."""

    def __init__(self, args):
        """
        Args:
            args (OrganizedDict):
            args.project_id (str): Conviso Platform project ID
            args.api_key (str): Conviso Platform apikey
            args.nuclei_output (_io.TextIOWrapper): Nuclei scan result from STDIN ou file (CLI parameter)
        """
        logging.basicConfig(
            filename="ptani.log",
            filemode="w",
            encoding="utf-8",
            level=args.log_level,
            format="%(created)s:%(levelname)s:%(module)s:%(pathname)s:%(lineno)s:%(message)s",
        )
        self.__args = args
        self.nuclei_scan_results = self.__parse_nuclei_json(self.__args.nuclei_output)
        self.report_service = ReportService.ReportInterface(self.__args.project_id, self.__args.is_english)
        self.gql_service = GQLService.GQLInterface(
            self.__args.api_key, self.__args.project_id, self.__args.api_environment
        )

    def __parse_nuclei_json(self, file):
        """Make nuclei output compatible with the ISO accepted in JSON by python.

        Args:
            file (_io.TextIOWrapper) : nuclei file readed from argument parser.

        Returns:
            list<dict>: a list of dictionaries with the Nuclei results.
        """
        if not file:
            raise Exception("Nuclei test output was not found. Check uasge in --help.")
        file_content = file.read().strip()
        file_content = file_content.replace("}\n{", "},\n{")
        return json.loads("[" + file_content + "]")
