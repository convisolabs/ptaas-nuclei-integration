#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

"""
Automated identification and issuance of vulnerability reports to Conviso Platform using nuclei as scanner engine.

https://github.com@convisolabs/ptaas-nuclei-integration/blob/master/README.md
"""


from lib import ArgumentParser, ConvisoNucleiIntegration


def main():
    integration_interface = ConvisoNucleiIntegration.IntegrationInterface(
        ArgumentParser.get_arguments()
    )

    integration_interface.report_service.create_nuclei_reports(
        integration_interface.nuclei_scan_results
    )

    integration_interface.gql_service.deploy_reports(
        integration_interface.report_service.reports
    )
    pass


if __name__ == "__main__":
    main()
