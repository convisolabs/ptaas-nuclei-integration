#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

"""
Automated identification and issuance of vulnerability reports to Conviso Platform using nuclei as scanner.

https://github.com@convisolabs/ptaas-nuclei-integration/blob/master/README.md
"""


from lib import ArgumentParser
from lib import ConvisoNucleiIntegration
from lib import Deployer 

def main():
    # 1 read nuclei scan output
    integrationInterface = ConvisoNucleiIntegration.IntegrationInterface(
        __arguments__.nuclei_output,
        __arguments__.project_id
    )
  
    # 2 create reports
    integrationInterface.conviso_reports = integrationInterface.get_conviso_reports()

    # 3 deploy to flow
    deployer = Deployer.ReportDeployer( __arguments__.api_key)
    deployer.create_notification(integrationInterface.conviso_reports)
    # print(integrationInterface.conviso_reports)
    # deploy_report_in_batch(conviso_reports)


if __name__ == "__main__":
    __arguments__ = ArgumentParser.get_arguments()
    main()
