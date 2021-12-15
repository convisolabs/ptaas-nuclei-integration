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


from dotenv import dotenv_values
from lib import ArgumentParser, ConvisoNucleiIntegration, Deployer


def main():
    __arguments__ = ArgumentParser.get_arguments()
    
    _integrationInterface = ConvisoNucleiIntegration.IntegrationInterface(
        __arguments__.nuclei_output,
        __arguments__.project_id
    )

    conviso_reports = _integrationInterface.get_conviso_reports()
    print('[INFO] Found {} reports to deploy. '.format(len(conviso_reports)))
    deployer = Deployer.ReportDeployer(__arguments__.api_key)
    # deployer.create_flow_notifications(conviso_reports)
    
    pass


if __name__ == "__main__":
    main()
