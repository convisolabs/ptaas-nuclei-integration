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


from lib import ArgumentParser, FlowNucleiIntegration, GraphQLService


def main():
    __arguments__ = ArgumentParser.get_arguments()

    _integrationInterface = FlowNucleiIntegration.IntegrationInterface(
        __arguments__.nuclei_output,
        __arguments__.project_id
    )

    conviso_reports = _integrationInterface.get_conviso_reports()
    print('[INF] Generated {} reports from Nuclei test output'.format(
        len(conviso_reports))
    )

    gqlService = GraphQLService.Interface(__arguments__.api_key)
    gqlService.create_flow_notifications(conviso_reports)

    print('[INF] Done! Review your reports in https://app.conviso.com.br')
    pass


if __name__ == "__main__":
    main()
