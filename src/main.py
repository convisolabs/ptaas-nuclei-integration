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


from src.lib import ArgumentParser
from src.lib import NucleiIntegration


def main():
    if ArgumentParser.arguments_verification(__arguments__):
        pass

    parserController = NucleiIntegration.NucleiParser(
        __arguments__.nuclei_json
    )

    appsecflow_reports = parserController.create_reports()


if __name__ == "__main__":
    __arguments__ = ArgumentParser.get_arguments()
    main()
