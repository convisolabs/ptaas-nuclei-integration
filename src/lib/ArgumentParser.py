#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import argparse
import sys
from textwrap import dedent

from dotenv import dotenv_values

__version__ = "1.0.0"
__ENV__ = dotenv_values()


def __get_default_from_env():
    api_key = __ENV__.get("CONVISO_PLATFORM_APIKEY")
    if api_key:
        return api_key
    return None


def get_arguments():
    """Provides an interface to control the tool, parsing command line strings into Python objects."""
    parser = argparse.ArgumentParser(
        prog="ptani",
        description=f"""ptaas-nuclei-integration@v{__version__} - MIT © Conviso 2021""",
        prefix_chars="-",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\r\nUage examples: 
        \r\t$ nuclei -irr -json -u https://www.target.com -t ~/nuclei-templates/misconfiguration/http-missing-security-headers.yaml | python -pid 2747 -apk $CONVISO_APIKEY 
        \r\t$ nuclei -irr -json -l /tmp/targets.txt -t ./src/templates/http-missing-security-headers.yaml | python -pid 2747 -apk $CONVISO_APIKEY -hml
        \r\t$ python -pid 2747 -apk $CONVISO_APIKEY -no ./nuclei-output.json 
        """
        ),
    )
    parser.add_argument(
        "-L",
        "--log-level",
        help="Make it verbose, useful for debugging.",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    parser.add_argument(
        "-apk",
        "--api-key",
        help="Your apikey generated in Conviso Platform.",
        type=str,
        # todo: preferir o argumento -apk, fallback na .env
        default=__get_default_from_env(),
        required=True,
    )
    parser.add_argument(
        "-pid",
        "--project-id",
        help="Project ID in Conviso Platform.",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-no",
        "--nuclei-output",
        help="Nuclei test result file path.",
        type=argparse.FileType("r"),
        default=(None if sys.stdin.isatty() else sys.stdin),
        required=True,
    )
    parser.add_argument(
        "-hml",
        "--homologation",
        help="Use API in homologation enviroment. Useful for testing in development.",
        action="store_const",
        const="homologation",
        dest="api_environment",
    )
    return parser.parse_args()
