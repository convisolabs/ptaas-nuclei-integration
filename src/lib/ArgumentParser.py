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
from datetime import datetime
from textwrap import dedent

from dotenv import dotenv_values

__VERSION__ = "gamma"
__PROJECT_URL__ = "https://github.com/convisolabs/ptaas-nuclei-integration"
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
        description=f"""ptaas-nuclei-integration@v:{__VERSION__} -- MIT © Conviso 2021-{datetime.now().year} -- {__PROJECT_URL__}""",
        prefix_chars="-",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\r\nUsage examples: 
        \r\tFrom pipe: $ nuclei -irr -json -u https://www.target.com -t ~/nuclei-templates/misconfiguration/http-missing-security-headers.yaml | python -pid $PID -apk $CONVISO_APIKEY -no -
        \r\tFrom file: $ python3 -pid $PID -apk $CONVISO_APIKEY -no ./nuclei-output.json 
        \r\nObservation: Nuclei parameters \"-json\" and \"-irr\" are required for script operation.
        \r\n
        """
        ),
    )
    parser.add_argument(
        "-apk",
        "--api-key",
        help="Your apikey generated in Conviso Platform",
        type=str,
        default=__get_default_from_env(),
        required=True,
    )
    parser.add_argument(
        "-pid",
        "--project-id",
        help="Project ID in Conviso Platform",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-no",
        "--nuclei-output",
        help="Nuclei test result file path. Input from pipe/STDIN use \"-\". i.e., --nuclei-output -",
        type=argparse.FileType("r"),
        default=(None if sys.stdin.isatty() else sys.stdin),
    )
    parser.add_argument(
        "-eng",
        "--english",
        help="Issue reports in English",
        action="store_const",
        dest="is_english",
        const=True,
    )
    parser.add_argument(
        "-hml",
        "--homologation",
        help="Use API in homologation enviroment. Useful for testing and development",
        action="store_const",
        dest="api_environment",
        const="homologation",
    )
    parser.add_argument(
        "-L",
        "--log-level",
        help="Log the occurred actions. Useful for debugging. Check \"ptani.log\" file",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="DEBUG",
    )
    parser.add_argument(
        "-S",
        "--script",
        help="Script path to be executed. Example: <URL>",
        type=str,
    )
    return parser.parse_args()
