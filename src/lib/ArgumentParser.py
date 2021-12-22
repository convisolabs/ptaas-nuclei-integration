#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import argparse
import sys

from dotenv import dotenv_values

__version__ = "1.0.1"


def get_arguments():
    """Interface to parsing command line strings into Python objects.
    """

    __env__ = dotenv_values()

    parser = argparse.ArgumentParser(
        prog="ptani",
        description='ptaas-nuclei-integration@v{} - MIT © Conviso 2021' .format(
            __version__),
        prefix_chars='-',
    )
    parser.add_argument(
        '-apk', '--api-key',
        help="Api Key in APPSecFlow.",
        type=str,
        required=False,
        default=['APPSECFLOW_APIKEY']
    )
    parser.add_argument(
        '-pid', '--project-id',
        help="Project ID in APPSecFlow.",
        type=str,
        required=True,
    )
    parser.add_argument(
        '-no', '--nuclei-output',
        help="Nuclei test result file path.",
        type=argparse.FileType('r'),
        default=(None if sys.stdin.isatty() else sys.stdin)
    )
    return parser.parse_args()
