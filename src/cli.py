#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

""" Interface to programmatic automate your reports with this tool. """

from collections import OrderedDict
from lib import ConvisoNucleiIntegration

integration_interface = ConvisoNucleiIntegration.IntegrationInterface(OrderedDict({
  "project_id": "<CHANGE>",
  "api_key": "<CHANGE>",
}))
