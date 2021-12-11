#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# MIT License
# 
# Copyright (c) 2021 Conviso AppSec Labs
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

from os import error
import json


class NucleiParser:

    def __init__(self, arg_nuclei_json_file):
        self.json_dict = self.get_nuclei_json_dict(arg_nuclei_json_file)

    def get_nuclei_json_dict(self, file):
        """Read the nuclei output file.

        Returns:
            list: Returns the contention of the file on the JSON list.
        """
        file_content = file.read().strip()
        file_content = file_content.replace('}\n{', '},\n{')
        return json.loads('[' + file_content + ']')

    def create_reports(self):
        """ Creates a new JSON from Nuclei JSON, crossing with templates to create each reporting. 
        """
        # for each key, search for the value in the
        for item in self.json_dict:
            print(item['matcher-name'])
        pass

    def create_local_cache(self):
        """ Saves the data that will go to the AppSecFlow on the computer, for case any error.
        Each generated report has your hash created from your content.
        """
        pass
