#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MIT License
#
# Copyright (c) 2021 Conviso AppSec Labs < https://github.com@convisolabs >
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.


import os
from datetime import datetime
from shutil import rmtree

import base65536

UTF8 = 'utf-8'


class ParserInterface:
    def __init__(self, project_id):
        self.__project_id = project_id
        self.evidence_service = EvidenceService()

    def create_mutation_body(self, nuclei_item, template_id, description):
        return {
            "vulnerabilityTemplateId": template_id,
            "description": description,
            "project_id": self.__project_id,
            "evidenceArchives":  self.evidence_service.mount_binary_file(nuclei_item)
        }


class EvidenceService:
    def __init__(self):
        self.base_dir = './tmp'
        self.__create_tmp_dir()
        # self.nuclei_output = nuclei_output
        # self.evidence_content = self.__mount_binary_file(self.nuclei_output)

    def __create_tmp_dir(self):
        if os.path.isdir(self.base_dir):
            rmtree(self.base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def mount_binary_file(self, nuclei_output, lines):
        token = self.__generate_token_stamp()
        tmp_filepath = "{}/evidence-{}.txt".format(self.base_dir, token)

        f = open(tmp_filepath, "w")
        if not lines:
            lines=[
            "#\n# REQUEST DONE\n#\n",
            nuclei_output['request'],
            " \n\n",
            "#\n# RESPONSE RECEIVED \n#\n",
            nuclei_output['response'],
            " \n\n",
            ]
        f.writelines(lines)
        f.close()
        return open(tmp_filepath, 'rb')

    def __generate_token_stamp(self):
        _timestamp = str(datetime.now().timestamp())
        first_layer = base65536.encode(_timestamp.encode(UTF8))
        second_layer = first_layer.encode(UTF8)
        third_layer = second_layer.hex()
        return third_layer


def open_token_stamp(token_stamp):
    undo_third_layer = bytes.fromhex(token_stamp)
    undo_second_layer = undo_third_layer.decode(UTF8)
    undo_first_layer = base65536.decode(undo_second_layer)
    return undo_first_layer
