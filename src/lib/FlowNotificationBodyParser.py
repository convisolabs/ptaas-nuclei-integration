from base64 import b16encode
import base65536
import os
from datetime import datetime
from shutil import rmtree
UTF8 = 'utf-8'


class FlowNotificationBodyParser:
    def __init__(self, project_id):
        self.project_id = project_id
        self.create_file = CreateFile()

    def create_mutation_body(self, nuclei_item, template_id, description):
        return {
            "vulnerabilityTemplateId": template_id,
            "description": description,
            "project_id": self.project_id,
            "evidenceArchives":  self.create_file.mount_binary_file(nuclei_item)
        }


class CreateFile:
    def __init__(self):
        self.base_dir = './tmp'
        if os.path.isdir(self.base_dir):
            rmtree(self.base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def mount_binary_file(self, nuclei_output):
        token = self.__generate_token_stamp()
        tmp_filepath = "{}/evidence-{}.txt".format(self.base_dir, token)

        f = open(tmp_filepath, "w")
        f.writelines([
            "#\n# REQUEST \n#\n",
            nuclei_output['request'],
            " \n\n",
            "#\n# RESPONSE \n#\n",
            nuclei_output['response'],
            " \n\n",
        ])
        f.close()
        return  open(tmp_filepath, 'rb')

    def __generate_token_stamp(self):
        _timestamp = str(datetime.now().timestamp())
        first_layer = base65536.encode(_timestamp.encode(UTF8))
        second_layer = first_layer.encode(UTF8)
        third_layer = second_layer.hex()
        return third_layer

    def __open_token_stamp(token_stamp):
        undo_third_layer = bytes.fromhex(token_stamp)
        undo_second_layer = undo_third_layer.decode(UTF8)
        undo_first_layer = base65536.decode(undo_second_layer)
        return undo_first_layer
