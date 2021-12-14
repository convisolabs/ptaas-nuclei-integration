import random
import string


class FlowNotificationBodyParser:
    def __init__(self):
        self.create_file = CreateFile()

    def create_body(self, nuclei_output, template_id, project_id, description):
        return {
            "vulnerabilityTemplateId": template_id,
            "description": description,
            "project_id": project_id,
            "evidenceArchives":  self.create_file.get_file_binary(nuclei_output)
        }
        
        
class CreateFile:
    def __init__(self):
        pass

    def get_file_binary(self, nuclei_output):
        hash = self.__generate_hash()
        f = open("./evidences/evidence-{}.txt".format(hash), "w")
        req = nuclei_output['request']
        res = nuclei_output['response']
        f.write('REQUEST\n\n')
        f.write(req)
        f.write('RESPONSE\n\n')
        f.write(res)
        f.close()

        return [open("./evidences/evidence-{}.txt".format(hash), 'rb')]

    def __generate_hash(self):
        characters = string.ascii_letters + string.digits
        return ''.join(random.sample(characters, 16))