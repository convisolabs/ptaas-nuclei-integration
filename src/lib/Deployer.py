
from gql.transport.aiohttp import AIOHTTPTransport
from gql import Client, gql
from util import progressBar as animation


class ReportDeployer:

    def __init__(self, api_key):

        self.client = Client(
            transport=AIOHTTPTransport(
                url='https://app.conviso.com.br/graphql',
                headers={
                    'x-api-key': api_key
                }
            )
        )

    def create_notification(self, reports):
        i = 0
        print('')
        print('Starting notification creation process in AppSecFlow', end="\n")
        for input in reports:
            input['project_id'] = int(input['project_id'])

            query = gql('''
                mutation($evidenceArchives: [Upload!]!, $vulnerabilityTemplateId: Int!, $description: String!, $project_id: Int!) {
                    createNotification(input: {
                        evidenceArchives: $evidenceArchives
                        vulnerabilityTemplateId: $vulnerabilityTemplateId
                        projectId: $project_id
                        description: $description
                        }){
                        clientMutationId
                        errors
                        notification{
                            description
                        }
                    }
                }
                ''')

            try:
                result = self.client.execute(
                    query, variable_values=input, upload_files=True
                )
                animation.progressBar(
                    int(i * 100 / len(reports)),
                    int((i + 1) * 100 / len(reports))
                )

                i += 1
            except Exception as e:
                print(str(e))
            finally:
                self.__close_reader(input['evidenceArchives'])

    def __close_reader(self, evidenceArchives):
        for evidence in evidenceArchives:
            evidence.close()
