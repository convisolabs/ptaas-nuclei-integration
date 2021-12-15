
from gql.transport.aiohttp import AIOHTTPTransport
from gql import Client, gql
from util import progressBar as animation

QUERIES_MAP = {
    "createNotification": ''' mutation($evidenceArchives: [Upload!]!, $vulnerabilityTemplateId: Int!, $description: String!, $project_id: Int!) {
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
            } '''
}


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

    def create_flow_notifications(self, reports):
        print('[INFO] Deploying reports...')

        i = 0
        for report in reports:
            report['project_id'] = int(report['project_id'])

            query = gql(QUERIES_MAP['createNotification'])

            try:
                result = self.client.execute(
                    query, variable_values=report, upload_files=True)
                print('')
                animation.progressBar(
                    int(i * 100 / len(reports)), 
                    int((i + 1) * 100 / len(reports)))
                i += 1
            except Exception as e:
                print(str(e))
            # finally:
            #     self.__close_reader(input['evidenceArchives'])

    def __close_reader(self, evidenceArchives):
        for evidence in evidenceArchives:
            evidence.close()
