import copy
import datetime
import json
from os import path
import requests
import time
from urllib.parse import urljoin


class HealtCheck:
    def __init__(self, user_info=path.expanduser('~/.config/datahub/config.json'),
                        base_url='https://api.datahub.io'):
        self.base_url = base_url
        self.user_info = user_info
        if isinstance(user_info, str):
            self.user_info = json.loads(open(user_info).read())
        self.jwt = self.user_info.get('token')
        self.owner_id = self.user_info['profile'].get('id')
        self.email = self.user_info['profile'].get('email')
        self.username = self.user_info['profile'].get('username')
        self.now = datetime.datetime.now()
        self.today = datetime.datetime(self.now.year, self.now.month, self.now.day)
        self.health_report = {}

    @staticmethod
    def check_status(resp, report_name, status=200):
        success = resp.status_code == status
        report = {
            'success': success,
            'errors': 'Unexpected status code: Expected %s, but Recieved %s' % (
                                    status, resp.status_code) if not success else None,
            'name': report_name
        }
        return report

    @staticmethod
    def check_body(body, key, exp_value, report_name):
        success = body.get(key) == exp_value
        report = {
            'success': success,
            'errors': 'Unexpected key/value in body: Expected {%s:%s}, but Recieved {%s:%s}' % (
                    key, exp_value, key, body.get(key)) if not success else None,
            'name': report_name
        }
        return report

    @staticmethod
    def check_message(actual_error, expected_error, report_name):
        success = actual_error == expected_error
        report = {
            'success': success,
            'errors': 'Unexpected error message: Expected "%s", but Recieved "%s"' % (
                    expected_error, actual_error) if not success else None,
            'name': report_name
        }
        return report

    @staticmethod
    def check_numbers(low_number, high_number, report_name, equal=False):
        success = low_number < high_number
        condition = 'greather than'
        if equal:
            success = low_number == high_number
            condition = 'equal to'
        report = {
            'success': success,
            'errors': 'Expected %s %s, but Received %s' % (
                            condition, low_number, high_number) if not success else None,
            'name': report_name
        }
        return report

    def check_health(self):
        print('This may take a while, please wait')
        print('Scanning Auth Service...')
        self.check_auth()
        print('Scanning Rawstore Service...')
        self.check_bitstore()
        print('Scanning Flow Manager Service...')
        self.check_flowmanager()
        print('Scanning File Manager Service...')
        self.check_filemanager()
        print('Scanning Metastore Service...')
        self.check_metastore()
        print('Scanning Resolver Service...')
        self.check_resolver()
        print('Scanning Plans Service...')
        self.check_plans()
        print('Scanning Frontend Service...')
        self.check_frontend()
        print('Scan Finished!')

    def alles_good(self):
        successes = []
        for report in self.health_report.values():
            for item in report:
                successes.append(item.get('success'))
        return all(successes)

    def display_report(self):
        for report in self.health_report:
            print(report)
            print('\t|', 'Name\t|', 'Success\t|', 'Error')
            for item in self.health_report[report]:
                if not item.get('success'):
                    print('\t|', '%s\t|' % item.get('name'), '%s\t|' % item.get('success'), '%s' % item.get('errors') or '')


    def check_flowmanager(self, prefix='source', dataset_id='basic-csv', valid_content=None):
        info = {
            'prefix': prefix,
            'owner': self.username,
            'ownerid':self.owner_id,
            'dataset_id': dataset_id,
            'revision': 'latest'
        }
        flowmanager_report = []

        if valid_content is None:
            valid_content = json.loads(open('content.json').read() % info)
        api_url = urljoin(self.base_url, prefix)
        info_endpoint = urljoin(api_url, '{prefix}/{ownerid}/{dataset_id}/{revision}')
        upload_endpoint = urljoin(api_url, '{prefix}/upload'.format(prefix=prefix))

        resp = requests.post(upload_endpoint)
        rep = HealtCheck.check_status(resp, 'Upload without content: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload without content: success is false')
        flowmanager_report.append(rep)
        message = 'Received empty contents (make sure your content-type is correct)'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload without content: error message is correct')
        flowmanager_report.append(rep)

        content = {}
        resp = requests.post(upload_endpoint, json=content)
        rep = HealtCheck.check_status(resp, 'Upload without owner: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload without owner: success is false')
        flowmanager_report.append(rep)
        message = 'Missing owner in spec'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload without owner: error message is correct')
        flowmanager_report.append(rep)

        content = {'meta': {'ownerid': 'non-existing-owner'}}
        resp = requests.post(upload_endpoint, json=content)
        rep = HealtCheck.check_status(resp, 'Upload with invalid owner: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload with invalid owner: success is false')
        flowmanager_report.append(rep)
        message = 'No token or token not authorised for owner'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload with invalid owner: error message is correct')
        flowmanager_report.append(rep)

        content = valid_content
        resp = requests.post(upload_endpoint, json=content)
        rep = HealtCheck.check_status(resp, 'Upload with no JWT: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload with no JWT: success is false')
        flowmanager_report.append(rep)
        message = 'No token or token not authorised for owner'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload with no JWT: error message is correct')
        flowmanager_report.append(rep)

        content = copy.deepcopy(valid_content)
        content['meta']['dataset'] = 'new-basic-csv'
        resp = requests.post(upload_endpoint, json=content, headers={'auth-token': self.get_token('source')})
        rep = HealtCheck.check_status(resp, 'Upload exeeding limits: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload exeeding limits: success is false')
        flowmanager_report.append(rep)
        message = 'Max datasets for user exceeded plan limit (2)'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload exeeding limits: error message is correct')
        flowmanager_report.append(rep)

        content = copy.deepcopy(valid_content)
        content['inputs'][0]['kind'] = 'invalid'
        resp = requests.post(upload_endpoint, json=content, headers={'auth-token': self.get_token('source')})
        rep = HealtCheck.check_status(resp, 'Upload with invalid input: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload with invalid input: success is false')
        flowmanager_report.append(rep)
        message = 'Unexpected error: Only supporting datapackage inputs atm'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload with invalid input: error message is correct')
        flowmanager_report.append(rep)

        content = copy.deepcopy(valid_content)
        content['schedule'] = 'every 1k'
        resp = requests.post(upload_endpoint, json=content, headers={'auth-token': self.get_token('source')})
        rep = HealtCheck.check_status(resp, 'Upload with invalid schedule unit: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload with invalid schedule unit: success is false')
        flowmanager_report.append(rep)
        message = 'Bad time unit for schedule, only s/m/h/d/w are allowed'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload with invalid schedule unit: error message is correct')
        flowmanager_report.append(rep)

        content = copy.deepcopy(valid_content)
        content['schedule'] = 'every 1s'
        resp = requests.post(upload_endpoint, json=content, headers={'auth-token': self.get_token('source')})
        rep = HealtCheck.check_status(resp, 'Upload with invalid schedule time: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Upload with invalid schedule time: success is false')
        flowmanager_report.append(rep)
        message = 'Can\'t schedule tasks for less than one minute'
        rep = HealtCheck.check_message(body.get('errors', [''])[0], message,
                                'Upload with invalid schedule time: error message is correct')
        flowmanager_report.append(rep)

        resp = requests.get(info_endpoint.format(**info))
        rep = HealtCheck.check_status(resp, 'Latest revision: status 200', 200)
        flowmanager_report.append(rep)
        latest_revision = int(resp.json().get('id', '').split('/')[-1])
        content = valid_content
        resp = requests.post(upload_endpoint, json=content, headers={'auth-token': self.get_token('source')})
        rep = HealtCheck.check_status(resp, 'Upload valid data: status 200', 200)
        flowmanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', True, 'Upload valid data: success is true')
        flowmanager_report.append(rep)
        time.sleep(90)

        resp = requests.get(info_endpoint.format(**info))
        new_latest_revision = int(resp.json().get('id', '').split('/')[-1])
        rep = HealtCheck.check_numbers(latest_revision, new_latest_revision, 'New revision processed')
        flowmanager_report.append(rep)

        body = resp.json()
        rep = HealtCheck.check_body(body, 'state', 'SUCCEEDED', 'New revision succeeded')
        flowmanager_report.append(rep)

        info['revision'] = 'successful'
        resp = requests.get(info_endpoint.format(**info))
        successful_revision = int(resp.json().get('id', '').split('/')[-1])
        rep = HealtCheck.check_status(resp, 'New revision succeeded', 200)
        flowmanager_report.append(rep)
        rep = HealtCheck.check_numbers(new_latest_revision, successful_revision, 'Successful and latest revision match', equal=True)
        flowmanager_report.append(rep)

        info['revision'] = str(successful_revision)
        resp = requests.get(info_endpoint.format(**info))
        successful_revision = int(resp.json().get('id', '').split('/')[-1])
        rep = HealtCheck.check_status(resp, 'Able to get with revision number', 200)
        flowmanager_report.append(rep)

        info['revision'] = str(successful_revision + 1)
        resp = requests.get(info_endpoint.format(**info))
        rep = HealtCheck.check_status(resp, 'Get invalid revision number: status 404', 404)
        flowmanager_report.append(rep)

        info['revision'] = 'invalid'
        resp = requests.get(info_endpoint.format(**info))
        rep = HealtCheck.check_status(resp, 'Get invalid revision word: status 404', 404)
        flowmanager_report.append(rep)
        self.health_report['flowmanager_report'] = flowmanager_report

    def check_auth(self, prefix='auth'):
        auth_check = urljoin(self.base_url, path.join(prefix, 'check?jwt={jwt}'))
        auth_authorize = urljoin(self.base_url, path.join(prefix, 'authorize?jwt={jwt}&service={service}' ))
        auth_update = urljoin(self.base_url, path.join(prefix, 'update?jwt={jwt}&username={username}'))
        auth_public_key = urljoin(self.base_url, path.join(prefix, 'public-key' ))
        auth_resolver = urljoin(self.base_url, path.join(prefix, 'resolve?username={username}' ))
        auth_profile = urljoin(self.base_url, path.join(prefix, 'get_profile?username={username}' ))

        auth_report = []

        resp = requests.get(auth_check.format(jwt='wrong'))
        rep = HealtCheck.check_status(resp, 'Auth Check not authenticate: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'authenticated', False, 'Auth check not authenticate: success is false')
        auth_report.append(rep)

        resp = requests.get(auth_check.format(jwt=self.jwt))
        rep = HealtCheck.check_status(resp, 'Auth Check authenticated: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'authenticated', True, 'Auth Check authenticated: success is true')
        auth_report.append(rep)

        resp = requests.get(auth_authorize.format(jwt='wrong', service='service'))
        rep = HealtCheck.check_status(resp, 'Auth authorize invalid jwt: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'permissions', {}, 'Auth authorize invalid jwt: no pemissions')
        auth_report.append(rep)

        resp = requests.get(auth_authorize.format(jwt=self.jwt, service='service'))
        rep = HealtCheck.check_status(resp, 'Auth authorize invalid service: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'permissions', {}, 'Auth authorize invalid service: no pemissions')
        auth_report.append(rep)

        resp = requests.get(auth_authorize.format(jwt=self.jwt, service='source'))
        rep = HealtCheck.check_status(resp, 'Auth authorize success for source: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'permissions', {'max_dataset_num': 2}, 'Auth authorize success: pemissions there')
        auth_report.append(rep)

        resp = requests.get(auth_authorize.format(jwt=self.jwt, service='source'))
        rep = HealtCheck.check_status(resp, 'Auth authorize success for source service: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'permissions', {'max_dataset_num': 2}, 'Auth authorize success for rawstore service: pemissions there')
        auth_report.append(rep)

        resp = requests.get(auth_authorize.format(jwt=self.jwt, service='rawstore'))
        rep = HealtCheck.check_status(resp, 'Auth authorize success for source service: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'permissions', {'max_private_storage_mb': 0, 'max_public_storage_mb': 100}, 'Auth authorize success for rawstore service: pemissions there')
        auth_report.append(rep)

        resp = requests.post(auth_update.format(jwt='invalid', username='tester'))
        rep = HealtCheck.check_status(resp, 'Auth update invalid jwt: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Auth update invalid jwt: success false')
        auth_report.append(rep)
        rep = HealtCheck.check_message(body.get('error', ''), 'Not authenticated', 'Auth update invalid jwt: Error message is incorrect')
        auth_report.append(rep)

        resp = requests.post(auth_update.format(jwt=self.jwt, username='tester'))
        rep = HealtCheck.check_status(resp, 'Auth update valid jwt: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'success', False, 'Auth update valid jwt: success false')
        auth_report.append(rep)
        message = 'Cannot modify username, already set'
        rep = HealtCheck.check_message(body.get('error', ''), message, 'Auth update valid jwt: Error message is incorrect')
        auth_report.append(rep)

        resp = requests.get(auth_public_key)
        rep = HealtCheck.check_status(resp, 'Auth public key: status 200', 200)
        auth_report.append(rep)

        resp = requests.get(auth_resolver.format(username=self.username))
        rep = HealtCheck.check_status(resp, 'Auth resolve valid username: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'userid', self.owner_id, 'Auth resolve valid username: corect username')
        auth_report.append(rep)

        resp = requests.get(auth_resolver.format(username='invalid'))
        rep = HealtCheck.check_status(resp, 'Auth resolve invalid username: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'userid', None, 'Auth resolve valid username: username null')
        auth_report.append(rep)

        resp = requests.get(auth_profile.format(username=self.username))
        rep = HealtCheck.check_status(resp, 'Auth profile valid username: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'found', True, 'Auth profile valid username: corect username')
        auth_report.append(rep)

        resp = requests.get(auth_profile.format(username='invalid'))
        rep = HealtCheck.check_status(resp, 'Auth profile invalid username: status 200', 200)
        auth_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'found', False, 'Auth profile invalid username: username null')
        auth_report.append(rep)

        self.health_report['auth_report'] = auth_report

    def check_filemanager(self,
                        prefix='storage',
                        bucket='pkgstore.datahub.io',
                        dataset_id='basic-csv',
                        resource_name='comma-separated'):
        info = {
            'prefix': 'source',
            'owner': self.username,
            'ownerid':self.owner_id,
            'dataset_id': dataset_id,
            'revision': 'latest'
        }
        revision_number = self.get_revision_number(info)
        filemanager_report = []
        info_endpoint = urljoin(self.base_url, path.join(prefix, 'info', bucket,
                self.owner_id, dataset_id, resource_name, '{filename}'))
        owner_endpoint = urljoin(self.base_url, path.join(prefix, 'owner', '{owner}'))
        dataset_endpoint = urljoin(self.base_url, path.join(prefix, 'dataset_id', '{ownerid}', '{dataset_id}'))
        flow_endpoint = urljoin(self.base_url, path.join(prefix, 'flow_id', '{ownerid}', '{dataset_id}', '{revision}'))

        resp = requests.get(info_endpoint.format(filename='invalid'))
        rep = HealtCheck.check_status(resp, 'Storage with invalid filename: status 404', 404)
        filemanager_report.append(rep)

        resp = requests.get(info_endpoint.format(filename='datapackage.json'))
        rep = HealtCheck.check_status(resp, 'Storage with invalid filename: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_body(body, 'owner', self.username, 'Storage with valid filename: owner matches')
        filemanager_report.append(rep)

        resp = requests.get(owner_endpoint.format(owner='invalid'))
        rep = HealtCheck.check_status(resp, 'Storage with invalid owner: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_numbers(0, body.get('totalBytes'), 'Storage with invalid owner: totalBytes is 0', equal=True)
        filemanager_report.append(rep)

        resp = requests.get(owner_endpoint.format(owner=self.username))
        rep = HealtCheck.check_status(resp, 'Storage with valid owner: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_numbers(0, body.get('totalBytes'), 'Storage with valid owner: totalBytes is more than 0')
        filemanager_report.append(rep)

        resp = requests.get(dataset_endpoint.format(ownerid=self.owner_id, dataset_id='invalid'))
        rep = HealtCheck.check_status(resp, 'Storage with invalid dataset: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_numbers(0, body.get('totalBytes'), 'Storage with invalid dataset: totalBytes is 0', equal=True)
        filemanager_report.append(rep)

        resp = requests.get(dataset_endpoint.format(ownerid=self.owner_id, dataset_id=dataset_id))
        rep = HealtCheck.check_status(resp, 'Storage with valid dataset: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_numbers(0, body.get('totalBytes'), 'Storage with valid dataset: totalBytes is more than 0')
        filemanager_report.append(rep)

        resp = requests.get(flow_endpoint.format(**info))
        rep = HealtCheck.check_status(resp, 'Storage with invalid flow: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_numbers(0, body.get('totalBytes'), 'Storage with invalid flow: totalBytes is 0', equal=True)
        filemanager_report.append(rep)

        info['revision'] = revision_number
        resp = requests.get(flow_endpoint.format(**info))
        rep = HealtCheck.check_status(resp, 'Storage with valid flow: status 200', 200)
        filemanager_report.append(rep)
        body = resp.json()
        rep = HealtCheck.check_numbers(0, body.get('totalBytes'), 'Storage with invalid flow: totalBytes is more than 0')
        filemanager_report.append(rep)

        self.health_report['filemanager_report'] = filemanager_report

    def check_bitstore(self, prefix='rawstore', dataset_id='basic-csv'):
        info_endpoint = urljoin(self.base_url, path.join(prefix, 'info?jwt={jwt}'))
        authorize_endpoint = urljoin(self.base_url, path.join(prefix, 'authorize?jwt={jwt}'))
        presign_endpoint = urljoin(self.base_url, path.join(prefix, 'presign?jwt={jwt}&url={url}&ownerid={ownerid}'))

        rawstore_report = []

        resp = requests.get(info_endpoint.format(jwt='invalid'))
        rep = HealtCheck.check_status(resp, 'Rawstore info with invalid JWT: status 401', 401)
        rawstore_report.append(rep)

        resp = requests.get(info_endpoint.format(jwt=self.get_token('rawstore')))
        rep = HealtCheck.check_status(resp, 'Rawstore info with valid JWT: status 200', 200)
        rawstore_report.append(rep)

        resp = requests.post(authorize_endpoint.format(jwt='invalid'))
        rep = HealtCheck.check_status(resp, 'Rawstore authorize with invalid JWT: status 400', 400)
        rawstore_report.append(rep)

        payload = {'metadata': {"owner": "invalid"}}
        resp = requests.post(authorize_endpoint.format(jwt=self.get_token('rawstore')), json=payload)
        rep = HealtCheck.check_status(resp, 'Rawstore authorize with invalid owner: status 401', 401)
        rawstore_report.append(rep)

        payload = {
            'metadata': {"owner": self.owner_id, 'findability': 'unlisted', 'dataset': dataset_id},
            'filedata': {'file.csv': {'length':  1000000000}}
        }
        resp = requests.post(authorize_endpoint.format(jwt=self.get_token('rawstore')), json=payload)
        rep = HealtCheck.check_status(resp, 'Rawstore authorize exeeds limit: status 403', 403)
        rawstore_report.append(rep)

        payload = {
          "metadata": {"owner": self.owner_id,"findability": "unlisted"},
          "filedata": {
            "comma.csv": {"length": 45,"md5": "XHvyntj8DTJCm4U+LF+S5g==","name": "comma-separated"},
            "datapackage.json": {"length": 366,"md5": "f1cPlzjOYL3ymM/eaFKNhA==","name": "datapackage.json"}
          }
        }
        resp = requests.post(authorize_endpoint.format(jwt=self.get_token('rawstore')), json=payload)
        rep = HealtCheck.check_status(resp, 'Rawstore authorize valid input: status 200', 200)
        rawstore_report.append(rep)

        resp = requests.get(presign_endpoint.format(
                        jwt='invalid',url='http://example.com',ownerid='invalid'))
        rep = HealtCheck.check_status(resp, 'Rawstore presign no need to presign: status 200', 200)
        rawstore_report.append(rep)

        self.health_report['rawstore_report'] = rawstore_report

    def check_resolver(self, prefix='resolver'):
        resolve_endpoint = urljoin(self.base_url, path.join(prefix, 'resolve?path={userid}/dataset'))
        resolver_report = []

        resp = requests.get(resolve_endpoint.format(userid=self.username))
        rep = HealtCheck.check_status(resp, 'Resolver resolve valid owner: status 200', 200)
        resolver_report.append(rep)
        body = resp.json()
        rep =  HealtCheck.check_body(body, 'userid', self.owner_id, 'Resolver resolve valid owner: owner matches')
        resolver_report.append(rep)

        resp = requests.get(resolve_endpoint.format(userid='invalid'))
        rep = HealtCheck.check_status(resp, 'Resolver resolve invalid owner: status 200', 200)
        resolver_report.append(rep)
        body = resp.json()
        rep =  HealtCheck.check_body(body, 'userid', None, 'Resolver resolve invalid owner: owner is None')
        resolver_report.append(rep)

        self.health_report['resolver_report'] = resolver_report

    def check_metastore(self, prefix='metastore'):
        dataset_endpoint = urljoin(self.base_url, path.join(prefix, 'search','dataset?datahub.ownerid="{owner}"'))
        events_endpoint = urljoin(self.base_url, path.join(prefix, 'search', 'events?ownerid="{owner}"'))
        headers = {'Auth-Token': '%s' % self.jwt}
        metastore_report = []

        resp = requests.get(dataset_endpoint.format(owner=self.owner_id))
        rep = HealtCheck.check_status(resp, 'Metastore search datasets invalid JWT: status 200', 200)
        metastore_report.append(rep)
        body = resp.json()
        rep =  HealtCheck.check_numbers(0, body.get('summary')['total'],  'Metastore search datasets invalid JWT: total is 0', equal=True)
        metastore_report.append(rep)
        rep =  HealtCheck.check_numbers(0, body.get('summary')['totalBytes'],  'Metastore search datasets invalid JWT: totalBytes is 0', equal=True)
        metastore_report.append(rep)

        resp = requests.get(dataset_endpoint.format(owner=self.owner_id), headers=headers)
        rep = HealtCheck.check_status(resp, 'Metastore search datasets valid JWT: status 200', 200)
        metastore_report.append(rep)
        body = resp.json()
        rep =  HealtCheck.check_numbers(0, body.get('summary')['total'],  'Metastore search datasets valid JWT: total is 0')
        metastore_report.append(rep)
        rep =  HealtCheck.check_numbers(0, body.get('summary')['totalBytes'],  'Metastore search datasets valid JWT: totalBytes is 0')
        metastore_report.append(rep)

        resp = requests.get(dataset_endpoint.format(owner=self.owner_id), headers=headers)
        datasets = resp.json().get('results')
        dataset = [i for i in datasets if i.get('name') == 'basic-csv'][0]
        update_time = dataset.get('datahub', {}).get('modified')
        update_time = datetime.datetime.strptime(update_time, '%Y-%m-%dT%H:%M:%S.%f')
        rep =  HealtCheck.check_numbers(self.today, update_time, 'Metastore Latest metadata is there')
        metastore_report.append(rep)

        resp = requests.get(events_endpoint.format(owner=self.owner_id))
        rep = HealtCheck.check_status(resp, 'Metastore search events invalid JWT: status 200', 200)
        metastore_report.append(rep)
        body = resp.json()
        rep =  HealtCheck.check_numbers(0, body.get('summary')['total'],  'Metastore search events invalid JWT: total is 0')
        metastore_report.append(rep)

        resp = requests.get(events_endpoint.format(owner=self.owner_id), headers=headers)
        rep = HealtCheck.check_status(resp, 'Metastore search events valid JWT: status 200', 200)
        metastore_report.append(rep)
        body = resp.json()
        rep =  HealtCheck.check_numbers(3, body.get('summary')['total'],  'Metastore search events valid JWT: total is 0')
        metastore_report.append(rep)

        events = resp.json().get('results')
        event = [i for i in events if i.get('dataset') == 'basic-csv'][0]
        update_time = event.get('timestamp')
        update_time = datetime.datetime.strptime(update_time, '%Y-%m-%dT%H:%M:%S.%f')
        rep =  HealtCheck.check_numbers(self.today, update_time, 'Metastore Latest event is there')
        metastore_report.append(rep)

        self.health_report['metastore_report'] = metastore_report

    def check_plans(self, prefix='plans'):
        plans_endpoint = urljoin(self.base_url, prefix)
        plans_report = []
        resp = requests.get(plans_endpoint)
        rep = HealtCheck.check_status(resp, 'Plans: status 401', 401)
        plans_report.append(rep)

        self.health_report['plans_report'] = plans_report

    def check_frontend(self, homepage='https://datahub.io', dataset='basic-csv'):
        frontend_report = []
        resp = requests.get(homepage)
        rep = HealtCheck.check_status(resp, 'Frontend homepage: status 200', 200)
        frontend_report.append(rep)

        resp = requests.get(urljoin(homepage, '%s/%s' % (self.username, dataset)))
        rep = HealtCheck.check_status(resp, 'Frontend showcase: status 200', 200)
        frontend_report.append(rep)

        resp = requests.get(urljoin(homepage,'search'))
        rep = HealtCheck.check_status(resp, 'Frontend Search: status 200', 200)
        frontend_report.append(rep)
        self.health_report['frontend_report'] = frontend_report

    def get_report(self):
        return self.health_report

    def get_token(self, service):
        resp = requests.get(urljoin(self.base_url, 'auth/authorize?jwt=%s&service=%s' % (self.jwt, service)))
        return resp.json().get('token')

    def get_revision_number(self, info):
        info_endpoint = urljoin(self.base_url, '{prefix}/{ownerid}/{dataset_id}/{revision}')
        resp = requests.get(info_endpoint.format(**info))
        revision_number = int(resp.json().get('id', '').split('/')[-1])
        return revision_number
