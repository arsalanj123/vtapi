#!/usr/bin/env python3

import sys
import os

try:
    from vtapi.apikey import apikey
    import requests
except Exception as e:
    raise e

class VirusTotal(object):

    """Docstring for VirusTotal. """

    def __init__(self, args):

        self.args = args
        self.params = {'apikey':apikey}
        self.domain = 'https://www.virustotal.com/vtapi/v2/'

    def check_status_code(self, status_code):
        """ Check status code """

        if status_code == 204:
            print('> Request rate limit exceeded.')
            sys.exit(204)
        
        if status_code == 400:
            print('> Bad request.')
            sys.exit(400)
        
        if status_code == 403:
            print('> Forbidden.')
            if not apikey:
                print('> Add your API key: vtapi/apikey.py')
            sys.exit(403)
        
        if status_code == 200:
            return True
    
    def request(self, data):
        """ Requests """

        try:
            if 'file_report' in data.values():
                url = self.domain + 'file/report'
                response = requests.get(url, params=data['params'])
            
            if 'url_report'  in data.values():
                url = self.domain + 'url/report'
                response = requests.get(url, params=data['params'])
            
            if 'domain_report'  in data.values():
                url = self.domain + 'domain/report'
                response = requests.get(url, params=data['params'])
            
            if 'ip_report'  in data.values():
                url = self.domain + 'ip-address/report'
                response = requests.get(url, params=data['params'])

            if 'file_scan' in data.values():
                url = self.domain + 'file/scan'
                response = requests.post(url, files=data['files'], params=data['params'])
            
            if 'file_rescan' in data.values():
                url = self.domain + 'file/rescan'
                response = requests.post(url, params=data['params'])
            
            if 'url_scan' in data.values():
                url = self.domain + 'url/scan'
                response = requests.post(url, data=data['params'])
            
            if self.check_status_code(response.status_code):
                return response

            return None
        except Exception as e:
            print('Error:', e)


    def report(self):
        """ Retrieve file scan reports """
        
        
        params   = self.params
        resource = self.args['RESOURCE']
        params['resource'] = resource
        
        data = {
            'request_type':'file_report',
            'params':params
        }

        if self.args['--domain']:
            data['request_type'] = 'domain_report'
            data['params'].pop('resource', None)
            data['params']['domain'] = resource

        if self.args['--url']:
            data['request_type'] = 'url_report'
        
        
        if self.args['--ip']:
            data['request_type'] = 'ip_report'
            data['params'].pop('resource', None)
            data['params']['ip'] = resource
            
        result = self.request(data)
        return result.json()

    def scan(self):
        """ Upload and scan a file / Scan an URL """

        params = self.params
        target = self.args['TARGET']
        data   = {'params':params}

        if self.args['--url']:
            data['request_type'] = 'url_scan'
            data['params']['url'] = target

        else:
            filename = self.args['TARGET']
            if not os.path.exists(filename):
                print('No found file.')
                return None
        
            files = {'file': (filename, open(filename, 'rb'))}
            data  = {
                'request_type':'file_scan',
                'params':params,
                'files':files
            }

        result = self.request(data)
        result = result.json()
        data.clear()

        # get report
        resource = result['resource']
        params['resource'] = resource
        data = { 'params':params }

        if self.args['--url']:
            data['request_type'] = 'url_report'
        else:
            data['request_type'] = 'file_report'
        
        result = self.request(data)
        return result.json()
    
    def rescan(self):
        """ Re-scan a file """
        
        params = self.params
        params['resource'] = self.args['RESOURCE']

        data = {
            'type_request':'file_rescan',
            'params':params
        }
        
        result = self.request(data)
        result = result.json()
        data.clear()

        # get report
        resource = result['resource']
        params['resource'] = resource

        data = {
            'type_request':'file_report',
            'params':params
        }

        result = self.request(data)
        return result.json()

    def get_result(self):
        opts = {
            'report':self.report,
            'scan':self.scan,
            'rescan':self.rescan,
        }

        for key, value in self.args.items():
            if value and key in opts:
                return opts[key]()

