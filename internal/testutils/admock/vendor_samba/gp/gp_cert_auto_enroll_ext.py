# TiCS: disabled # samba mock

import os

class gp_cert_auto_enroll_ext(object):
    def __init__(self, _lp, _credentials, _username, _store):
        pass

    def cache_get_all_attribute_values(self, _guid):
        return {'ZXhhbXBsZS1DQQ==': '{"files": ["/var/lib/adsys/certs/galacticcafe-CA.0.crt"]}'}

    def __enroll(self, guid, entries, trust_dir, private_dir):
        if os.getenv('ADSYS_WANT_AUTOENROLL_ERROR'):
            raise Exception('Autoenroll error requested')

        print('Enroll called')
        print()
        print(f'guid: {guid}')
        print(f'trust_dir: {trust_dir}; mode: {oct(os.stat(trust_dir).st_mode)}')
        print(f'private_dir: {private_dir}; mode: {oct(os.stat(private_dir).st_mode)}')

        if entries == []:
            return ['example-CA']

        print('\nentries:')
        for entry in entries:
            print(f'''keyname: {entry.keyname}
valuename: {entry.valuename}
type: {entry.type}
data: {entry.data}
''')
        return ['example-CA']

    def clean(self, guid, remove=None):
        if os.getenv('ADSYS_WANT_AUTOENROLL_ERROR'):
            raise Exception('Autoenroll error requested')

        print('Unenroll called')
        print(f'guid: {guid}')
        print(f'remove: {remove}')
