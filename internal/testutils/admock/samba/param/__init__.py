# TiCS: disabled # samba mock

import os


class LoadParm(object):
    def __init__(self, smb_conf=None):
        self.values = {}
        if smb_conf is None:
            return
        print('Loading smb.conf')
        with open(smb_conf, 'r') as f:
            print(f.read())

    def set(self, name, value):
        if name == 'client ldap sasl wrapping' and value == 'starttls' and os.getenv('ADSYS_TESTS_STARTTLS_SUPPORTED') == '0':
            raise ValueError('unknown client ldap sasl wrapping value: starttls')
        if os.getenv('ADSYS_TESTS_FAIL_LDAP_PARAMETER') == name:
            raise ValueError('simulated parameter configuration failure: %s' % name)
        self.values[name] = value

    def log_level(self):
        return 0
