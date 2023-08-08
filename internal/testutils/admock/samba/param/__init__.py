class LoadParm(object):
    def __init__(self, smb_conf=None):
        if smb_conf is None:
            return
        print('Loading smb.conf')
        with open(smb_conf, 'r') as f:
            print(f.read())

    def log_level(self):
        return 0
