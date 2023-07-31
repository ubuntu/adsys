def LoadParm(smb_conf=None):
    if smb_conf is None:
        return
    print('Loading smb.conf')
    with open(smb_conf, 'r') as f:
        print(f.read())
