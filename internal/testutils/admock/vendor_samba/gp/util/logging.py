# TiCS: disabled # samba mock

def logger_init(_name, _level):
    pass

class log(object):
    @staticmethod
    def warning(msg):
        print(f'WARNING: {msg}')
