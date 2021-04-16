AUTH_SESSION_INFO_DEFAULT_GROUPS = 1 << 0
AUTH_SESSION_INFO_AUTHENTICATED = 1 << 1
AUTH_SESSION_INFO_SIMPLE_PRIVILEGES = 1 << 2

def system_session():
    return

class Session:
    def __init__(self):
        self.security_token = b""

def user_session(samdb, lp_ctx, dn, session_info_flags):
    return Session()
