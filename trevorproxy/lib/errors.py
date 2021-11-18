class TrevorProxyError(Exception):
    pass

class SSHProxyError(TrevorProxyError):
    pass

class InterfaceProxyError(TrevorProxyError):
    pass