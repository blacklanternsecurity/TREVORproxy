class TrevorProxyError(Exception):
    pass

class SSHProxyError(TrevorProxyError):
    pass

class TorProxyError(TrevorProxyError):
    pass

class InterfaceProxyError(TrevorProxyError):
    pass