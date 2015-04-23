import asyncio

from .common import is_ami_action, AMICommandFailure
from .protocol import AMIProtocol


def connect(host, port=5038, username='', secret='', plaintext_login=False, loop=None):
    conn = AMIConnection(
        host=host,
        port=port,
        username=username,
        secret=secret,
        plaintext_login=plaintext_login,
        loop=loop)
    yield from conn.connect()
    return conn


class AMIConnection():
    """Asterisk AMI connection representation. Wraps protocol's actions."""
    def __init__(self, host, port=5038, username='', secret='', plaintext_login=False, loop=None):
        self.host = host
        self.port = port
        self.username = username
        self.secret = secret
        self.plaintext_login = plaintext_login

        self.closed = True

        self.loop = loop or asyncio.get_event_loop()
        self.protocol = AMIProtocol(loop=self.loop)

    # mirror ami protocol actions
    def __getattr__(self, item):
        if hasattr(self.protocol, item):
            attr = getattr(self.protocol, item)
            if is_ami_action(attr):
                return attr
        return object.__getattribute__(self, item)

    def connect(self):
        yield from self.loop.create_connection(lambda: self.protocol, host=self.host, port=self.port)
        yield from self.protocol.login(self.username, self.secret, self.plaintext_login)
        self.closed = False

    def close(self):
        self.closed = True
        self.protocol.close()

    def ping(self, timeout=3.0):
        try:
            yield from asyncio.wait_for(self.protocol.ping(), timeout, loop=self.loop)
        except asyncio.TimeoutError or AMICommandFailure:
            self.close()
            yield from self.connect()