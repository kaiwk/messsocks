import socket
import select
import struct
import logging.config

from enum import Enum

import exceptions as ex


HOST = '127.0.0.1'
PORT = 1081
ADDR = (HOST, PORT)

SOCKS_VERSION = 5
AUTHENTICATION_VERSION = 1

NO_AUTH = 0x00
USERNAME_PASSWORD = 0x02

USERNAME = 'username'
PASSWORD = 'password'

SERVER_IP = '127.0.0.1'
SERVER_PORT = 34561

PROXY_IP = '127.0.0.1'
PROXY_PORT = 45678

logging.config.fileConfig('logging.conf')
log = logging.getLogger('messsocks')


class State(Enum):
    CONNECT = 0
    REQUEST = 1
    VERIFY = 2

def exchange_loop():
    """A simple protocol to communicate with remote proxy
    client send:

            | ver | type | ipv4 | port |
            |-----+------+------+------|
            |   1 |    1 |    4 |    2 |

    ver: protocol version
    type: data frame type

    or
            | ver | type |
            |-----+------| + data
            |   1 |    0 |


    Explanation:

    type == 1, means its a new request, next 6 bytes is target address, so
    server return:

            | ver | success |
            |-----+---------|
            |   1 |       1 |

    success:
        1: success
        0: fail

    type == 0, means its a normal data frames, server return normal data frames
    from target.

    """
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_server.bind(ADDR)
    local_server.listen()
    local_conn = LocalConnection(local_server)
    proxy_conn = ProxyConnection(local_conn.local_skt)
    local_conn.proxy_conn = proxy_conn
    # socks5 and protocol
    ok, target_addr = local_conn.handle_socks5()
    proxy_conn.connect(target_addr)

    inputs = [local_server, proxy_conn, local_conn]
    while True:
        rlist, wlist, elist = select.select(inputs, [], [])
        for r in rlist:
            if r is local_server:
                local_conn = LocalConnection(local_server)
                proxy_conn = ProxyConnection(local_conn.local_skt)
                local_conn.proxy_conn = proxy_conn
                # socks5 and protocol
                ok, target_addr = local_conn.handle_socks5()
                proxy_conn.connect(target_addr)
                inputs.append(local_conn)
                inputs.append(proxy_conn)
            else:
                r.read()



class ProxyConnection():
    def __init__(self, local_skt):
        self.proxy_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_skt = local_skt

    def connect(self, target_addr):
        if self.handle_protocol(target_addr):
            pass
        else:
            raise ex.ProtocolException('Protocol resolution failed!')

    def fileno(self):
        return self.proxy_skt.fileno()

    def read(self):
        data = self.proxy_skt.recv(4096)
        self.local_skt.sendall(data)

    def send(self):
        data = self.local_skt.recv(4096)
        head = struct.pack('!BB', 1, 0) # ver = 1, type = 0
        self.proxy_skt.sendall(head)
        self.proxy_skt.sendall(data)

    def handle_protocol(self, target_addr):
        """
        :param target_addr: (ip, port)
        :returns: bool, connect success|failed
        :rtype:
        """
        self.proxy_skt.connect((PROXY_IP, PROXY_PORT))
        self.proxy_skt.sendall(struct.pack('!BB', 1, 1)) # ver = 1, type = 1
        self.proxy_skt.sendall(socket.inet_aton(target_addr[0])) # ip
        self.proxy_skt.sendall(struct.pack('!H', target_addr[1])) # port
        ver, success = struct.unpack('!BB', self.proxy_skt.recv(2))
        if ver == 1 and success == 1:
            return True
        return False


class LocalConnection():
    def __init__(self, local_server, proxy_conn=None):
        self.local_skt, _ = local_server.accept()
        self.proxy_conn = proxy_conn

    def fileno(self):
        return self.local_skt.fileno()

    def read(self):
        self.proxy_conn.send()

    def handle_socks5(self, auth_method=NO_AUTH):
        """
        :param local_skt: local server connection
        :param auth_method:
        :returns: True|False, (ip, port)
        :rtype: bool, tuple

        reference: rfc1928

        1. connect:

        Client:
                       +----+----------+----------+
                       |VER | NMETHODS | METHODS  |
                       +----+----------+----------+
                       | 1  |    1     | 1 to 255 |
                       +----+----------+----------+

        NMETHODS: number of methods
        METHODS:
            - X'00' NO AUTHENTICATION REQUIRED
            - X'01' GSSAPI
            - X'02' USERNAME/PASSWORD
            - X'03' to X'7F' IANA ASSIGNED
            - X'80' to X'FE' RESERVED FOR PRIVATE METHODS
            - X'FF' NO ACCEPTABLE METHODS

        Server:
                             +----+--------+
                             |VER | METHOD |
                             +----+--------+
                             | 1  |   1    |
                             +----+--------+

        Server select a method.

        2. request

        Client:

            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

        VER: protocol version: X'05'
        CMD
            - CONNECT X'01'
            - BIND X'02'
            - UDP ASSOCIATE X'03'
        RSV: RESERVED
        ATYP: address type of following address
            - IP V4 address: X'01'
            - DOMAINNAME: X'03', first byte is length of domain name
            - IP V6 address: X'04'
            DST.ADDR       desired destination address
            DST.PORT desired destination target_port in network octet
            order

        Server:

            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """

        # connect, verify credentials
        ver, nmethods = struct.unpack('!BB', self.local_skt.recv(2))
        methods = [ord(self.local_skt.recv(1)) for _ in range(nmethods)]
        if ver == SOCKS_VERSION:
            if auth_method in methods:
                self.local_skt.sendall(struct.pack('!BB', ver, auth_method))

                if auth_method == USERNAME_PASSWORD:
                    if not verify_credentials(self.local_skt, USERNAME, PASSWORD):
                        return False, ()
        log.info('connect success...')

        # after verification
        ver, cmd, _, atyp = struct.unpack('!BBBB', self.local_skt.recv(4))
        log.error('socks version: %s', ver)
        assert ver == SOCKS_VERSION
        if atyp == 1: # ipv4
            target_ip = socket.inet_ntoa(self.local_skt.recv(4))
        elif atyp == 3: # domain
            domain_len = ord(self.local_skt.recv(1))
            target_ip = self.local_skt.recv(domain_len)
        else:
            return False, ()
        target_port = struct.unpack('!H', self.local_skt.recv(2))[0]

        if cmd == 1: # connect
            try:
                log.info('target: %s:%s', target_ip, target_port)
                # Success, rep = 0
                reply = struct.pack('!BBBBIH', SOCKS_VERSION, 0, 0, atyp, 0, 0)
            except Exception as err:
                # Failed, rep = 1
                reply = struct.pack('!BBBBIH', SOCKS_VERSION, 1, 0, atyp, 0, 0)
                log.error('socks version: %s, bind address: %s:%s', SOCKS_VERSION, 0, 0)
                self.local_skt.sendall(reply)
                log.error(err)
                return False, ()

        self.local_skt.sendall(reply)

        if reply[1] == 0 and cmd == 1:
            log.info('start communication...')
            return True, (target_ip, target_port)


def verify_credentials(conn, username, passwd):
    """
    reference: rfc1929
    Client:

           +----+------+----------+------+----------+
           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
           +----+------+----------+------+----------+
           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
           +----+------+----------+------+----------+

    Server:

                        +----+--------+
                        |VER | STATUS |
                        +----+--------+
                        | 1  |   1    |
                        +----+--------+

    """

    version = ord(conn.recv(1))
    log.info('authentication version: %s', version)
    assert version == AUTHENTICATION_VERSION

    ulen = ord(conn.recv(1))
    _username = conn.recv(ulen).decode('utf-8')

    plen = ord(conn.recv(1))
    _password = conn.recv(plen).decode('utf-8')

    if _username == username and _password == passwd:
        # Success, status = 0
        response = struct.pack(">BB", version, 0)
        conn.sendall(response)
        return True

    # Failure, status != 0
    response = struct.pack(">BB", version, 1)
    conn.sendall(response)
    return False


if __name__ == '__main__':
    exchange_loop()
