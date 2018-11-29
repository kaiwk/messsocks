import socket
import select
import struct
import logging.config

from enum import Enum


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


def connect_remote_proxy(lsconn, local_proxy):
    ok, target_addr = start_connect(lsconn)
    if ok:
        local_proxy.sendall(socket.inet_aton(target_addr[0]))
        local_proxy.sendall(struct.pack('!H', target_addr[1]))
    return ok

def exchange_loop():
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_server.bind(ADDR)
    local_server.listen()
    lsconn, _ = local_server.accept()
    local_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # start protocol between local proxy and remote proxy
    # TODO: design a decent protocol
    local_proxy.connect((PROXY_IP, PROXY_PORT))
    success = struct.unpack('!B', local_proxy.recv(1))[0]
    # end protocol

    if success:
        connect_remote_proxy(lsconn, local_proxy)
    local_proxy.setblocking(False)
    lsconn.setblocking(False)

    inputs = [local_server, local_proxy, lsconn]
    local_data = None
    proxy_data = None
    while True:
        rlist, wlist, elist = select.select(inputs, [], [])
        for r in rlist:
            if r is local_server:
                lsconn, _ = local_server.accept()
                connect_remote_proxy(lsconn, local_proxy)
                lsconn.setblocking(False)
                inputs.append(lsconn)
                inputs.append(local_proxy)
            elif r is local_proxy:
                proxy_data = local_proxy.recv(4096)
                if proxy_data:
                    log.info('proxy data is not none')
                    lsconn.sendall(proxy_data)
            else:
                local_data = r.recv(4096)
                if local_data:
                    log.info('local data is not none')
                    local_proxy.sendall(local_data)


def start_connect(lsconn, auth_method=NO_AUTH):
    """
    :param lsconn: local server connection
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
    ver, nmethods = struct.unpack('!BB', lsconn.recv(2))
    methods = [ord(lsconn.recv(1)) for _ in range(nmethods)]
    if ver == SOCKS_VERSION:
        if auth_method in methods:
            lsconn.sendall(struct.pack('!BB', ver, auth_method))

            if auth_method == USERNAME_PASSWORD:
                if not verify_credentials(lsconn, USERNAME, PASSWORD):
                    return False, ()
    log.info('connect success...')

    # after verification
    ver, cmd, _, atyp = struct.unpack('!BBBB', lsconn.recv(4))
    assert ver == SOCKS_VERSION
    if atyp == 1: # ipv4
        target_ip = socket.inet_ntoa(lsconn.recv(4))
    elif atyp == 3: # domain
        domain_len = ord(lsconn.recv(1))
        target_ip = lsconn.recv(domain_len)
    else:
        return False, ()
    target_port = struct.unpack('!H', lsconn.recv(2))[0]

    if cmd == 1: # connect
        try:
            log.info('target: %s:%s', target_ip, target_port)
            # Success, rep = 0
            reply = struct.pack('!BBBBIH', SOCKS_VERSION, 0, 0, atyp, 0, 0)
        except Exception as err:
            # Failed, rep = 1
            reply = struct.pack('!BBBBIH', SOCKS_VERSION, 1, 0, atyp, 0, 0)
            log.error('socks version: %s, bind address: %s:%s', SOCKS_VERSION, 0, 0)
            lsconn.sendall(reply)
            log.error(err)
            return False, ()

    lsconn.sendall(reply)

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
