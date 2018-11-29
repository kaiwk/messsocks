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

logging.config.fileConfig('logging.conf')
log = logging.getLogger('messsocks')


class State(Enum):
    CONNECT = 0
    REQUEST = 1
    VERIFY = 2


def exchange_loop():
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    skt.bind(ADDR)
    skt.listen()
    local_fds = [skt]
    remote_skts = []
    l2r_pairs = dict()
    r2l_pairs = dict()

    while True:
        inputs = local_fds + remote_skts
        rlist, wlist, elist = select.select(inputs, [], [], 3)
        try:
            for r in rlist:
                if r == skt:
                    lconn, dst_addr = r.accept()
                    log.info('connected by %s', dst_addr)
                    if start_connect(lconn, remote_skts):  # append new remote socket
                        rskt = remote_skts[-1]
                        rskt.setblocking(False)
                        lconn.setblocking(False)
                        local_fds.append(lconn)           # append new local client connection
                        l2r_pairs[lconn] = rskt
                        r2l_pairs[rskt] = lconn
                else:
                    data = r.recv(4096)
                    if data:
                        if r in l2r_pairs:
                            l2r_pairs[r].send(data)
                        elif r in r2l_pairs:
                            r2l_pairs[r].send(data)
                    else:
                        if r in l2r_pairs:
                            del l2r_pairs[r]
                        elif r in r2l_pairs:
                            del r2l_pairs[r]
        except Exception:
            local_fds = [skt]
            remote_skts = []
            l2r_pairs = dict()
            r2l_pairs = dict()

        # log.info('l2r_pairs: %s', l2r_pairs)
        # log.info('r2l_pairs: %s', r2l_pairs)


def start_connect(conn, remote_skts, auth_method=NO_AUTH):
    """
    :param conn: client connection
    :param remote_skts: remote socket list
    :param auth_method:
    :returns: success or not
    :rtype: bool

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
        DST.PORT desired destination dst_port in network octet
        order

    Server:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    """

    # connect, verify credentials
    ver, nmethods = struct.unpack('>BB', conn.recv(2))
    methods = [ord(conn.recv(1)) for _ in range(nmethods)]
    if ver == SOCKS_VERSION:
        if auth_method in methods:
            conn.sendall(struct.pack('>BB', ver, auth_method))

            if auth_method == USERNAME_PASSWORD:
                if not verify_credentials(conn, USERNAME, PASSWORD):
                    return False
    log.info('connect success...')

    # after verification
    ver, cmd, _, atyp = struct.unpack('>BBBB', conn.recv(4))
    assert ver == SOCKS_VERSION
    if atyp == 1: # ipv4
        dst_addr = socket.inet_ntoa(conn.recv(4))
    elif atyp == 3: # domain
        domain_len = ord(conn.recv(1))
        dst_addr = conn.recv(domain_len)
    else:
        return False
    dst_port = struct.unpack('>H', conn.recv(2))[0]

    try:
        if cmd == 1: # connect
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(2)
            log.info('remote: %s:%s', dst_addr, dst_port)
            remote.connect((dst_addr, dst_port))
            # Success, rep = 0
            reply = struct.pack('>BBBBIH', SOCKS_VERSION, 0, 0, atyp, 0, 0)
    except Exception as err:
        # Failed, rep = 1
        reply = struct.pack('>BBBBIH', SOCKS_VERSION, 1, 0, atyp, 0, 0)
        log.error('socks version: %s, bind address: %s:%s', SOCKS_VERSION, 0, 0)
        conn.sendall(reply)
        log.error(err)
        return False

    conn.sendall(reply)

    if reply[1] == 0 and cmd == 1:
        remote_skts.append(remote)
        log.info('start communication...')
        return True
    return False


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
