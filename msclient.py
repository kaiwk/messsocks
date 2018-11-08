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

logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }
    },
    'handlers': {
        'mess_handler': {
            'class': 'logging.FileHandler',
            'level': 'INFO',
            'filename': './logs/msclient.log',
            'formatter': 'default',
            'mode': 'a'
        },
    },
    'loggers': {
        'messsocks': {
            'handlers': ['mess_handler']
        }
    }
})
log = logging.getLogger('msclient')
log.setLevel(logging.DEBUG)


class State(Enum):
    CONNECT = 0
    REQUEST = 1
    VERIFY = 2


def start_proxy(auth_method=NO_AUTH):
    """
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(ADDR)
        s.listen()
        while True:
            conn, dst_addr = s.accept()
            log.info('connected by %s', dst_addr)
            state = State.CONNECT
            with conn:
                if state == State.CONNECT:
                    ver, nmethods = struct.unpack('>BB', conn.recv(2))
                    methods = [ord(conn.recv(1)) for _ in range(nmethods)]
                    if ver == SOCKS_VERSION:
                        if auth_method in methods:
                            conn.sendall(struct.pack('>BB', ver, auth_method))
                        if auth_method == NO_AUTH:
                            state = State.REQUEST
                        elif auth_method == USERNAME_PASSWORD:
                            state = State.VERIFY

                if state == State.VERIFY:
                    if verify_credentials(conn, USERNAME, PASSWORD):
                        state = State.REQUEST
                    else:
                        state = State.CONNECT

                if state == State.REQUEST:
                    ver, cmd, _, atyp = struct.unpack('>BBBB', conn.recv(4))
                    assert ver == SOCKS_VERSION

                    if atyp == 1: # ipv4
                        dst_addr = socket.inet_ntoa(conn.recv(4))
                    elif atyp == 3: # domain
                        domain_len = ord(conn.recv(1))
                        dst_addr = conn.recv(domain_len)
                    dst_port = struct.unpack('>H', conn.recv(2))[0]

                    try:
                        if cmd == 1: # connect
                            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            log.info('remote: %s:%s', dst_addr, dst_port)

                            remote.connect((dst_addr, dst_port))
                            bind_address = remote.getsockname()
                            log.info('bind: %s', bind_address)

                            bind_addr = struct.unpack('>I', socket.inet_aton(bind_address[0]))[0]
                            bind_port = bind_address[1]
                            # Success, rep = 0
                            reply = struct.pack('>BBBBIH', SOCKS_VERSION, 0, 0, atyp, 3, bind_port)
                    except Exception as err:
                        # Success, rep = 1
                        reply = struct.pack('>BBBBIH', SOCKS_VERSION, 1, 0, atyp, bind_addr, bind_port)
                        log.error(err)

                    log.info('socks version: %s, bind address: %s:%s', SOCKS_VERSION, bind_addr, bind_port)
                    conn.sendall(reply)

                    # start exchange data
                    if reply[1] == 0 and cmd == 1:
                        exchange_loop(conn, remote)
                        conn.close()
                        state = State.CONNECT


def exchange_loop(client, remote):
    while True:
        r, w, e = select.select([client, remote], [], [])

        if client in r:
            data = client.recv(4096)
            if remote.send(data) <= 0:
                break

        if remote in r:
            data = remote.recv(4096)
            if client.send(data) <= 0:
                break


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
    start_proxy()
