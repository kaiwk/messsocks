import socket
import struct

import messsocks.exception as ex
from messsocks.log import get_logger

NO_AUTH = 0x00
USERNAME_PASSWORD = 0x02

SOCKS_VERSION = 5
AUTHENTICATION_VERSION = 1

USERNAME = 'username'
PASSWORD = 'password'

logger = get_logger('messsocks')


def serve(local_skt, auth_method=NO_AUTH):
    """
    :param local_skt: local server connection
    :param auth_method:
    :returns: True|False, (ip, port)
    :rtype: (bool, tuple)

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
    try:
        plt_head = local_skt.recv(2)
        ver, nmethods = struct.unpack('!BB', plt_head)
    except struct.error as e:
        logger.error(e)
        return False, (None, None)
    all_methods = [ord(local_skt.recv(1)) for _ in range(nmethods)]
    if ver == SOCKS_VERSION:
        if auth_method in all_methods:
            local_skt.sendall(struct.pack('!BB', ver, auth_method))
            if auth_method == USERNAME_PASSWORD:
                if not verify_credentials(local_skt, USERNAME, PASSWORD):
                    raise ex.ProtocolException('username/password verify failed')
        else:
            raise ex.ProtocolException('no matched authentication method')
    else:
        raise ex.ProtocolException('socks version is not 5')

    logger.info('verify success...')
    # after verification

    try:
        ptl_head = local_skt.recv(4)
        ver, cmd, _, atyp = struct.unpack('!BBBB', ptl_head)
    except (ConnectionResetError, struct.error) as e:
        logger.error(e)
        return False, (None, None)

    assert ver == SOCKS_VERSION

    if atyp == 1: # ipv4
        target_ip = socket.inet_ntoa(local_skt.recv(4))
    elif atyp == 3: # domain
        domain_len = ord(local_skt.recv(1))
        target_ip = local_skt.recv(domain_len)
    else:
        logger.error('not ipv4 and domain address type')
        return False, (None, None)

    target_port = struct.unpack('!H', local_skt.recv(2))[0]

    logger.info('target: %s:%s', target_ip, target_port)

    if cmd == 1: # connect
        try:
            # Success, rep = 0
            reply = struct.pack('!BBBBIH', SOCKS_VERSION, 0, 0, atyp, 0, 0)
        except struct.error as err:
            # Failed, rep = 1
            reply = struct.pack('!BBBBIH', SOCKS_VERSION, 1, 0, atyp, 0, 0)
            logger.error('socks version: %s, bind address: %s:%s', SOCKS_VERSION, 0, 0)
            local_skt.sendall(reply)
            logger.error(err)
            return False, (None, None)

    local_skt.sendall(reply)

    if reply[1] == 0 and cmd == 1:
        logger.info('socks5 handshake finish')
        return True, (target_ip, target_port)

    return False, (None, None)


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
    logger.info('authentication version: %s', version)
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
