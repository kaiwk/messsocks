import socket
import struct

import messsocks.exception as ex
from messsocks.log import get_logger

NO_AUTH = 0x00
USERNAME_PASSWORD = 0x02

SOCKS_VERSION = 5
AUTHENTICATION_VERSION = 1

USERNAME = "username"
PASSWORD = "password"

ADDRESS_TYPE = {"ipv4": 1, "domain": 3, "ipv6": 4}

logger = get_logger("messsocks")


def ensure_socks_version(expected, actual):
    if expected != actual:
        raise ex.ProtocolException("SOCKS version is not 5")


def verify(local_skt, auth_method):
    """
    Verify client
    """
    try:
        plt_head = local_skt.recv(2)
        ver, nmethods = struct.unpack("!BB", plt_head)
    except struct.error as e:
        logger.error(e)
        return False

    all_methods = [ord(local_skt.recv(1)) for _ in range(nmethods)]

    ensure_socks_version(SOCKS_VERSION, ver)

    if auth_method not in all_methods:
        raise ex.ProtocolException("no matched authentication method")

    local_skt.sendall(struct.pack("!BB", ver, auth_method))
    if auth_method == USERNAME_PASSWORD:
        if verify_credentials(local_skt, USERNAME, PASSWORD):
            # verify success
            pass
        else:
            raise ex.ProtocolException("username/password verify failed")

    logger.info("verify success...")
    return True


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

    # phase 1: verification
    if not verify(local_skt, auth_method):
        return False, (None, None)

    try:
        ptl_head = local_skt.recv(4)
        ver, cmd, _, atyp = struct.unpack("!BBBB", ptl_head)
    except (ConnectionResetError, struct.error) as e:
        logger.error(e)
        return False, (None, None)

    ensure_socks_version(SOCKS_VERSION, ver)

    if atyp == ADDRESS_TYPE["ipv4"]:
        target_host = socket.inet_ntoa(local_skt.recv(4))
    elif atyp == ADDRESS_TYPE["domain"]:
        domain_len = ord(local_skt.recv(1))
        target_host = local_skt.recv(domain_len)
    else:
        logger.error("not ipv4 and domain address type")
        return False, (None, None)

    target_port = struct.unpack("!H", local_skt.recv(2))[0]

    logger.info("target: %s:%s", target_host, target_port)

    # connect
    success = 0
    failed = 1
    if cmd == 1:
        try:
            reply = struct.pack("!BBBBIH", SOCKS_VERSION,
                                success, 0, atyp, 0, 0)
        except struct.error as err:
            reply = struct.pack("!BBBBIH", SOCKS_VERSION,
                                failed, 0, atyp, 0, 0)
            logger.error("socks version: %s, bind address: %s:%s",
                         SOCKS_VERSION, 0, 0)
            local_skt.sendall(reply)
            logger.error(err)
            return False, (None, None)

    local_skt.sendall(reply)

    if reply[1] == success and cmd == 1:
        logger.info("socks5 handshake finish")
        return True, (target_host, target_port)

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
    logger.info("authentication version: %s", version)
    assert version == AUTHENTICATION_VERSION

    ulen = ord(conn.recv(1))
    _username = conn.recv(ulen).decode("utf-8")

    plen = ord(conn.recv(1))
    _password = conn.recv(plen).decode("utf-8")

    success = 0
    failed = 1

    if _username == username and _password == passwd:
        response = struct.pack(">BB", version, success)
        conn.sendall(response)
        return True

    response = struct.pack(">BB", version, failed)
    conn.sendall(response)
    return False
