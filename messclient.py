import socket
import struct
import logging.config
import asyncio

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


async def verify_credentials(reader, writer, username, passwd):
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

    version = ord(await reader.read(1))
    log.info('authentication version: %s', version)
    assert version == AUTHENTICATION_VERSION

    ulen = ord(await reader.read(1))
    _username = await reader.read(ulen).decode('utf-8')

    plen = ord(await reader.read(1))
    _password = await reader.read(plen).decode('utf-8')

    if _username == username and _password == passwd:
        # Success, status = 0
        response = struct.pack(">BB", version, 0)
        writer.write(response)
        await writer.drain()
        return True

    # Failure, status != 0
    response = struct.pack(">BB", version, 1)
    writer.write(response)
    await writer.drain()
    return False


async def start_proxy(reader, writer):
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
    auth_method = NO_AUTH
    state = State.CONNECT
    if state == State.CONNECT:
        ver, nmethods = struct.unpack('>BB', await reader.read(2))
        log.info('start connect: %r', state)
        methods = [ord(await reader.read(1)) for _ in range(nmethods)]
        if ver == SOCKS_VERSION:
            if auth_method in methods:
                writer.write(struct.pack('>BB', ver, auth_method))
                await writer.drain()
            if auth_method == NO_AUTH:
                state = State.REQUEST
            elif auth_method == USERNAME_PASSWORD:
                state = State.VERIFY

    if state == State.VERIFY:
        if await verify_credentials(reader, writer, USERNAME, PASSWORD):
            state = State.REQUEST
        else:
            state = State.CONNECT
        log.info('state: %r', state)

    if state == State.REQUEST:
        ver, cmd, _, atyp = struct.unpack('>BBBB', await reader.read(4))
        assert ver == SOCKS_VERSION
        log.info('start request: %r', state)
        if atyp == 1: # ipv4
            dst_addr = socket.inet_ntoa(await reader.read(4))
        elif atyp == 3: # domain
            domain_len = ord(await reader.read(1))
            dst_addr = await reader.read(domain_len)
        dst_port = struct.unpack('>H', await reader.read(2))[0]

        try:
            if cmd == 1: # connect
                # bind_address = ('127.0.0.1', 34567)
                # log.info('bind address is %s', bind_address)
                remote_reader, remote_writer = await asyncio.open_connection(dst_addr, dst_port)
                bind_address = remote_writer.get_extra_info('sockname')
                log.debug('remote: %s:%s', dst_addr, dst_port)
                log.debug('bind: %s', bind_address)

                bind_addr = struct.unpack('>I', socket.inet_aton(bind_address[0]))[0]
                bind_port = bind_address[1]
                # Success, rep = 0
                reply = struct.pack('>BBBBIH', SOCKS_VERSION, 0, 0, atyp, 3, bind_port)
        except Exception as err:
            # Success, rep = 1
            reply = struct.pack('>BBBBIH', SOCKS_VERSION, 1, 0, atyp, bind_addr, bind_port)
            log.error(err)

        log.debug('socks version: %s, bind address: %s:%s', SOCKS_VERSION, bind_addr, bind_port)
        writer.write(reply)
        await writer.drain()

        # start exchange data
        if reply[1] == 0 and cmd == 1:
            log.info('start exchange data: %r', state)
            count = 0
            while True:
                log.info('reader reading...')
                data = await reader.read(4096)
                if data:
                    remote_writer.write(data)
                    await remote_writer.drain()

                log.info('remote reader reading...')
                data = await remote_reader.read(4096)
                if data:
                    writer.write(data)
                    await writer.drain()

                log.info('looping: %d', count)
                count += 1

                if not data:
                    break

            log.info('end exchange data: %r', state)

async def main():
    server = await asyncio.start_server(start_proxy, HOST, PORT)
    addr = server.sockets[0].getsockname()
    log.info('Serving on %s', addr)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
