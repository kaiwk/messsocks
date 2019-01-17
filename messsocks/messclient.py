import socket
import select
import struct
import threading

import messsocks.exception as ex
from messsocks.log import get_logger
from messsocks.utils import ip2int
from messsocks.protocol import socks5
from messsocks.config import get_config

NO_AUTH = 0x00
USERNAME_PASSWORD = 0x02

USERNAME = 'username'
PASSWORD = 'password'

logger = get_logger('messclient')
glogger = get_logger('messsocks')


def start_client(bind_addr, proxy_addr):
    """A simple protocol to communicate with remote proxy
    client send:

            | ver | type | ipv4 | port |
            |-----+------+------+------|
            |   1 |    1 |    4 |    2 |

    ver: protocol version
    type: data frame type

    Explanation:

    type == 1, means its a new request, next 6 bytes is target address, so
    server return:

            | ver | success |
            |-----+---------|
            |   1 |       1 |

    success:
        1: success
        0: fail

    type == 0, means it's a normal data frames, server return normal data frames
    from target.

    """
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_server.bind(bind_addr)
    local_server.listen()
    while True:
        local_skt, _ = local_server.accept()
        proxy_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_conn = LocalConnection(local_skt, proxy_skt)
        proxy_conn = ProxyConnection(local_skt, proxy_skt)
        try:
            local_conn.handle_protocol()
            proxy_conn.handle_protocol(proxy_addr, local_conn.target_addr)
        except ex.ProtocolException as err:
            logger.error(err)
            continue
        glogger.info('start connecting proxy server')
        threading.Thread(target=relay, args=(local_conn, proxy_conn)).start()
        logger.debug('Thread count: %s', threading.active_count())

    local_server.close()

def relay(local_conn, proxy_conn):
    cur_thread = threading.current_thread()
    logger.debug('Thread %s: %s', cur_thread.name, cur_thread.ident)
    proxy_conn.proxy_skt.setblocking(False)
    local_conn.local_skt.setblocking(False)
    inputs = [proxy_conn, local_conn]
    while True:
        try:
            rlist, wlist, elist = select.select(inputs, [], [], 3)
        except ValueError:
            return
        for r in rlist:
            try:
                r.read()
            except (ConnectionResetError, OSError):
                return


class ProxyConnection():
    def __init__(self, local_skt, proxy_skt):
        self.proxy_skt = proxy_skt
        self.local_skt = local_skt

    def fileno(self):
        return self.proxy_skt.fileno()

    def read(self):
        data = self.proxy_skt.recv(4096)
        if data:
            self.local_skt.sendall(data)
        else:
            glogger.info('proxy read data: is empty')
            self.proxy_skt.close()
            self.local_skt.shutdown(socket.SHUT_WR)

    def close(self):
        self.proxy_skt.close()

    def handle_protocol(self, proxy_addr, target_addr):
        """
        :param target_addr: (ip, port)
        :returns: bool, connect success|failed
        :rtype:
        """
        ip, port = target_addr
        ip = ip2int(ip)
        head = struct.pack('!BBIH', 1, 1, ip, port)
        try:
            self.proxy_skt.connect(proxy_addr)
        except ConnectionRefusedError:
            raise ex.ProtocolException('proxy socket connect failed')
        self.proxy_skt.sendall(head)
        return True


class LocalConnection():
    def __init__(self, local_skt, proxy_skt):
        self.local_skt = local_skt
        self.proxy_skt = proxy_skt
        self.target_addr = None

    def fileno(self):
        return self.local_skt.fileno()

    def read(self):
        data = self.local_skt.recv(4096)
        if data:
            self.proxy_skt.sendall(data)
        else:
            glogger.info('local read data: is empty')
            self.local_skt.close()
            self.proxy_skt.shutdown(socket.SHUT_WR)

    def handle_protocol(self):
        ok, target_addr = socks5.serve(self.local_skt)
        if ok:
            self.target_addr = target_addr
        else:
            raise ex.ProtocolException('socks5 resolution falied')

    def close(self):
        self.local_skt.close()


def main():
    config = get_config()
    host = config['client']['host']
    port = int(config['client']['port'])

    proxy_host = config['server']['host']
    proxy_port = int(config['server']['port'])
    start_client((host, port), (proxy_host, proxy_port))


if __name__ == '__main__':      # pragma: no cover
    main()
