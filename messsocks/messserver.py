import socket
import struct
import select
import threading

from log import get_logger
from protocol import raw

PROXY_IP = '127.0.0.1'
PROXY_PORT = 45678

logger = get_logger('messserver')
glogger = get_logger('messsocks')

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_IP, PROXY_PORT))
    server.listen()
    while True:
        proxy_skt, _ = server.accept()
        glogger.info('proxy server connected!')
        proxy_conn = ProxyConnection(proxy_skt)
        try:
            proxy_conn.handle_protocol()
        except (socket.timeout, ConnectionRefusedError):
            continue
        target_conn = TargetConnection(proxy_conn.target_skt, proxy_conn.proxy_skt)
        threading.Thread(target=relay, args=(proxy_conn, target_conn)).start()
        logger.debug('Thread count: %s', threading.active_count())


def relay(proxy_conn, target_conn):
    cur_thread = threading.current_thread()
    logger.debug('Thread %s: %s', cur_thread.name, cur_thread.ident)
    proxy_conn.proxy_skt.setblocking(False)
    target_conn.target_skt.setblocking(False)
    inputs = [proxy_conn, target_conn]
    while True:
        try:
            rlist, wlist, elist = select.select(inputs, [], [])
        except ValueError:
            break
        for r in rlist:
            try:
                r.read()
            except OSError:
                break


class ProxyConnection():
    def __init__(self, proxy_skt):
        self.proxy_skt = proxy_skt
        self.target_skt = None

    def fileno(self):
        return self.proxy_skt.fileno()

    def read(self):
        data = self.proxy_skt.recv(4096)
        if not data:
            self.proxy_skt.close()
        self.target_skt.sendall(data)

    def close(self):
        self.proxy_skt.close()

    def handle_protocol(self):
        head = self.proxy_skt.recv(8)
        ver, conn_type, ip, port = struct.unpack('!BBIH', head)
        raw.check_version(ver)

        ip = socket.inet_ntoa(struct.pack('!I', ip))
        glogger.debug('ver: %s, type: %s, addr: %s:%s', ver, conn_type, ip, port)

        if conn_type == raw.NEW_CONN:   # new connection
            target_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_skt.settimeout(2)
            target_skt.connect((ip, port))
            self.target_skt = target_skt
            return target_skt
        return None


class TargetConnection():
    def __init__(self, target_skt, proxy_skt):
        self.proxy_skt = proxy_skt
        self.target_skt = target_skt

    def fileno(self):
        return self.target_skt.fileno()

    def handle_protocol(self):
        pass

    def read(self):
        data = self.target_skt.recv(4096)
        self.proxy_skt.sendall(data)

    def close(self):
        self.target_skt.close()


if __name__ == '__main__':
    start_server()
