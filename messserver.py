import socket
import struct
import select
import logging
import logging.config

PROXY_IP = '127.0.0.1'
PROXY_PORT = 45678

logging.config.fileConfig('logging.conf')
log = logging.getLogger('messsocks')


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_IP, PROXY_PORT))
    server.listen()
    while True:
        # bootstrap
        proxy_conn = ProxyConnection(server)
        log.info('proxy server connected!')
        target_skt = proxy_conn.serve()
        proxy_conn.target_skt = target_skt
        target_conn = TargetConnection(target_skt, proxy_conn)

        inputs = [server, proxy_conn, target_conn]
        while True:
            rlist, wlist, elist = select.select(inputs, [], [])
            for r in rlist:
                if r is server:
                    proxy_conn = ProxyConnection(server)
                    proxy_conn.proxy_skt.setblocking(False)
                    target_skt = proxy_conn.serve()
                    target_skt.setblocking(False)
                    proxy_conn.target_skt = target_skt
                    target_conn = TargetConnection(target_skt, proxy_conn)
                    inputs.append(proxy_conn)
                    inputs.append(target_conn)
                else:
                    if type(r) is ProxyConnection:
                        r.handle_protocol()
                    try:
                        r.read()
                    except BrokenPipeError:
                        inputs.remove(r)


class ProxyConnection():
    def __init__(self, server, target_skt=None):
        self.proxy_skt, _ = server.accept()
        self.target_skt = target_skt

    def serve(self):
        """
        New target socket
        """
        target_skt = self.handle_protocol()
        return target_skt

    def fileno(self):
        return self.proxy_skt.fileno()

    def read(self):
        data = self.proxy_skt.recv(4096)
        self.target_skt.sendall(data)

    def send(self):
        data = self.target_skt.recv(4096)
        self.proxy_skt.sendall(data)

    def handle_protocol(self):
        ver, connect_type = struct.unpack('!BB', self.proxy_skt.recv(2))
        assert ver == 1
        if connect_type == 1:
            target_ip = socket.inet_ntoa(self.proxy_skt.recv(4))
            target_port = struct.unpack('!H', self.proxy_skt.recv(2))[0]
            self.proxy_skt.sendall(struct.pack('!BB', 1, 1))
            target_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_skt.connect((target_ip, target_port))
            return target_skt
        return None


class TargetConnection():
    def __init__(self, target_skt, proxy_conn):
        self.proxy_conn = proxy_conn
        self.target_skt = target_skt

    def fileno(self):
        return self.target_skt.fileno()

    def read(self):
        self.proxy_conn.send()


if __name__ == '__main__':
    start_server()
