import socket
import struct
import select
import threading

import messsocks.exception as ex
from messsocks.log import get_logger
from messsocks.protocol import raw
from messsocks.config import get_config

logger = get_logger("messserver")
glogger = get_logger("messsocks")


def start_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    while True:
        proxy_skt, _ = server.accept()
        glogger.info("proxy server connected!")
        proxy_conn = ProxyConnection(proxy_skt)
        try:
            proxy_conn.handle_protocol()
        except ex.ProtocolException as err:
            logger.error(err)
            continue
        target_conn = TargetConnection(proxy_conn.target_skt, proxy_conn.proxy_skt)
        threading.Thread(target=relay, args=(proxy_conn, target_conn)).start()
        logger.debug("Thread count: %s", threading.active_count())

    server.close()


def relay(proxy_conn, target_conn):
    cur_thread = threading.current_thread()
    logger.debug("Thread %s: %s", cur_thread.name, cur_thread.ident)
    proxy_conn.proxy_skt.setblocking(False)
    target_conn.target_skt.setblocking(False)
    inputs = [proxy_conn, target_conn]
    while True:
        try:
            rlist, wlist, elist = select.select(inputs, [], [], 3)
        except ValueError:
            return
        for r in rlist:
            try:
                r.read()
            except OSError:
                return


class ProxyConnection:
    def __init__(self, proxy_skt):
        self.proxy_skt = proxy_skt
        self.target_skt = None

    def fileno(self):
        return self.proxy_skt.fileno()

    def read(self):
        data = self.proxy_skt.recv(4096)
        if data:
            self.target_skt.sendall(data)
        else:
            glogger.info("proxy read data is empty")
            self.proxy_skt.close()
            self.target_skt.shutdown(socket.SHUT_WR)

    def close(self):
        self.proxy_skt.close()

    def handle_protocol(self):
        head = self.proxy_skt.recv(8)
        ver, conn_type, ip, port = struct.unpack("!BBIH", head)
        raw.check_version(ver)

        ip = socket.inet_ntoa(struct.pack("!I", ip))
        glogger.debug("ver: %s, type: %s, addr: %s:%s", ver, conn_type, ip, port)

        if conn_type == raw.NEW_CONN:
            target_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                target_skt.settimeout(3)
                target_skt.connect((ip, port))
            except (ConnectionRefusedError, socket.timeout):
                raise ex.ProtocolException("connect to target server failed")
            self.target_skt = target_skt
            return target_skt
        raise ex.ProtocolException("proxy protocol resolution failed")


class TargetConnection:
    def __init__(self, target_skt, proxy_skt):
        self.proxy_skt = proxy_skt
        self.target_skt = target_skt

    def fileno(self):
        return self.target_skt.fileno()

    def read(self):
        data = self.target_skt.recv(4096)
        if data:
            self.proxy_skt.sendall(data)
        else:
            glogger.info("target read data is empty")
            self.target_skt.close()
            self.proxy_skt.shutdown(socket.SHUT_WR)

    def close(self):
        self.target_skt.close()


def main():
    config = get_config()
    host = config["server"]["host"]
    port = int(config["server"]["port"])
    glogger.info("start server...")
    start_server(host, port)


if __name__ == "__main__":  # pragma: no cover
    main()
