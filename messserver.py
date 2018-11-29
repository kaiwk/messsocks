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
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    skt.bind((PROXY_IP, PROXY_PORT))
    skt.listen()
    while True:
        proxy_conn, _ = skt.accept()
        log.info('proxy server proxy_connected!')

        # start protocol
        ver = struct.unpack('!B', proxy_conn.recv(1))[0]
        assert ver == 1
        target_ip = socket.inet_ntoa(proxy_conn.recv(4))
        target_port = struct.unpack('!H', proxy_conn.recv(2))[0]
        log.info('target_ip: %s, target_port: %s', target_ip, target_port)
        proxy_conn.sendall(struct.pack('!BB', 1, 1))
        # end protocol

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((target_ip, target_port))

        proxy_conn.setblocking(False)
        remote.setblocking(False)

        inputs = [proxy_conn, remote]
        while True:
            rlist, wlist, elist = select.select(inputs, [], [])
            for r in rlist:
                if r is proxy_conn:
                    data = proxy_conn.recv(4096)
                    if data:
                        log.info('remote send: data is not none')
                        remote.sendall(data)
                elif r is remote:
                    data = remote.recv(4096)
                    if data:
                        log.info('proxy_conn send: data is not none')
                        proxy_conn.sendall(data)


def remote_task(proxy_conn, ):

    pass


if __name__ == '__main__':
    start_server()
