import socket
import struct
import logging


SERVER_IP = '127.0.0.1'
SERVER_PORT = 34561


logging.config.fileConfig('logging.conf')
log = logging.getLogger('messsocks')


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_IP, SERVER_PORT))
        s.listen()
        while True:
            conn, dst_addr = s.accept()
    pass


if __name__ == '__main__':
    pass
