"""A simple protocol to communicate with remote proxy based on raw socket

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

import struct
import socket

import messsocks.exception as ex
from messsocks.log import get_logger


logger = get_logger('messsocks')

REQ_PKT_HSIZE = 8

VERSION = 1

NORMAL_CONN = 0x00
NEW_CONN = 0x01


def serve(proxy_skt):
    """

    :param proxy_skt: proxy socket
    :type proxy_skt: socket
    :returns: target socket
    :rtype: socket

    """
    logger.info('read head!')
    head = proxy_skt.recv(2)
    logger.info('head: %s', head)
    ver, conn_type = struct.unpack('!BB', head)
    check_version(ver)
    logger.info('ver: %s, type: %s', ver, conn_type)
    if conn_type == NEW_CONN:   # new connection
        target_ip = socket.inet_ntoa(proxy_skt.recv(4))
        target_port = struct.unpack('!H', proxy_skt.recv(2))[0]
        proxy_skt.sendall(struct.pack('!BB', 1, 1))
        target_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_skt.connect((target_ip, target_port))
        return target_skt
    return None


def check_version(version):
    """ check protocol version

    :param version: protocol version

    """
    if version != VERSION:
        raise ex.ProtocolException('mismatched protocol version')
