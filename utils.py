import struct
import socket

def ip2int(ip):
    """ convert string ip to int

    :param ip: ip
    :type ip: str
    :returns: ip
    :rtype: int

    """
    return struct.unpack('!I', socket.inet_aton(ip))[0]

def int2ip(ip):
    """ convert int ip to string

    :param ip: ip
    :type ip: int
    :returns: ip
    :rtype: str

    """
    return socket.inet_ntoa(struct.pack('!I', ip))
