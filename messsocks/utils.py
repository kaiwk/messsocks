import struct
import socket


def ip2int(ip):
    """convert string ip to int
    https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python

    :param ip: ip
    :type ip: str
    :returns: ip
    :rtype: int

    """
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int2ip(ip):
    """ convert int ip to string
    https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python

    :param ip: ip
    :type ip: int
    :returns: ip
    :rtype: str

    """
    return socket.inet_ntoa(struct.pack("!I", ip))
