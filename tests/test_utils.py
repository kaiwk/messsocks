# content of test_sample.py
from messsocks.utils import int2ip, ip2int


def test_int2ip():
    assert int2ip(168427787) == "10.10.1.11"
    assert int2ip(2886732556) == "172.16.11.12"
    assert int2ip(3232235876) == "192.168.1.100"
    assert int2ip(3232235879) == "192.168.1.103"


def test_ip2int():
    assert ip2int("10.10.1.11") == 168427787
    assert ip2int("172.16.11.12") == 2886732556
    assert ip2int("192.168.1.100") == 3232235876
    assert ip2int("192.168.1.103") == 3232235879
