from multiprocessing import Process

import requests

from messsocks.messclient import start_client
from messsocks.messserver import start_server
from messsocks.config import get_config


def test_connect():

    proxies = {
        'http': 'socks5://127.0.0.1:1081',
        'https': 'socks5://127.0.0.1:1081'
    }

    config = get_config()
    server_host = config['server']['host']
    server_port = int(config['server']['port'])

    client_host = config['client']['host']
    client_port = int(config['client']['port'])

    server = Process(target=start_server,
                     args=(server_port,))
    client = Process(target=start_client,
                     args=((client_host, client_port), (server_host, server_port)))
    server.start()
    client.start()

    http_url = 'http://www.baidu.com'
    https_url = 'https://www.baidu.com'

    res = requests.get(http_url).text
    proxy_res = requests.get(http_url, proxies=proxies).text
    assert res == proxy_res

    res = requests.get(https_url).text
    proxy_res = requests.get(https_url, proxies=proxies).text
    assert res == proxy_res

    client.terminate()
    server.terminate()
