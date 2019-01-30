from multiprocessing import Process

import requests

from messsocks.messclient import start_client, main as client_main
from messsocks.messserver import start_server, main as server_main
from messsocks.config import get_config


class TestClientServer:
    def setup_method(self, method):

        self.proxies = {
            "http": "socks5://127.0.0.1:1081",
            "https": "socks5://127.0.0.1:1081",
        }
        self.http_url = "http://www.baidu.com"
        self.https_url = "https://www.baidu.com"

        config = get_config()
        server_host = config["server"]["host"]
        server_port = int(config["server"]["port"])
        client_host = config["client"]["host"]
        client_port = int(config["client"]["port"])

        self.server = Process(target=start_server, args=(server_host, server_port))
        self.client = Process(
            target=start_client,
            args=((client_host, client_port), (server_host, server_port)),
        )
        self.server.start()
        self.client.start()

    def teardown_method(self, method):
        self.client.terminate()
        self.server.terminate()

    def test_client_server(self):

        res = requests.get(self.http_url).text
        proxy_res = requests.get(self.http_url, proxies=self.proxies).text
        assert res == proxy_res

        res = requests.get(self.https_url).text
        proxy_res = requests.get(self.https_url, proxies=self.proxies).text
        assert res == proxy_res
