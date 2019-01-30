from messsocks.config import get_config


def test_config():
    config = get_config()
    server_host = config["server"]["host"]
    server_port = config["server"]["port"]

    assert server_host == "127.0.0.1"
    assert server_port == "45678"

    client_host = config["client"]["host"]
    client_port = config["client"]["port"]

    assert client_host == "127.0.0.1"
    assert client_port == "1081"
