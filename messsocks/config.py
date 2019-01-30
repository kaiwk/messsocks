import configparser
from pathlib import Path


def get_config():
    parser = configparser.ConfigParser()
    conf_path = Path(__file__).parent.parent / "conf" / "example.conf"
    parser.read(conf_path)
    return parser
