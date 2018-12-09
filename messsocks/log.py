from pathlib import Path
import logging.config

def get_logger(name):
    """

    :param name: name
    :returns: logger
    :rtype: logger

    """
    conf_path = Path(__file__).parent.parent / 'conf' / 'logging.conf'
    logging.config.fileConfig(conf_path)
    return logging.getLogger(name)
