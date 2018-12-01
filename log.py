import logging.config

def get_logger(name):
    """

    :param name: name
    :returns: logger
    :rtype: logger

    """
    logging.config.fileConfig('logging.conf')
    return logging.getLogger(name)
