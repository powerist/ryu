"""
Inception utilities
"""


def tuple_to_zk_data(data_tuple, sep=','):
    """
    Convert tuple to string
    """
    zk_data = sep.join(data_tuple)
    return zk_data


def zk_data_to_tuple(zk_data, sep=','):
    """
    Convert string to tuple
    """
    data_tuple = tuple(zk_data.split(sep))
    return data_tuple
