# -*- coding: utf-8 -*- 
import binascii
import re


def print_data(data):
    hexstring = binascii.hexlify(data)
    n = 80
    split_string = "\n".join([hexstring[i:i+n] for i in range(0, len(hexstring), n)])
    print split_string


def round_up(x, k):
    return ((x + k - 1) & -k)


def print_structure(container, struct):
    actual_data = struct.build(container)
    return "{}".format(struct.parse(actual_data))
# remove control character in string
# This will affect the executable_name part in path
def remove_control_char(str):
    return re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]').sub('', str)