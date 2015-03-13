#!/usr/bin/python

#coding:utf8

def r_s2i(input_string):
    """
    reverse sequence string to int converter
    """
    res = []
    final = 0
    for letter in input_string:
        res.append(ord(letter))
    #print 'res: {0}'.format(res)
    for i in xrange(len(res)):
        final += res[i]*pow(2, i*8)
    return final

def rva2raw(can_rva, base_rva, base_raw):
    """
    convert rva to raw address (offset relative to file header)
    """
    return (can_rva - base_rva + base_raw)

def display(data):
    for i in data:
        print i

