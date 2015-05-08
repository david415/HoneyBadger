#!/usr/bin/python

import re
import sys
import os
import argparse

def count_distribution(filename, or_addr):
    port_map = {}

    count = 0
    for line in open(filename):
        count += 1
        m = re.search(' ([0-9.]+):([0-9]+)-(.+):([0-9]+)', line)
        if m is None:
            print "parse fail"
            sys.exit(-1)

        addr1 = m.group(1)
        addr2 = m.group(3)
        if addr1 == or_addr:
            dest_port = m.group(4)
        else:
            dest_port = m.group(2)
        if port_map.has_key(int(dest_port)):
            port_map[int(dest_port)] += 1
        else:
            port_map[int(dest_port)] = 1

    return port_map

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("or_addr", help="origin ipv4 address")
    parser.add_argument("total", help="total flows")
    parser.add_argument("attack", help="attack flows")
    args = parser.parse_args()
    total_map = count_distribution(args.total, args.or_addr)
    attack_map = count_distribution(args.attack, args.or_addr)

    #print attack_map
    #print total_map

    total_total = 0
    for port in sorted(total_map.keys()):
        total_total += int(total_map[int(port)])

    for port in sorted(attack_map.keys(), reverse=True):
        #if attack_map.has_key(port) and total_map.has_key(port):
        frequency = float(attack_map[int(port)]) / float(total_map[int(port)])
        total_freq = float(total_map[int(port)]) / float(total_total)
        print "port %s frequency %s attacks %s total %s (expected %s)\n" % (port, frequency, attack_map[int(port)], total_map[int(port)], total_freq)

    for port in sorted(total_map.keys()):
        if total_map[port] > 0:
            print "port %s total %d" % (port, total_map[port])

if __name__ == '__main__':
    main()
