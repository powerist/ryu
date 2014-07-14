#!/usr/bin/env python

from common import process_in_parallel

import sys
import traceback

SCPS='scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

if len(sys.argv) < 2:
    print "usage: collect_data <output_file> <num_skips=30>"
    sys.exit()
output_file = sys.argv[1]
num_skips = sys.argv[2] if len(sys.argv) >= 3 else 30

######################################################### retrieve data (in parallel: Map)
cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    cmd = SCPS + ' %s:%s %s' % (ip, '~/ping.log', '/tmp/ping.log.%s' % ip)
    cmds.append(cmd)

process_in_parallel(cmds)        

######################################################### transform data (single-thread: Map)
for line in open('vm_ip.txt'):
    ip = line.strip()    

    print 'tranform file=/tmp/ping.log.%s' % ip
    fin = open('/tmp/ping.log.%s' % ip)
    fout = open('/tmp/ping.out.%s' % ip, 'w')
    line_in = ''
    line_out = []
    num_line_out = 0
    while True:
        line_in = fin.readline().strip()
        line_in  = line_in.replace('\x00', '') # remove possible \x00 non-sense chars
        if not line_in:
            break

        (time_stamp, line_in)=line_in.split(':', 1) # get time stamp
        line_in = line_in.strip()

        if line_in.startswith('ARPING '):
            line_out.append(line_in.replace('ARPING ', ''))
        elif line_in.startswith('Unicast '):
            line_out.append(line_in)
        elif line_in.startswith('Sent '):
            pass
        elif line_in.startswith('Received 0 response'):
            line_out.append('X X X X X Timeout')
            line_out.append(time_stamp)
            num_line_out += 1
            if num_line_out >= num_skips:
                fout.write(','.join(line_out) + '\n')
            line_out = []
        elif line_in.startswith('Received 1 response'):
            line_out.append(time_stamp)
            num_line_out += 1
            if num_line_out >= num_skips:
                fout.write(','.join(line_out) + '\n')
            line_out = []
        else:
            raise RuntimeError('Unknown format of line=%s', line_in)
    fin.close()
    fout.close()

######################################################### combine data (single-thread: Reduce)
def check_ip(ip1, ip2):
    parts1 = ip1.split('.')
    parts2 = ip2.split('.')
    if int(parts1[2]) / 10 != int(parts2[2]) / 10:
        return 'inter_dc'
    elif parts1[2] != parts2[2]:
        return 'inter_host'
    else:
        return 'same_host'

fout = open(output_file, 'w')
for ip in open('vm_ip.txt'):
    ip = ip.strip()
    for line in open('/tmp/ping.out.%s' % ip):
        line = line.strip()
        items = line.split(' ')
        local_ip = items[2]
        peer_ip = items[0]
        fout.write(line + ',' + check_ip(local_ip, peer_ip) + '\n')

fout.close()
