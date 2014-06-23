#!/usr/bin/env python

import subprocess
import sys
import threading
import traceback

SCPS='scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

if len(sys.argv) < 2:
    print "usage: collect_data <output_file> <tail_line=600> <head_line=300>"
    sys.exit()
output_file = sys.argv[1]
tail_line = sys.argv[2] if len(sys.argv) >= 3 else 600
head_line = sys.argv[3] if len(sys.argv) >= 4 else 300

def exec_cmd(cmd):
    print(('-' * 15 + ' %s ') % cmd)
    proc = subprocess.Popen(['/bin/bash', '-c', cmd])
    proc.communicate()            

def process_in_parallel(cmds):
    try:
        threads = []
        # execute each command
        for cmd in cmds:
            thread = threading.Thread(target=exec_cmd, args=(cmd,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    except Exception:
        print(traceback.format_exc())

######################################################### retrieve data (in parallel: Map)
cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    cmd = SCPS + ' %s:%s %s' % (ip, '~/ping.log', '/tmp/ping.log.%s' % ip)
    cmds.append(cmd)

process_in_parallel(cmds)        

######################################################### transform data (in parallel: Map)
cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    cmd = """cat /tmp/ping.log.%s | grep -v skip |grep -A 1 ARPING  |grep -v ^-- |sed -e 's/ARPING //' |sed -e 's/^.*time=\(.*\)/\1/' |paste - - -d,|grep -v 10.2.99.0 | perl -ne 's/([0-9]+\.[0-9]+) (usec)/($2?$1\/1000:$1)." msec"/e; s/msec//; print "".$_' | tail -n +%s |head -%s > /tmp/ping.out.%s""" % (ip, tail_line, head_line, ip)
    cmds.append(cmd)
        
process_in_parallel(cmds)        

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
