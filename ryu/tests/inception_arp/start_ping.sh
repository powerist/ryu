#!/usr/bin/env python

from common import process_in_parallel

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    cmd = SSHS + ' ' + ip + ' "/home/ubuntu/run_test.sh 0.2 > ping.log &"';
    print "starting ping on %s" % ip
    cmds.append(cmd)
        
process_in_parallel(cmds)
