#!/usr/bin/env python

from common import process_in_parallel

import subprocess
import threading
import traceback

SSHS='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    cmd = SSHS + ' ' + ip + " 'kill `cat /tmp/do_test.pid`; rm /tmp/do_test.pid'"
    print "stopping ping on %s" % ip
    cmds.append(cmd)
        
process_in_parallel(cmds)
