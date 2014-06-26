#!/usr/bin/env python

from common import process_in_parallel

import traceback

SCPS='scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    for filename in ["run_test.sh", "calc_exp", "vm_ip.txt"]:
        cmd = SCPS + ' %s %s:%s' % (filename, ip, '~/')
        cmds.append(cmd)
        
process_in_parallel(cmds)
