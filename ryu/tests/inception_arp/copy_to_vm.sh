#!/usr/bin/env python

import subprocess
import threading
import traceback

SCPS='scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

def exec_cmd(cmd):
    print(('-' * 15 + ' %s ') % cmd)
    proc = subprocess.Popen(['/bin/bash', '-c', cmd])
    proc.communicate()            

cmds = []
for line in open('vm_ip.txt'):
    ip = line.strip()
    for filename in ["run_test.sh", "calc_exp", "vm_ip.txt"]:
        cmd = SCPS + ' %s %s:%s' % (filename, ip, '~/')
        cmds.append(cmd)
        
try:
    # execute each command
    for cmd in cmds:
        thread = threading.Thread(target=exec_cmd, args=(cmd,))
        thread.start()
except Exception:
        print(traceback.format_exc())
