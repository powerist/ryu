#!/usr/bin/env python

import subprocess
import threading
import traceback

def exec_cmd(cmd):
    print(('-' * 15 + ' %s ') % cmd)
    proc = subprocess.Popen(['/bin/bash', '-c', cmd])
    proc.communicate()            

def process_in_parallel(cmds, sliding_window=100):
    try:
        # execute each command
        start = 0
        end = sliding_window
        while True:
            if start == len(cmds):
                break
            end = len(cmds) if end > len(cmds) else end
            threads = []
            for cmd in cmds[start:end]:
                thread = threading.Thread(target=exec_cmd, args=(cmd,))
                thread.start()
                threads.append(thread)
            print 'batch processing %s to %s' % (start, end)
            for thread in threads:
                thread.join()
            start = end
            end += sliding_window
    except Exception:
        print(traceback.format_exc())
