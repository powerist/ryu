#!/usr/bin/env python

import time
import sys 

import psutil


def main():
    fout = open('/tmp/cpu_memory.log', 'w')
    pid = int(sys.argv[1])
    process = psutil.Process(pid)
    while True:
        cpu = process.cpu_percent()
        memory = process.memory_percent()
        data = '%.2f,%.2f\n' % (cpu, memory) 
        fout.write(data)
        time.sleep(3)
    
if __name__ == "__main__":
    main()
