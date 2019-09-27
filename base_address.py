# Author: Paolo Stagno - VoidSec (https://voidsec.com)

import sys
for a in Modules():
    # Modules(), returns a list of module objects with name,size,base,rebase_to attributes
    if a.name=="/path/libc":
        ba=a.base
        print("\n-----------\nlib base addr: "+hex(ba).rstrip("L")+"\n-----------")
f_name = ["func1", "func2", "crash"]
f_addr = [0x2B0001,0x2B0002,0x2B0003]
f_addr.reverse()
for a in f_name:
    offset=ba+f_addr.pop()
    print(a+":"+hex(offset).rstrip("L"))
    # add software breakpoint 
    add_bpt(offset, 0, BPT_SOFT)
    # enable breakpoint
    enable_bpt(offset, True)