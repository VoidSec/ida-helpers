# Author: Paolo Stagno - VoidSec (https://voidsec.com)

addresses=[0xea180000, 0xe2480000, 0xe2180000]
size=[0x180000, 0x80000, 0x80000]
print("Dumping Segments:\n---------------------------------------")
i=0
while i < len(addresses):
    #filename = AskFile(1, "*.bin", "Output file name")
    with open("/Users/segment/s_"+str(i)+".bin", "wb") as out:
        data = GetManyBytes(addresses[i], size[i], use_dbg=False)
        out.write(data)
    print("seg n. {}: addr. {} - size. {}b").format(i,hex(int(str(addresses[i]),16)),int(str(size[i]),16))
    i+=1
print("[+] DONE")