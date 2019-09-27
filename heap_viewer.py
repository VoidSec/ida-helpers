# Author: Paolo Stagno - VoidSec (https://voidsec.com)

import sys
import os
import argparse

parser = argparse.ArgumentParser(prog="heap_viewer.py", description="IDA Segments Heap Viewer")
parser.add_argument("-f", dest="heap_base", required=True, help="IDA Segment Export")
parser.add_argument("-o", dest="output_file", required=True, help="Output File")
parser.add_argument('--segment', dest="sp2seg", action='store_false', default=True, help="Hide space between two segment information")
args = parser.parse_args()
heap_base=args.heap_base
output=args.output_file
sp2seg=args.sp2seg
# grab segments start addresses
start = "cat "+heap_base+" | cut -f 2 > /tmp/start.txt"
os.system(start)
# grab segments end addresses
end = "cat "+heap_base+" | cut -f 3 > /tmp/end.txt"
os.system(end)
start = open("/tmp/start.txt", "r")
end = open("/tmp/end.txt", "r")
start_addr=[]
end_addr=[]
for line_s in start:
    start_addr.append(int(line_s.rstrip("\n"), 16))
for line_e in end:
    end_addr.append(int(line_e.rstrip("\n"), 16))
#Debug
#print(start_addr)
#print(end_addr)
s_size=[]
i=0
for s_addr in start_addr:
    # segment size (segment end address - start address)
    s_size.append(end_addr[i]-s_addr)
    i=i+1
#print(s_size)
space2segment=[]
start=0
while start<len(start_addr)-1: 
    end=start+1
    #print(start_addr[start])
    #print(end_addr[end])
    # calculate the space between 2 segments (current segment start address - next segment end address)
    space2segment.append(start_addr[start]-end_addr[end])
    start+=1
#print(space2segment)
f = open(output, "a")
i=0
f.write("|\tseg n.\t|\tstart\t|\tend\t|\tsize\t|\n")
f.write("|\t:----:\t|\t:----:\t|\t:----:\t|\t:----:\t|\n")
print("-----------------------------------------------------------------------------------------------")
print("|\tseg n.\t|\tstart\t\t|\tend\t\t|\tsize")
print("-----------------------------------------------------------------------------------------------")
while i<len(start_addr):
    f.write("|\t"+str(i)+"\t|\t"+str(hex(start_addr[i])).rstrip("L")+"\t|\t"+str(hex(end_addr[i])).rstrip("L")+"\t|\t"+str(s_size[i])+"\t|\n")
    print("|\t"+str(i)+"\t|\t"+str(hex(start_addr[i])).rstrip("L")+"\t|\t"+str(hex(end_addr[i])).rstrip("L")+"\t|\t"+str(s_size[i]))
    if sp2seg is True:
        if (i<len(space2segment)):
            f.write("|\t"+str(space2segment[i])+"\t|\n")
            print("-----------------------------------------------------------------------------------------------["+str(space2segment[i])+"]")
        else:
            print("-----------------------------------------------------------------------------------------------")
    i+=1
f.close()
print("\n[>] Output file: "+output)