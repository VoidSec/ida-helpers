# ida-helpers
Collection of IDA helpers

## Heap Viewer

Heap viewer will parse an "IDA Segment Export" data `heap_base.txt` and will produce a table with the following details:
	+ segment n.
	+ segment start address
	+ segment end address
	+ segment size
	+ space between two segments

Usage:
```
heap_viewer.py -f heap_base.txt -o output.md --segment
	-f 			IDA Segment Export input file
	-o 			Output File
	--segment		Hide space between two segment information
```

This will be the output file format:
```
-----------------------------------------------------------------------------------------------
|	seg n.	|	start		|	end			|	size
-----------------------------------------------------------------------------------------------
|	0		|	0xea180000	|	0xea300000	|	0x180000
-----------------------------------------------------------------------------------------------[130547712]
|	1		|	0xe2480000	|	0xe2500000	|	0x80000
-----------------------------------------------------------------------------------------------[2621440]
|	2		|	0xe2180000	|	0xe2200000	|	0x80000
-----------------------------------------------------------------------------------------------[23592960]
|	3		|	0xe0a80000	|	0xe0b00000	|	0x80000
-----------------------------------------------------------------------------------------------[18874368]
```

## Segment Dumper
To use in conjunction with `Heap Viewer`, copy and paste the output address list and size from `Heap Viewer` inside `Segment Dumper` and load it into IDA, it will dump the relative segment from the memory saving it as a .bin file in the hardcoded folder.

## Base Address

Replace the path of the desired library, insert function names in `f_name` and respective offset in `f_addr`. The script will pull library base address from IDA and calculate the final addresses for every listed functions, setting a software breakpoint to the respective address.

```
eg.

library base address = C7180000
function address = C718FF90

offset(base addr - function addr)= FF90

func addr = (offset + base addr)
```
## P/P/R
Find pop pop ret gadgets

## Func Complexity
Print out an ordererd list of functions, from the least complex to the most one (based on the number of basic blocks)
