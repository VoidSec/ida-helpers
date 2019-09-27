# ida-helpers
Collection of IDA helpers

+ Heap Viewer

Heap viewer will parse an "IDA Segment Export" data `heap_base.txt` and will produce a table with the following details:
	+ segment n.
	+ segment start address
	+ segment end address
	+ segment size
	+ space between two segments

Usage:
```
heap_viewer.py -f heap_base.txt -o output.md --segment
	-f 				IDA Segment Export input file
	-o 				Output File
	--segment		Hide space between two segment information
```

This will be the output file format:
```
-------------------------------------------------------
|	seg n.	|	start		|	end		|	size
-------------------------------------------------------
|	0	|	0xea180000	|	0xea300000	|	1572864
-------------------------------------------------------[130547712]
|	1	|	0xe2480000	|	0xe2500000	|	524288
-------------------------------------------------------[2621440]
|	2	|	0xe2180000	|	0xe2200000	|	524288
-------------------------------------------------------[23592960]
|	3	|	0xe0a80000	|	0xe0b00000	|	524288
-------------------------------------------------------
```

+ Base Address

Replace the path of the desired library, insert function names in `f_name` and respective offset in `f_addr`. The script will pull library base address from IDA and calculate the final addresses for every listed functions, setting a software breakpoint to the respective address.

```
eg.

library base address = C7180000
function address = C718FF90

offset(base addr - function addr)= FF90

func addr = (offset + base addr)
```