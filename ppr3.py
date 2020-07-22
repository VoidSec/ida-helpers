#!/user/bin/env python3 

"""
POP-POP-RET finder ported in py3 and IDA Pro 7.5 
Author: Matteo 'uf0' Malvica 
"""

import idc
import ida_bytes

def disp(a,b,c,d): 			#Function to display pop/pop/rets...
	mnem1 = print_operand(a,0)  	#Getting first operand from start addr (pop *)
	mnem2 = print_operand(int(a+1),0) 	#Getting first operand from start addr +1 (pop xxx, pop *)
	print("{0:08X}".format(a))
	y = Assemble(a, str(b+" "+mnem1))[1]  	#Assembling instruction at a
	a = a+1  	#incrementing a
	z = Assemble(a, str(c+" "+mnem2))[1]  	#Assembling instruction at a + 1
	print("{0:08X} {0:08X}".format((ord(y[0])),(ord(z[0]))))  	#Printing assembly - non-mnemonic (e.g. \x5b\x5d\xc3)

def main():
	print("Running POP/POP/RETN Script\n\n")
	
	addr = get_segm_by_sel(selector_by_name(".text")) 	# Getting start addr of code segment through the selector for .text
	end = get_segm_end(addr)  		# Getting end addr of code segment
	
	while addr < end and addr != BADADDR:  	#While stepping through addr's and not bad addr's
		addr = next_addr(addr)  	#addr = next address starting from var addr
		op1 = print_insn_mnem(addr)  	#Getting mnemonic instruction where addr is pointing
		if str(op1) == "pop":  	#If the instruction is a pop...
			x = addr + 1  		#...then incrementing x to the next address after the pop
			op2 = print_insn_mnem(x) 	#Get the mnemonic instruction of x
			if str(op2) == "pop":  	#If the instruction is a pop...
				y = x + 1  		#...then increment x to the next address again.
				ret = print_insn_mnem(y) 	# Get the instruction at x
				if str(ret) == "retn":  	#If it's a return....
					z = get_operand_value(y,0)	#Check to see if the RETN instruction has an operand value. e.g. retn 12. If 
					if z == -1:	#If it doesn't have an operand value, continue.
						disp(addr,op1,op2,ret)  #Call the disp() function to display
				
	print("\n\nScript Finished!")

if __name__ == '__main__':
    main()



	
