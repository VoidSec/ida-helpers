import idaapi
import idautils
import idc


def display(start):
    mnem1 = idc.print_operand(start, 0)
    mnem2 = idc.print_operand((start + 1), 0)
    mnem3 = idc.print_operand((start + 2), 0)
    byte1 = idautils.Assemble(start, "pop " + mnem1)
    byte2 = idautils.Assemble(start + 1, "pop " + mnem2)

    if mnem3 == "":
        byte3 = idautils.Assemble(start + 2, "ret")
    else:
        byte3 = idautils.Assemble(start + 2, "ret " + mnem3)

    print(
        f"- 0x{start:08X}: pop {mnem1}; pop {mnem2}; ret {mnem3}; \\x{ord(byte1[1]):02x}\\x{ord(byte2[1]):02x}{byte3[1]}")


def main():
    count = 0
    print("Executing POP/POP/RET finder...")
    for ea in idautils.Segments():
        name = idc.get_segm_name(ea)
        if name == ".text":
            start_addr = idc.get_segm_start(ea)
            end_addr = idc.get_segm_end(ea)
            print(
                f"{name} segment start at 0x{start_addr:08X} - end at 0x{end_addr:08X}; size: {end_addr - start_addr} bytes")
            while start_addr < end_addr and start_addr != idaapi.BADADDR:
                op1 = idc.print_insn_mnem(start_addr)
                if op1 == "pop":
                    x = start_addr + 1
                    op2 = idc.print_insn_mnem(x)
                    if op2 == "pop":
                        y = x + 1
                        ret = idc.print_insn_mnem(y)
                        if ret == "retn":
                            count += 1
                            display(start_addr)
                start_addr = idc.next_addr(start_addr)
    print(f"Finished! Total gadgets found: {count}")


if __name__ == '__main__':
    main()
