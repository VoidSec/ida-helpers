import idaapi
import idautils
import idc

functions_list = []
for f_ep in idautils.Functions():  # get list of functions' entrypoint
    function = idaapi.get_func(f_ep)  # get pointer to a function
    flowchart = idaapi.FlowChart(function)  # retrieve flowchart of a function
    # append function to the list
    functions_list.append([flowchart.size, str(idc.get_func_name(function.start_ea))])

functions_list.sort()  # sort the list
for function in functions_list:
    print("{} -\t{}".format(function[0], function[1]))
    # print("Function %s starting at 0x%x consists of %d basic blocks\n" % (GetFunctionName(function.startEA), function.startEA, flowchart.size))
