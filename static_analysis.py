from idautils import *
from idaapi import *
from idc import *
from parse import *
import json


class StaticAnalysis:
    registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']

    def __init__(self):
        return

    @staticmethod
    def strip_comments(line):
        curidx = 0
        while True:
            foundidx = line.find("//", curidx)
            if foundidx == -1:
                return line
            # If number of quotes before the // is even, we are outside a string -> remove comment
            numquotes = line.count('"', 0, foundidx)
            if (numquotes & 1) == 0:
                return line[:foundidx].rstrip()
            curidx = foundidx + 2

    @staticmethod
    def load_commented_json(json_filename):
        lines = map(self.strip_comments, open(json_filename, "rt"))
        data = json.loads('\n'.join(lines))
        return data

    def get_args_of_functions(self, address_of_func, number_of_args):
        if number_of_args <= 0:
            return
    
        args_of_functions = {}
    
        xref = CodeRefsTo(address_of_func, 1)
        for address in xref:
            args_of_functions[address] = self.get_args_of_function(address, number_of_args)
    
        return args_of_functions
    
    @staticmethod
    def get_push_args(address, number_of_args):
        if number_of_args <= 0:
            return

        args_f = [None] * number_of_args
        arg_counter = 0

        for i in range(0,10):
            address = PrevHead(address, 0)
            if arg_counter == number_of_args:
                break
            if GetMnem(address) == 'push':
                if GetOpType(address, 0) == idaapi.o_imm:
                    args_f[arg_counter] = GetOperandValue(address, 0)
                else:
                    args_f[arg_counter] = GetOpnd(address, 0)
                arg_counter += 1  

        return args_f

    @staticmethod
    def get_reg_args(caller_address, number_of_args):
        args_reg = ['edi', 'esi', 'edx']
        args = []

        for reg_num in xrange(number_of_args):
            reg = args_reg[reg_num]

            address = caller_address
            ins_counter = 10
            while ins_counter != 0:
                address = PrevHead(address, 0)
                if GetMnem(address) == 'mov' and GetOpnd(address, 0) == reg:
                    if GetOpType(address, 1) != idaapi.o_imm:
                        return
                    args.append(GetOperandValue(address, 1))
                    break
                ins_counter -= 1

            if ins_counter == 0:
                return None

        return args

    @staticmethod
    def get_flow_chart(address):
        start_func = GetFunctionAttr(address, FUNCATTR_START)
        return idaapi.FlowChart(idaapi.get_func(start_func))
        
    @staticmethod
    def get_block_id(flow_chart, specific_address):
        for index in range(0, flow_chart.size):
            block = flow_chart._getitem(index)
            if specific_address >= block.startEA and specific_address < block.endEA:
                return index
    
    @staticmethod
    def get_block_start_address(flow_chart, specific_address):
        for index in range(0, flow_chart.size):
            block = flow_chart._getitem(index)
            if specific_address >= block.startEA and specific_address < block.endEA:
                return block.startEA
    
    @staticmethod            
    def is_add_in_func(func_start_add, address):
        if GetFunctionAttr(address, FUNCATTR_START) == func_start_add:
            return True
        else: return False
        
    @staticmethod            
    def find_ins_txt(address, ins_str):
        res_list = []
        while 1:
            address = FindText(address, SEARCH_DOWN, 0, 0, ins_str)
            if address == BADADDR: break
            res_list.append(address)
            address = NextHead(int(address))
            if address == BADADDR: break
        return res_list
